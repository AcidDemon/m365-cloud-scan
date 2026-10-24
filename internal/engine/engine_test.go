package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/graphref"
	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// --- a Graph stand-in -------------------------------------------------------

type fakeSession struct {
	drive, path string
	buf         []byte
	recv        int64
	firstSeen   bool
}

type fakeGraph struct {
	mu        sync.Mutex
	srv       *httptest.Server
	sessions  map[string]*fakeSession
	files     map[string][]byte // "drive/itemPath" -> content
	folders   map[string]bool   // "drive/path"
	conflicts map[string]string // itemPath -> conflictBehavior
	firstAt   map[string]int64  // itemPath -> offset of the first chunk PUT
	deleted   []string
	// badDrive confirms every upload one byte short, a failure that uses the
	// route's retry budget.
	badDrive     string
	failFolders  []int // statuses for the next folder creations
	failSessions []int // statuses for the next createUploadSession calls
	failChunks   []int // statuses for the next chunk PUTs
	n            int
}

func newFakeGraph(t *testing.T) *fakeGraph {
	f := &fakeGraph{
		sessions:  map[string]*fakeSession{},
		files:     map[string][]byte{},
		folders:   map[string]bool{},
		conflicts: map[string]string{},
		firstAt:   map[string]int64{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGraph) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path

	if r.Method == http.MethodPut && strings.HasPrefix(p, "/upload/") {
		f.upload(w, r, strings.TrimPrefix(p, "/upload/"))
		return
	}
	drive, rest, _ := strings.Cut(strings.TrimPrefix(p, "/drives/"), "/")
	switch {
	case r.Method == http.MethodDelete && strings.HasPrefix(rest, "items/"):
		f.deleted = append(f.deleted, strings.TrimPrefix(rest, "items/"))
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/children"):
		var body struct{ Name string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		parent := strings.TrimSuffix(strings.TrimPrefix(rest, "root:/"), ":/children")
		if parent == "root/children" {
			parent = ""
		}
		key := path2(drive, parent, body.Name)
		if len(f.failFolders) > 0 {
			w.WriteHeader(f.failFolders[0])
			f.failFolders = f.failFolders[1:]
			return
		}
		if f.folders[key] {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":{"code":"nameAlreadyExists"}}`)
			return
		}
		f.folders[key] = true
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"id":"folder"}`)

	case r.Method == http.MethodPost && strings.HasSuffix(rest, "/createUploadSession"):
		itemPath := strings.TrimSuffix(strings.TrimPrefix(rest, "root:/"), ":/createUploadSession")
		var body struct {
			Item map[string]string `json:"item"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.conflicts[itemPath] = body.Item["@microsoft.graph.conflictBehavior"]
		if len(f.failSessions) > 0 {
			status := f.failSessions[0]
			f.failSessions = f.failSessions[1:]
			if status == http.StatusTooManyRequests {
				w.Header().Set("Retry-After", "120")
			}
			w.WriteHeader(status)
			return
		}
		f.n++
		id := strconv.Itoa(f.n)
		f.sessions[id] = &fakeSession{drive: drive, path: itemPath}
		fmt.Fprintf(w, `{"uploadUrl":%q}`, f.srv.URL+"/upload/"+id)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeGraph) upload(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := f.sessions[id]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if len(f.failChunks) > 0 {
		w.WriteHeader(f.failChunks[0])
		f.failChunks = f.failChunks[1:]
		return
	}
	var start, end, total int64
	if _, err := fmt.Sscanf(r.Header.Get("Content-Range"), "bytes %d-%d/%d", &start, &end, &total); err != nil {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	if !s.firstSeen {
		s.firstSeen = true
		f.firstAt[s.path] = start
	}
	if int64(len(s.buf)) < total {
		s.buf = append(s.buf, make([]byte, total-int64(len(s.buf)))...)
	}
	b, _ := io.ReadAll(r.Body)
	copy(s.buf[start:], b)
	if end+1 > s.recv {
		s.recv = end + 1
	}
	if s.recv < total {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"nextExpectedRanges":["%d-"]}`, s.recv)
		return
	}
	f.files[s.drive+"/"+s.path] = s.buf
	if s.drive == f.badDrive {
		total--
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"id":"di-%s","name":%q,"size":%d,"webUrl":"https://sp/%s"}`,
		id, filepath.Base(s.path), total, s.path)
}

func (f *fakeGraph) file(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[key]
	return b, ok
}

func path2(drive, parent, name string) string {
	if parent == "" {
		return drive + "/" + name
	}
	return drive + "/" + parent + "/" + name
}

// --- rig --------------------------------------------------------------------

type rig struct {
	t        *testing.T
	dir      string
	shareDir string
	st       *store.Store
	g        *fakeGraph
	e        *Engine
	share    model.Share
}

func newRig(t *testing.T, deleteAfterUpload bool) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := st.AddShare(model.Share{Name: "scans", Enabled: true,
		Rules: model.ShareRules{DeleteAfterUpload: deleteAfterUpload}})
	if err != nil {
		t.Fatal(err)
	}
	shareDir := filepath.Join(dir, "srv", sh.Name)
	if err := os.MkdirAll(shareDir, 0o750); err != nil {
		t.Fatal(err)
	}
	g := newFakeGraph(t)
	gc := graph.NewClient(g.srv.Client(), g.srv.URL, staticToken("t"))
	e := New(st, graphref.New(gc), Options{
		ProgressDir:   filepath.Join(dir, "progress"),
		QuarantineDir: filepath.Join(dir, "quarantine"),
		Retry: config.RetryPolicy{MaxAttempts: 1, BaseDelay: time.Millisecond,
			MaxDelay: 2 * time.Millisecond, ChunkSize: config.GraphUploadChunkMultiple},
	}, nil)
	return &rig{t: t, dir: dir, shareDir: shareDir, st: st, g: g, e: e, share: sh}
}

func (r *rig) route(driveID, folder, sub string, conflict model.ConflictPolicy, maxAttempts int) model.Route {
	r.t.Helper()
	d, err := r.st.PutDestination(model.Destination{Name: driveID, DriveID: driveID, FolderPath: folder})
	if err != nil {
		r.t.Fatal(err)
	}
	rt, err := r.st.PutRoute(model.Route{ShareID: r.share.ID, DestinationID: d.ID, Enabled: true,
		SubfolderTemplate: sub, Conflict: conflict, MaxAttempts: maxAttempts})
	if err != nil {
		r.t.Fatal(err)
	}
	return rt
}

func (r *rig) queue(name string, size int, routes ...model.Route) (model.Item, []byte) {
	r.t.Helper()
	data := make([]byte, size)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	p := filepath.Join(r.shareDir, name)
	if err := os.WriteFile(p, data, 0o640); err != nil {
		r.t.Fatal(err)
	}
	it := model.Item{ShareID: r.share.ID, Path: p, Name: name, Size: int64(size),
		Discovered: time.Date(2026, 8, 21, 9, 0, 0, 0, time.UTC)}
	for _, rt := range routes {
		it.Legs = append(it.Legs, model.Leg{RouteID: rt.ID, State: model.LegPending})
	}
	it, err := r.st.PutItem(it)
	if err != nil {
		r.t.Fatal(err)
	}
	return it, data
}

func (r *rig) once() {
	r.t.Helper()
	if err := r.e.Once(context.Background()); err != nil {
		r.t.Fatalf("Once: %v", err)
	}
}

func (r *rig) item(id string) model.Item {
	r.t.Helper()
	it, ok := r.st.Item(id)
	if !ok {
		r.t.Fatalf("item %s gone from the store", id)
	}
	return it
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Stat(p)
	return err == nil
}

// --- tests ------------------------------------------------------------------

func TestTwoRoutesConfirmThenTheFileGoes(t *testing.T) {
	r := newRig(t, true)
	a := r.route("d1", "", "{yyyy}/{MM}", model.ConflictOverwrite, 0)
	b := r.route("d2", "Scans", "", "", 0)
	it, data := r.queue("scan001.pdf", 4096, a, b)

	r.once()

	if _, ok := r.st.Item(it.ID); ok {
		t.Error("item should be dropped once every leg confirmed")
	}
	if exists(t, it.Path) {
		t.Error("local file should be deleted")
	}
	for _, key := range []string{"d1/2026/08/scan001.pdf", "d2/Scans/scan001.pdf"} {
		got, ok := r.g.file(key)
		if !ok {
			t.Fatalf("%s never arrived", key)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s: %d bytes, want %d", key, len(got), len(data))
		}
	}
	if r.g.conflicts["2026/08/scan001.pdf"] != "replace" || r.g.conflicts["Scans/scan001.pdf"] != "rename" {
		t.Errorf("conflict behaviours = %v", r.g.conflicts)
	}
}

func TestOneLegFailsKeepsTheFileThenQuarantines(t *testing.T) {
	r := newRig(t, true)
	r.g.badDrive = "bad"
	good := r.route("d1", "", "", "", 0)
	bad := r.route("bad", "", "", "", 2)
	it, _ := r.queue("scan002.pdf", 2048, good, bad)

	r.once()
	got := r.item(it.ID)
	if got.Legs[0].State != model.LegConfirmed {
		t.Fatalf("good leg = %+v", got.Legs[0])
	}
	if got.Legs[1].State != model.LegRetrying || got.Legs[1].Attempts != 1 {
		t.Fatalf("bad leg = %+v", got.Legs[1])
	}
	if got.Done() {
		t.Error("Done() must be false with one leg outstanding")
	}
	if !exists(t, it.Path) {
		t.Fatal("the file must stay on disk while a leg is outstanding")
	}

	time.Sleep(5 * time.Millisecond) // clear NextAttempt
	r.once()

	got = r.item(it.ID)
	if got.Legs[1].State != model.LegQuarantined {
		t.Fatalf("bad leg after the budget = %+v", got.Legs[1])
	}
	if got.Legs[0].State != model.LegConfirmed || got.Legs[0].DriveItemID == "" {
		t.Errorf("the confirmed leg must stay confirmed: %+v", got.Legs[0])
	}
	if !got.Quarantined || !got.Stuck() {
		t.Error("the item should be flagged quarantined")
	}
	if exists(t, it.Path) {
		t.Error("the file should have left the share")
	}
	q := filepath.Join(r.dir, "quarantine", r.share.Name, it.ID+"-scan002.pdf")
	if !exists(t, q) {
		t.Fatalf("nothing in quarantine at %s", q)
	}
}

func TestRetryRestoresFromQuarantine(t *testing.T) {
	r := newRig(t, true)
	r.g.badDrive = "bad"
	good := r.route("d1", "", "", "", 0)
	bad := r.route("bad", "", "", "", 1)
	it, data := r.queue("scan003.pdf", 512, good, bad)

	r.once()
	if !r.item(it.ID).Quarantined {
		t.Fatal("expected quarantine after a single-attempt budget")
	}
	r.g.badDrive = "" // whatever SharePoint got wrong is fixed

	if err := r.e.Retry(it.ID); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	back := r.item(it.ID)
	if back.Quarantined {
		t.Error("Quarantined should be cleared")
	}
	if back.Legs[0].State != model.LegConfirmed {
		t.Error("a confirmed leg must not be re-queued")
	}
	if back.Legs[1].State != model.LegPending || back.Legs[1].Attempts != 0 {
		t.Errorf("failed leg = %+v", back.Legs[1])
	}
	if got, err := os.ReadFile(it.Path); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("file not back in the share: %v", err)
	}

	r.once()
	if _, ok := r.st.Item(it.ID); ok {
		t.Error("the retried item should have completed and been dropped")
	}
}

func TestTransientFailureKeepsTheFileAndRetries(t *testing.T) {
	r := newRig(t, true)
	r.g.failSessions = []int{http.StatusInternalServerError}
	rt := r.route("d1", "", "", "", 0)
	it, _ := r.queue("scan004.pdf", 1024, rt)

	r.once()
	got := r.item(it.ID)
	if l := got.Legs[0]; l.State != model.LegRetrying || l.Attempts != 0 || l.Transient != 1 {
		t.Fatalf("leg = %+v", got.Legs[0])
	}
	if !exists(t, it.Path) {
		t.Fatal("a 500 must never cost the file")
	}

	time.Sleep(5 * time.Millisecond)
	r.once()
	if _, ok := r.st.Item(it.ID); ok {
		t.Error("the second pass should have confirmed and dropped the item")
	}
	if exists(t, it.Path) {
		t.Error("file should be gone after confirmation")
	}
}

// dnsDown is the customer's outage: the resolver cannot find Graph at all.
type dnsDown struct{}

func (dnsDown) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, &net.DNSError{Err: "no such host", Name: r.URL.Hostname(), IsNotFound: true}
}

// The incident behind this test: DNS stopped resolving and every scan was
// quarantined within half a minute. An outage says nothing about the scan, so
// the leg waits it out past the route's budget and the file stays in the share.
func TestOutageRetriesPastTheBudget(t *testing.T) {
	r := newRig(t, true)
	r.e.gc.Set(graph.NewClient(&http.Client{Transport: dnsDown{}}, "", staticToken("t")))
	rt := r.route("d1", "", "", "", 1)
	it, _ := r.queue("scan-dns.pdf", 1024, rt)

	for range 3 {
		r.once()
		time.Sleep(5 * time.Millisecond) // clear NextAttempt
	}

	got := r.item(it.ID)
	if l := got.Legs[0]; l.State != model.LegRetrying || l.Attempts != 0 || l.Transient != 3 {
		t.Fatalf("leg = %+v", l)
	}
	if !strings.Contains(got.Legs[0].LastError, "no such host") {
		t.Errorf("lastError = %q", got.Legs[0].LastError)
	}
	if got.Quarantined || !exists(t, it.Path) {
		t.Fatal("an outage must leave the scan in the share")
	}
	if err := r.e.Retry(it.ID); err != nil {
		t.Fatal(err)
	}
	if l := r.item(it.ID).Legs[0]; l.Transient != 0 || l.State != model.LegPending {
		t.Errorf("an admin retry should start the leg over: %+v", l)
	}
}

// The tenant can drop out between Once looking and the leg running.
func TestDisconnectMidPassWaits(t *testing.T) {
	r := newRig(t, true)
	rt := r.route("d1", "", "", "", 1)
	it, _ := r.queue("scan-nc.pdf", 64, rt)
	r.e.gc.Set(nil)

	r.e.runLeg(context.Background(), r.item(it.ID), 0, nopProgress{})

	if l := r.item(it.ID).Legs[0]; l.State != model.LegRetrying || l.Attempts != 0 || l.Transient != 1 {
		t.Fatalf("leg = %+v", l)
	}
}

// Graph refusing the destination does not improve with time, so the admin
// should hear about it now rather than after the budget runs out.
func TestRefusedDestinationQuarantinesAtOnce(t *testing.T) {
	for _, call := range []string{"folder", "session"} {
		t.Run(call, func(t *testing.T) {
			r := newRig(t, true)
			if call == "folder" {
				r.g.failFolders = []int{http.StatusForbidden}
			} else {
				r.g.failSessions = []int{http.StatusForbidden}
			}
			rt := r.route("d1", "Scans", "", "", 0)
			it, _ := r.queue("scan-403.pdf", 512, rt)

			r.once()

			got := r.item(it.ID)
			if l := got.Legs[0]; l.State != model.LegQuarantined || l.Attempts != 1 {
				t.Fatalf("leg = %+v", l)
			}
			if !got.Quarantined {
				t.Error("the item should be flagged quarantined")
			}
		})
	}
}

func TestThrottleWaitsAsLongAsGraphAsks(t *testing.T) {
	r := newRig(t, true)
	r.g.failSessions = []int{http.StatusTooManyRequests} // Retry-After: 120
	rt := r.route("d1", "", "", "", 1)
	it, _ := r.queue("scan-429.pdf", 512, rt)

	r.once()

	l := r.item(it.ID).Legs[0]
	if l.State != model.LegRetrying || l.Attempts != 0 {
		t.Fatalf("leg = %+v", l)
	}
	if wait := time.Until(l.NextAttempt); wait < 110*time.Second {
		t.Errorf("next attempt in %v, Graph asked for 120s", wait)
	}
}

func TestOutageBackoffGrowsThenLevelsOff(t *testing.T) {
	r := newRig(t, true)
	r.e.opt.Retry = config.RetryPolicy{MaxAttempts: 1, BaseDelay: time.Minute, MaxDelay: 4 * time.Minute}
	rt := r.route("d1", "", "", "", 1)
	it, _ := r.queue("scan-backoff.pdf", 64, rt)
	outage := &transfer.Transient{Err: &net.DNSError{Err: "no such host", Name: "graph.microsoft.com", IsNotFound: true}}

	for _, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 4 * time.Minute} {
		before := time.Now()
		r.e.fail(r.item(it.ID), 0, rt, outage, false)
		if gap := r.item(it.ID).Legs[0].NextAttempt.Sub(before); gap < want || gap > want+time.Second {
			t.Errorf("waited %v, want %v", gap, want)
		}
	}
}

// An upload session that expired mid-file is a 404 on the chunk, not a refused
// destination: a fresh session usually fixes it.
func TestExpiredUploadSessionUsesTheBudget(t *testing.T) {
	r := newRig(t, true)
	r.g.failChunks = []int{http.StatusNotFound}
	rt := r.route("d1", "", "", "", 2)
	it, _ := r.queue("scan-expired.pdf", 512, rt)

	r.once()

	if l := r.item(it.ID).Legs[0]; l.State != model.LegRetrying || l.Attempts != 1 || l.Transient != 0 {
		t.Fatalf("leg = %+v", l)
	}
}

// Retries inside one upload must not inherit the minutes-long leg schedule, or
// a worker and the route Test button sit on one chunk for that long.
func TestChunkRetriesStayShort(t *testing.T) {
	r := newRig(t, true)
	r.e.opt.Retry.MaxAttempts = 2
	r.e.opt.Retry.BaseDelay, r.e.opt.Retry.MaxDelay = time.Minute, time.Minute
	r.g.failChunks = []int{http.StatusInternalServerError}
	rt := r.route("d1", "", "", "", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := r.e.TestRoute(ctx, rt.ID); err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
}

func TestOutagesAndRefusalsAreToldApart(t *testing.T) {
	dns := &url.Error{Op: "Post", URL: "https://graph.microsoft.com/v1.0/drives", Err: &net.OpError{
		Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "graph.microsoft.com", IsNotFound: true}}}
	api := func(status int) error { return &graph.APIError{Status: status} }
	// A real open error, because the syscall.Errno inside it is what once
	// passed for a network error.
	_, missing := os.Open(filepath.Join(t.TempDir(), "missing.pdf"))
	// http.NewRequest reports a path it cannot parse as a *url.Error too.
	_, unparsable := http.NewRequest(http.MethodPost, "https://graph.microsoft.com/v1.0/drives/d/root:/Rechnung 100%.pdf:/createUploadSession", nil)
	for _, tc := range []struct {
		name                string
		err                 error
		transient, rejected bool
	}{
		{"DNS failure from Graph", &transfer.Transient{Err: dns}, true, false},
		{"DNS failure fetching a token", fmt.Errorf("graph: acquire token: auth: reach Entra ID: %w", dns), true, false},
		{"box not connected", errNotConnected, true, false},
		{"shutdown", fmt.Errorf("upload: %w", context.Canceled), true, false},
		{"throttled", &transfer.Transient{Err: api(http.StatusTooManyRequests), RetryAfter: time.Minute}, true, false},
		{"Entra unavailable", fmt.Errorf("graph: acquire token: %w", &transfer.Transient{Err: errors.New("RESPONSE 503")}), true, false},
		{"bad gateway", &transfer.Transient{Err: api(http.StatusBadGateway)}, true, false},
		{"file locked", api(http.StatusLocked), true, false},
		{"request timeout", api(http.StatusRequestTimeout), true, false},
		{"quota full", api(http.StatusInsufficientStorage), true, false},
		{"unparsable path", unparsable, false, false},
		{"folder forbidden", fmt.Errorf("create folder %q: %w", "Scans", api(http.StatusForbidden)), false, true},
		{"library gone", api(http.StatusNotFound), false, true},
		{"token refused", fmt.Errorf("graph: acquire token: %w", errors.New("AADSTS700027")), false, false},
		{"local file", fmt.Errorf("open: %w", missing), false, false},
	} {
		if got := transient(tc.err); got != tc.transient {
			t.Errorf("%s: transient = %v", tc.name, got)
		}
		if got := rejected(tc.err); got != tc.rejected {
			t.Errorf("%s: rejected = %v", tc.name, got)
		}
	}
}

func TestSizeMismatchIsNotAConfirmation(t *testing.T) {
	r := newRig(t, true)
	r.g.badDrive = "d1" // SharePoint reports one byte short
	rt := r.route("d1", "", "", "", 0)
	it, _ := r.queue("scan005.pdf", 1024, rt)

	r.once()

	got := r.item(it.ID)
	if got.Legs[0].State == model.LegConfirmed {
		t.Fatal("a short confirmation must not count as success")
	}
	if !strings.Contains(got.Legs[0].LastError, "expected 1024") {
		t.Errorf("lastError = %q", got.Legs[0].LastError)
	}
	if !exists(t, it.Path) {
		t.Error("the file must survive an unconfirmed upload")
	}
}

func TestDeleteAfterUploadOffKeepsTheFile(t *testing.T) {
	r := newRig(t, false)
	rt := r.route("d1", "", "", "", 0)
	it, _ := r.queue("scan006.pdf", 256, rt)

	r.once()

	got := r.item(it.ID)
	if !got.Done() {
		t.Fatalf("expected a completed item, got %+v", got.Legs)
	}
	if !exists(t, it.Path) {
		t.Error("the file must stay when DeleteAfterUpload is off")
	}
}

func TestResumeHonoursASavedOffset(t *testing.T) {
	r := newRig(t, true)
	rt := r.route("d1", "", "", "", 0)
	chunk := int64(config.GraphUploadChunkMultiple)
	it, _ := r.queue("scan007.pdf", int(2*chunk), rt)

	prog, err := transfer.NewFileProgressStore(filepath.Join(r.dir, "progress"))
	if err != nil {
		t.Fatal(err)
	}
	if err := prog.Save(progressKey(it.ID, rt.ID), chunk); err != nil {
		t.Fatal(err)
	}

	r.once()

	if got := r.g.firstAt["scan007.pdf"]; got != chunk {
		t.Fatalf("first chunk sent at %d, want a resume at %d", got, chunk)
	}
	if _, ok := r.st.Item(it.ID); ok {
		t.Error("the resumed upload should have completed")
	}
}

func TestTestRouteUploadsAProbeAndRemovesIt(t *testing.T) {
	r := newRig(t, true)
	rt := r.route("d1", "Scans", "{yyyy}", "", 0)

	if err := r.e.TestRoute(context.Background(), rt.ID); err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	r.g.mu.Lock()
	defer r.g.mu.Unlock()
	if len(r.g.deleted) != 1 {
		t.Fatalf("probe not cleaned up: deleted=%v", r.g.deleted)
	}
	var probe string
	for k := range r.g.files {
		probe = k
	}
	if !strings.HasPrefix(probe, "d1/Scans/"+time.Now().UTC().Format("2006")+"/m365-scan-test-") {
		t.Errorf("probe landed at %q", probe)
	}
	if !r.g.folders["d1/Scans/"+time.Now().UTC().Format("2006")] {
		t.Errorf("the templated folder was not created: %v", r.g.folders)
	}
}

// A box that has not been onboarded has no Graph client. Queued scans must wait
// rather than crash the daemon or burn their retry budget against nothing.
func TestNotConnectedLeavesWorkAlone(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	sh, _ := st.AddShare(model.Share{Name: "scans-hr", Enabled: true})
	d, _ := st.PutDestination(model.Destination{Name: "Personal", DriveID: "drv1"})
	rt, _ := st.PutRoute(model.Route{ShareID: sh.ID, DestinationID: d.ID, Enabled: true})
	src := filepath.Join(dir, "Rechnung.pdf")
	if err := os.WriteFile(src, []byte("scan"), 0o640); err != nil {
		t.Fatal(err)
	}
	it, _ := st.PutItem(model.Item{
		ShareID: sh.ID, Path: src, Name: "Rechnung.pdf", Size: 4,
		Discovered: time.Now(), Legs: []model.Leg{{RouteID: rt.ID, State: model.LegPending}},
	})

	e := New(st, graphref.New(nil), Options{ProgressDir: filepath.Join(dir, "p"), QuarantineDir: filepath.Join(dir, "q")},
		slog.New(slog.DiscardHandler))
	if err := e.Once(context.Background()); err != nil {
		t.Fatalf("Once must not fail when the box is not connected: %v", err)
	}

	got, _ := st.Item(it.ID)
	if got.Legs[0].State != model.LegPending {
		t.Fatalf("leg should still be pending, got %q", got.Legs[0].State)
	}
	if got.Legs[0].Attempts != 0 {
		t.Fatalf("a missing tenant must not consume the retry budget, attempts=%d", got.Legs[0].Attempts)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("the scan must still be on disk: %v", err)
	}
	if err := e.TestRoute(context.Background(), rt.ID); err == nil {
		t.Fatal("TestRoute should report that the box is not connected")
	}
}

// The delivery path deletes the file and the queue entry, so the only proof it
// worked is the record it leaves behind.
func TestDeliveredScanIsRecordedInTheHistory(t *testing.T) {
	r := newRig(t, true)
	a := r.route("d1", "", "{yyyy}/{MM}", model.ConflictOverwrite, 0)
	it, _ := r.queue("Rechnung.pdf", 2048, a)

	r.once()

	if _, ok := r.st.Item(it.ID); ok {
		t.Fatal("the queue entry should be gone once the scan is delivered")
	}
	hist := r.st.Uploads()
	if len(hist) != 1 {
		t.Fatalf("want one history record, got %d", len(hist))
	}
	u := hist[0]
	if u.Status != "uploaded" {
		t.Errorf("status = %q, want uploaded", u.Status)
	}
	if u.File != "Rechnung.pdf" || u.Size != 2048 || u.Share == "" {
		t.Errorf("record is missing the basics: %+v", u)
	}
	if len(u.Targets) != 1 || u.Targets[0].DriveItemID == "" {
		t.Errorf("want the driveItem recorded so the file can be found again: %+v", u.Targets)
	}
}

// A zero-byte scan never completes an upload session, so before this was caught
// up front the leg failed with `SharePoint confirmed id "" with 0 bytes,
// expected 0` — an error about the confirmation rather than about the file.
func TestEmptyFileIsRejectedWithItsOwnReason(t *testing.T) {
	r := newRig(t, true)
	rt := r.route("d1", "", "", "", 0)
	it, _ := r.queue("scan-empty.pdf", 0, rt)

	r.once()

	got := r.item(it.ID)
	if got.Legs[0].State != model.LegQuarantined {
		t.Errorf("leg state = %v, want quarantined: an empty file cannot become one that is not", got.Legs[0].State)
	}
	if !strings.Contains(got.Legs[0].LastError, "empty") {
		t.Errorf("lastError = %q, want it to name the empty file", got.Legs[0].LastError)
	}
	if strings.Contains(got.Legs[0].LastError, "confirmed id") {
		t.Errorf("lastError still blames the confirmation: %q", got.Legs[0].LastError)
	}
}
