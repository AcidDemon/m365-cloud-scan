package watch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
)

// stability is short enough that the suite stays fast and long enough that a
// scan pass cannot accidentally satisfy it.
const stability = 20 * time.Millisecond

type fixture struct {
	w     *Watcher
	st    *store.Store
	root  string
	share model.Share
}

func newFixture(t *testing.T, rules model.ShareRules) *fixture {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if rules.StabilityDelay == 0 {
		rules.StabilityDelay = model.Duration(stability)
	}
	sh, err := st.AddShare(model.Share{Name: "scans-hr", Enabled: true, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "srv")
	if err := os.MkdirAll(filepath.Join(root, sh.Name), 0o750); err != nil {
		t.Fatal(err)
	}
	return &fixture{
		w:     New(st, root, slog.New(slog.DiscardHandler)),
		st:    st,
		root:  root,
		share: sh,
	}
}

// route adds an enabled route with an optional per-route extension filter.
func (f *fixture) route(t *testing.T, enabled bool, filter ...string) model.Route {
	t.Helper()
	d, err := f.st.PutDestination(model.Destination{Name: store.NewID("dst")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.st.PutRoute(model.Route{ShareID: f.share.ID, DestinationID: d.ID, Enabled: enabled, Filter: filter})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *fixture) write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(f.root, f.share.Name, name)
	if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fixture) scan(t *testing.T) {
	t.Helper()
	if err := f.w.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// settle takes the two passes the stability rule needs: one to record the file,
// one after the delay to confirm it has not moved.
func (f *fixture) settle(t *testing.T) {
	t.Helper()
	f.scan(t)
	time.Sleep(2 * stability)
	f.scan(t)
}

func TestGrowingFileIsNotQueuedUntilStable(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	p := f.write(t, "scan.pdf", "page one")

	f.scan(t)
	if got := len(f.st.Items()); got != 0 {
		t.Fatalf("queued a file on first sight: %d items", got)
	}

	time.Sleep(2 * stability)
	if err := os.WriteFile(p, []byte("page one, page two"), 0o640); err != nil {
		t.Fatal(err)
	}
	f.scan(t)
	if got := len(f.st.Items()); got != 0 {
		t.Fatalf("queued a file that was still growing: %d items", got)
	}

	time.Sleep(2 * stability)
	f.scan(t)
	items := f.st.Items()
	if len(items) != 1 {
		t.Fatalf("want 1 item once the file held still, got %d", len(items))
	}
	if items[0].Path != p || items[0].Name != "scan.pdf" || items[0].Size != 18 {
		t.Fatalf("bad item: %+v", items[0])
	}
}

func TestSkippedNames(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	for _, name := range []string{".hidden.pdf", "~$draft.docx", "half.tmp", "half.PART", "x.crdownload", "y.filepart"} {
		f.write(t, name, "body")
	}
	f.write(t, "real.pdf", "body")

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 || items[0].Name != "real.pdf" {
		t.Fatalf("want only real.pdf queued, got %+v", items)
	}
}

func TestExtensionFilter(t *testing.T) {
	f := newFixture(t, model.ShareRules{Extensions: []string{"pdf", "TIF"}})
	f.route(t, true)
	f.write(t, "a.pdf", "body")
	f.write(t, "b.PDF", "body")
	f.write(t, "c.tif", "body")
	f.write(t, "d.txt", "body")
	f.write(t, "noext", "body")

	f.settle(t)
	got := map[string]bool{}
	for _, it := range f.st.Items() {
		got[it.Name] = true
	}
	want := map[string]bool{"a.pdf": true, "b.PDF": true, "c.tif": true}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for n := range want {
		if !got[n] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}

func TestMaxSizeFilter(t *testing.T) {
	f := newFixture(t, model.ShareRules{MaxSizeBytes: 8})
	f.route(t, true)
	f.write(t, "small.pdf", "12345678")
	f.write(t, "huge.pdf", "123456789")

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 || items[0].Name != "small.pdf" {
		t.Fatalf("want only small.pdf queued, got %+v", items)
	}
}

func TestTwoEnabledRoutesGiveTwoLegs(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	r1 := f.route(t, true)
	r2 := f.route(t, true)
	f.write(t, "scan.pdf", "body")

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 {
		t.Fatalf("want 1 item, got %d", len(items))
	}
	legs := map[string]model.LegState{}
	for _, l := range items[0].Legs {
		legs[l.RouteID] = l.State
	}
	if len(legs) != 2 || legs[r1.ID] != model.LegPending || legs[r2.ID] != model.LegPending {
		t.Fatalf("want a pending leg per route, got %+v", items[0].Legs)
	}
}

func TestDisabledRouteGetsNoLeg(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	on := f.route(t, true)
	f.route(t, false)
	f.write(t, "scan.pdf", "body")

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 || len(items[0].Legs) != 1 || items[0].Legs[0].RouteID != on.ID {
		t.Fatalf("want one leg on the enabled route, got %+v", items)
	}
}

func TestRouteFilterNarrowsLegs(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	all := f.route(t, true)
	f.route(t, true, "pdf")
	f.write(t, "scan.tif", "body")

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 || len(items[0].Legs) != 1 || items[0].Legs[0].RouteID != all.ID {
		t.Fatalf("want only the unfiltered route %s to get a leg, got %+v", all.ID, items)
	}
}

func TestZeroLegsQueuesNothing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *fixture)
	}{
		{"no routes at all", func(f *fixture) {}},
		{"only a disabled route", func(f *fixture) { f.route(t, false) }},
		{"every route filtered out", func(f *fixture) { f.route(t, true, "pdf") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, model.ShareRules{})
			tc.setup(f)
			f.write(t, "scan.tif", "body")

			f.settle(t)
			if got := len(f.st.Items()); got != 0 {
				t.Fatalf("queued an item with no legs: %d", got)
			}
		})
	}
}

func TestScanTwiceQueuesOnce(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	f.write(t, "scan.pdf", "body")

	f.settle(t)
	f.scan(t)
	f.scan(t)
	if got := len(f.st.Items()); got != 1 {
		t.Fatalf("want 1 item after repeated scans, got %d", got)
	}
}

func TestDisabledShareIsIgnored(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	f.write(t, "scan.pdf", "body")
	f.share.Enabled = false
	if err := f.st.PutShare(f.share); err != nil {
		t.Fatal(err)
	}

	f.settle(t)
	if got := len(f.st.Items()); got != 0 {
		t.Fatalf("scanned a disabled share: %d items", got)
	}
}

func TestSubdirectoriesAreScanned(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	sub := filepath.Join(f.root, f.share.Name, "monday")
	if err := os.MkdirAll(filepath.Join(sub, ".recycle"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "scan.pdf"), []byte("body"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, ".recycle", "old.pdf"), []byte("body"), 0o640); err != nil {
		t.Fatal(err)
	}

	f.settle(t)
	items := f.st.Items()
	if len(items) != 1 || items[0].Name != "scan.pdf" {
		t.Fatalf("want the subdirectory scan and nothing from .recycle, got %+v", items)
	}
}

func TestRunQueuesAFileAndStops(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	f.w.SetPollInterval(5 * time.Millisecond)
	f.w.SetRescanInterval(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.w.Run(ctx) }()

	f.write(t, "scan.pdf", "body")
	deadline := time.Now().Add(5 * time.Second)
	for len(f.st.Items()) == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Run never queued the file")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// An MFP that scans twice to the same filename overwrites the first file. The
// second scan must still be uploaded, and only once the first item is finished.
func TestOverwrittenFileIsQueuedAgainOnceTheItemIsDone(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	p := f.write(t, "Rechnung.pdf", "first")
	f.settle(t)

	first, ok := f.st.ItemByPath(p)
	if !ok {
		t.Fatal("the first scan was not queued")
	}

	// While the first upload is still running, a changed file must not be
	// queued a second time: the engine already has that path open.
	f.write(t, "Rechnung.pdf", "second and longer")
	f.settle(t)
	if got := len(f.st.Items()); got != 1 {
		t.Fatalf("a file changed mid-upload should not be re-queued, got %d items", got)
	}

	// Once the item has confirmed and the file was kept, the next scan replaces it.
	f.st.UpdateItem(first.ID, func(it *model.Item) {
		for i := range it.Legs {
			it.Legs[i].State = model.LegConfirmed
		}
	})
	f.write(t, "Rechnung.pdf", "third scan of the same name")
	f.settle(t)

	items := f.st.Items()
	if len(items) != 1 {
		t.Fatalf("want the finished item replaced by the new scan, got %d items", len(items))
	}
	if items[0].ID == first.ID {
		t.Fatal("the finished item was not replaced, so the new scan will never upload")
	}
	if items[0].Legs[0].State != model.LegPending {
		t.Fatalf("the replacement should start pending, got %q", items[0].Legs[0].State)
	}
}

// quarantine marks the item at p as quarantined without touching the file,
// which is what the engine leaves behind when the move out of the share fails.
func (f *fixture) quarantine(t *testing.T, p string) model.Item {
	t.Helper()
	it, ok := f.st.ItemByPath(p)
	if !ok {
		t.Fatalf("nothing queued at %s", p)
	}
	out, err := f.st.UpdateItem(it.ID, func(m *model.Item) {
		m.Quarantined = true
		m.Legs[0].State = model.LegQuarantined
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The engine is supposed to move a quarantined file out of the share. When that
// move fails the file stays, and the watcher used to queue it again on every
// sweep: 12 copies of one file is what put the dashboard in this state.
func TestQuarantinedFileThatNeverMovedIsNotRequeued(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	p := f.write(t, "Lieferschein.pdf", "one")
	f.settle(t)
	f.quarantine(t, p)

	// Sleeping between passes is what makes this a regression test: the stability
	// rule needs two passes a delay apart before anything is queued.
	for range 10 {
		f.scan(t)
		time.Sleep(2 * stability)
	}
	if got := len(f.st.Items()); got != 1 {
		t.Fatalf("want the single quarantine record, got %d items", got)
	}
}

// A different file at a quarantined item's path is a new scan and gets queued,
// while the quarantine record stays: it is what an admin still has to act on.
func TestQuarantinedItemDoesNotShadowANewFile(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	p := f.write(t, "Lieferschein.pdf", "one")
	f.settle(t)
	old := f.quarantine(t, p)

	f.write(t, "Lieferschein.pdf", "a fresh scan")
	f.settle(t)

	items := f.st.Items()
	if len(items) != 2 {
		t.Fatalf("want the quarantine record kept and the new scan queued, got %d items", len(items))
	}
	var kept bool
	for _, it := range items {
		if it.ID == old.ID {
			kept = it.Quarantined
		}
	}
	if !kept {
		t.Fatalf("the quarantine record was dropped: %+v", items)
	}
}

// A share created through the admin UI has no inotify watch until a scan runs.
// Before Kick existed, the first file dropped into a new share waited for the
// rescan tick, which on a real box is five minutes of apparent silence.
func TestKickScansWithoutWaitingForTheTick(t *testing.T) {
	f := newFixture(t, model.ShareRules{})
	f.route(t, true)
	f.w.SetRescanInterval(time.Hour) // long enough that only a kick can save us
	f.w.SetPollInterval(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.w.Run(ctx) }()

	// Give Run its startup scan, then write a file and ask for a scan now.
	time.Sleep(50 * time.Millisecond)
	f.write(t, "Rechnung.pdf", "scan")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.w.Kick()
		if len(f.st.Items()) == 1 {
			cancel()
			<-done
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("the file was never queued, so a kick does not trigger a scan")
}
