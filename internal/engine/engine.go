// Package engine drives every queued leg to SharePoint and removes the local
// scan only once all of them have confirmed.
//
// The failure asymmetry runs the other way round from a print queue: re-sending
// bytes costs a retry, but a scan deleted before it landed is gone for good.
// So every failure path here keeps the file: a leg that gives up moves it to
// quarantine, it never unlinks. An upload counts as confirmed only when Graph
// hands back a driveItem whose id is set and whose size matches the bytes on
// disk.
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/graphref"
	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

// defaultMaxAttempts is how many times a leg may fail before its file is
// quarantined, when the route does not say.
const defaultMaxAttempts = 5

// notConnectedEvery is how often an un-onboarded box repeats that it is waiting.
const notConnectedEvery = 15 * time.Minute

// errNotConnected is a terminal-looking error that must never consume the retry
// budget: the fix is onboarding the box, not trying again.
var errNotConnected = errors.New("the box is not connected to Microsoft 365")

type Options struct {
	ProgressDir   string
	QuarantineDir string
	Retry         config.RetryPolicy
	Interval      time.Duration // how often to look for work; default 2s
	// KeepHistory prunes the upload log by age. Zero keeps everything up to the
	// store's own cap.
	KeepHistory time.Duration
	Workers     int // concurrent legs; default 2
}

type Engine struct {
	st  *store.Store
	gc  *graphref.Ref
	opt Options
	log *slog.Logger

	mu         sync.Mutex
	lastNoConn time.Time
}

func New(st *store.Store, gc *graphref.Ref, opt Options, log *slog.Logger) *Engine {
	if opt.Interval <= 0 {
		opt.Interval = 2 * time.Second
	}
	if opt.Workers <= 0 {
		opt.Workers = 2
	}
	if opt.Retry == (config.RetryPolicy{}) {
		opt.Retry = config.DefaultRetryPolicy()
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Engine{st: st, gc: gc, opt: opt, log: log}
}

// Run works the queue until the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	t := time.NewTicker(e.opt.Interval)
	defer t.Stop()
	for {
		if err := e.Once(ctx); err != nil && ctx.Err() == nil {
			e.log.Error("upload pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Once does a single pass and returns when there is nothing more to do right
// now. Run calls it on a ticker; the tests call it directly.
// notConnected reports the backlog every notConnectedEvery, at warning level.
// A box sits un-onboarded between installation and the reseller running the
// wizard, which is expected rather than broken, and an hourly error would train
// whoever reads the journal to ignore it.
func (e *Engine) notConnected(waiting int) {
	e.mu.Lock()
	quiet := time.Since(e.lastNoConn) < notConnectedEvery
	if !quiet {
		e.lastNoConn = time.Now()
	}
	e.mu.Unlock()
	if !quiet {
		e.log.Warn("scans are waiting until the box is connected to Microsoft 365", "waiting", waiting)
	}
}

func (e *Engine) Once(ctx context.Context) error {
	// A box that has not been onboarded yet has no Graph client. Scans keep
	// arriving and keep waiting; burning the retry budget against a tenant that
	// was never configured would quarantine perfectly good files.
	if e.gc.Get() == nil {
		if n := len(e.st.Items()); n > 0 {
			e.notConnected(n)
		}
		return ctx.Err()
	}
	prog, err := transfer.NewFileProgressStore(e.opt.ProgressDir)
	if err != nil {
		return err
	}
	// One goroutine per item, not per leg: legs of an item share a file and a
	// store record, so they must not overlap. That also bounds legs in flight.
	sem := make(chan struct{}, e.opt.Workers)
	done := make(chan struct{})
	var started int
	for _, it := range e.st.Items() {
		if !e.wanted(it) {
			continue
		}
		started++
		go func(id string) {
			defer func() { done <- struct{}{} }()
			sem <- struct{}{}
			defer func() { <-sem }()
			e.runItem(ctx, id, prog)
		}(it.ID)
	}
	for range started {
		<-done
	}
	return ctx.Err()
}

// wanted reports whether an item has anything to do this pass: a leg that is
// due, or a finished item whose local copy is still waiting to be cleaned up.
func (e *Engine) wanted(it model.Item) bool {
	if it.Done() {
		return true
	}
	now := time.Now()
	for _, l := range it.Legs {
		if legDue(l, now) {
			return true
		}
	}
	return false
}

func legDue(l model.Leg, now time.Time) bool {
	switch l.State {
	case model.LegPending, model.LegUploading: // uploading means a crash mid-leg
		return true
	case model.LegRetrying:
		return !l.NextAttempt.After(now)
	}
	return false
}

func (e *Engine) runItem(ctx context.Context, id string, prog transfer.ProgressStore) {
	it, ok := e.st.Item(id)
	if !ok {
		return
	}
	for i := range it.Legs {
		if ctx.Err() != nil {
			return
		}
		// Re-read: an earlier leg may have moved the file to quarantine.
		fresh, ok := e.st.Item(id)
		if !ok || i >= len(fresh.Legs) || !legDue(fresh.Legs[i], time.Now()) {
			continue
		}
		e.runLeg(ctx, fresh, i, prog)
	}
	e.finish(id)
}

func (e *Engine) runLeg(ctx context.Context, it model.Item, i int, prog transfer.ProgressStore) {
	leg := it.Legs[i]
	share, ok := e.st.Share(it.ShareID)
	if !ok {
		e.fail(it, i, model.Route{}, errors.New("the share no longer exists"), true)
		return
	}
	rt, ok := e.st.Route(leg.RouteID)
	if !ok {
		e.fail(it, i, model.Route{}, errors.New("the route no longer exists"), true)
		return
	}
	dest, ok := e.st.Destination(rt.DestinationID)
	if !ok {
		e.fail(it, i, rt, errors.New("the destination no longer exists"), true)
		return
	}

	src := e.localPath(it, share)
	f, err := os.Open(src)
	if err != nil {
		e.fail(it, i, rt, fmt.Errorf("open %s: %w", src, err), false)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		e.fail(it, i, rt, err, false)
		return
	}
	size := st.Size()
	// An upload session with nothing to send is never completed by Graph, so it
	// returns no drive item and the size check below would report the confusing
	// `confirmed id "" with 0 bytes, expected 0`. The file has also been this
	// size for the whole stability delay, so it is empty rather than half
	// written: retrying cannot change it.
	if size == 0 {
		e.fail(it, i, rt, errors.New("the file is empty, so there is nothing to upload"), true)
		return
	}

	gc := e.gc.Get()
	if gc == nil {
		e.fail(it, i, rt, errNotConnected, true)
		return
	}
	folder := model.DestPath(dest, rt, it.Discovered, share.Name)
	if err := gc.EnsureFolderPath(ctx, dest.DriveID, folder); err != nil {
		e.fail(it, i, rt, fmt.Errorf("create folder %q: %w", folder, err), false)
		return
	}
	sess, err := gc.CreateUploadSessionConflict(ctx, dest.DriveID, joinPath(folder, it.Name), conflictBehavior(rt.Conflict))
	if err != nil {
		e.fail(it, i, rt, err, false)
		return
	}

	e.setLeg(it.ID, i, func(l *model.Leg) { l.State = model.LegUploading })
	// ponytail: the offset survives a crash but the session URL does not, so a
	// resume into a fresh session can only fail the size check below, never fake
	// a success. Persist the upload URL on the leg if real resume is wanted.
	key := progressKey(it.ID, rt.ID)
	sent := func(n int64) { e.setLeg(it.ID, i, func(l *model.Leg) { l.Sent = n }) }
	if err := transfer.Upload(ctx, e.opt.Retry, key, f, size, tracker{sess, sent}, prog); err != nil {
		// The dead session's offset would poison the next attempt, which opens a
		// fresh session that has none of these bytes.
		_ = prog.Clear(key)
		e.fail(it, i, rt, err, false)
		return
	}

	di := sess.Item()
	if di.ID == "" || di.Size != size {
		_ = prog.Clear(key)
		e.fail(it, i, rt, fmt.Errorf("SharePoint confirmed id %q with %d bytes, expected %d", di.ID, di.Size, size), false)
		return
	}
	e.setLeg(it.ID, i, func(l *model.Leg) {
		l.State = model.LegConfirmed
		l.LastError = ""
		l.Sent = size
		l.DriveItemID = di.ID
		l.WebURL = di.WebURL
		l.UploadedAt = time.Now()
		l.NextAttempt = time.Time{}
	})
	e.log.Info("leg confirmed", "item", it.ID, "route", rt.ID, "driveItem", di.ID, "bytes", size)
}

// fail records a failed leg. Nothing here deletes the file: a leg out of
// attempts quarantines it instead, and the item's other legs carry on against
// the moved path.
func (e *Engine) fail(it model.Item, i int, rt model.Route, cause error, terminal bool) {
	max := rt.MaxAttempts
	if max <= 0 {
		max = defaultMaxAttempts
	}
	var gaveUp bool
	e.setLeg(it.ID, i, func(l *model.Leg) {
		l.Attempts++
		l.LastError = cause.Error()
		if terminal || l.Attempts >= max {
			l.State = model.LegQuarantined
			gaveUp = true
			return
		}
		l.State = model.LegRetrying
		l.NextAttempt = time.Now().Add(transfer.Backoff(e.opt.Retry, l.Attempts, rand.Float64()))
	})
	if !gaveUp {
		e.log.Warn("leg failed, will retry", "item", it.ID, "route", rt.ID, "err", cause)
		return
	}
	e.log.Error("leg gave up, quarantining the scan", "item", it.ID, "route", rt.ID, "err", cause)
	if err := e.quarantine(it.ID); err != nil {
		e.log.Error("quarantine failed, the scan stays in the share", "item", it.ID, "err", err)
	}
	// A failure belongs in the history too. An admin asking "what happened to
	// that scan" is usually asking about one that did not arrive.
	if cur, ok := e.st.Item(it.ID); ok {
		if share, ok := e.st.Share(cur.ShareID); ok {
			e.record(cur, share, "quarantined", cause.Error())
		}
	}
}

// quarantine moves the file out of the share so an operator sees a stalled scan
// in one place. The item stays in the store until an admin retries or clears it.
func (e *Engine) quarantine(id string) error {
	it, ok := e.st.Item(id)
	if !ok || it.Quarantined {
		return nil // a sibling leg already moved it
	}
	share, ok := e.st.Share(it.ShareID)
	if !ok {
		return errors.New("the share no longer exists")
	}
	if err := moveFile(it.Path, e.quarantinePath(it, share)); err != nil {
		return err
	}
	_, err := e.st.UpdateItem(id, func(m *model.Item) { m.Quarantined = true })
	return err
}

// finish deletes the local file once every leg has confirmed, if the share says
// so. The driveItem ids and URLs are logged first: after the unlink they are
// the only record of where the scan went.
// record writes one line of history. A failure to record must not stop the
// delivery it describes, so it is logged and swallowed.
func (e *Engine) record(it model.Item, share model.Share, status, errText string) {
	u := model.Upload{
		ItemID: it.ID,
		At:     time.Now(), Share: share.Name, File: it.Name,
		Size: it.Size, Status: status, Error: errText,
	}
	for _, l := range it.Legs {
		leg := model.UploadLeg{RouteID: l.RouteID, DriveItemID: l.DriveItemID, WebURL: l.WebURL}
		if rt, ok := e.st.Route(l.RouteID); ok {
			if d, ok := e.st.Destination(rt.DestinationID); ok {
				leg.Destination = d.Label()
			}
		}
		u.Targets = append(u.Targets, leg)
	}
	if err := e.st.AppendUpload(u, e.opt.KeepHistory); err != nil {
		e.log.Error("recording the upload failed", "item", it.ID, "err", err)
	}
}

func (e *Engine) finish(id string) {
	it, ok := e.st.Item(id)
	if !ok || !it.Done() {
		return
	}
	share, ok := e.st.Share(it.ShareID)
	if !ok || !share.Rules.DeleteAfterUpload {
		return
	}
	landed := make([]string, 0, len(it.Legs))
	for _, l := range it.Legs {
		landed = append(landed, l.RouteID+" "+l.DriveItemID+" "+l.WebURL)
	}
	path := e.localPath(it, share)
	e.log.Info("scan delivered, deleting the local copy", "item", it.ID, "file", path, "landed", strings.Join(landed, "; "))
	// Record it before the item goes: the history is the only thing left once
	// the file and the queue entry are both gone.
	e.record(it, share, "uploaded", "")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// Keep the item: it is what stops the watcher re-queueing the file.
		e.log.Error("delete failed, keeping the item", "item", it.ID, "file", path, "err", err)
		return
	}
	if err := e.st.DeleteItem(it.ID); err != nil {
		e.log.Error("dropping the item failed", "item", it.ID, "err", err)
	}
}

// Retry puts a quarantined or failed item's legs back to pending and, if the
// file was moved to quarantine, moves it back into the share.
func (e *Engine) Retry(itemID string) error {
	it, ok := e.st.Item(itemID)
	if !ok {
		return errors.New("item not found")
	}
	share, ok := e.st.Share(it.ShareID)
	if !ok {
		return errors.New("the share no longer exists")
	}
	dst := it.Path
	if it.Quarantined {
		if _, err := os.Stat(dst); err == nil {
			// A newer scan took the name while this one sat in quarantine.
			dst = filepath.Join(filepath.Dir(dst), it.ID+"-"+it.Name)
		}
		if err := moveFile(e.quarantinePath(it, share), dst); err != nil {
			return fmt.Errorf("move %s back into the share: %w", it.Name, err)
		}
	}
	_, err := e.st.UpdateItem(itemID, func(m *model.Item) {
		m.Quarantined = false
		m.Path = dst
		for i := range m.Legs {
			if m.Legs[i].State == model.LegConfirmed {
				continue
			}
			m.Legs[i] = model.Leg{RouteID: m.Legs[i].RouteID, State: model.LegPending}
		}
	})
	return err
}

// TestRoute uploads a small probe file through a route and removes it again,
// so an admin can prove the wiring works before an MFP is involved.
func (e *Engine) TestRoute(ctx context.Context, routeID string) error {
	if e.gc.Get() == nil {
		return errors.New("the box is not connected to Microsoft 365")
	}
	rt, ok := e.st.Route(routeID)
	if !ok {
		return errors.New("route not found")
	}
	dest, ok := e.st.Destination(rt.DestinationID)
	if !ok {
		return errors.New("the destination no longer exists")
	}
	share, _ := e.st.Share(rt.ShareID) // only feeds the {share} token

	gc := e.gc.Get()
	if gc == nil {
		return errNotConnected
	}
	now := time.Now()
	folder := model.DestPath(dest, rt, now, share.Name)
	if err := gc.EnsureFolderPath(ctx, dest.DriveID, folder); err != nil {
		return fmt.Errorf("create folder %q: %w", folder, err)
	}
	body := []byte("m365 cloud scan connectivity test\n")
	name := "m365-scan-test-" + now.UTC().Format("20060102-150405") + ".txt"
	sess, err := gc.CreateUploadSessionConflict(ctx, dest.DriveID, joinPath(folder, name), "replace")
	if err != nil {
		return err
	}
	if err := transfer.Upload(ctx, e.opt.Retry, "probe:"+routeID, bytes.NewReader(body), int64(len(body)), sess, nopProgress{}); err != nil {
		return err
	}
	di := sess.Item()
	if di.ID == "" || di.Size != int64(len(body)) {
		return fmt.Errorf("SharePoint accepted the probe but confirmed %d of %d bytes", di.Size, len(body))
	}
	return gc.DeleteDriveItem(ctx, dest.DriveID, di.ID)
}

func (e *Engine) setLeg(id string, i int, fn func(*model.Leg)) {
	if _, err := e.st.UpdateItem(id, func(m *model.Item) {
		if i < len(m.Legs) {
			fn(&m.Legs[i])
		}
	}); err != nil {
		e.log.Error("state update failed", "item", id, "err", err)
	}
}

// localPath is where the bytes are right now. Item.Path always names the share
// copy, which is what makes Retry a plain move back; the quarantine copy is
// derived from the item id, so nothing has to remember two paths.
func (e *Engine) localPath(it model.Item, share model.Share) string {
	if it.Quarantined {
		return e.quarantinePath(it, share)
	}
	return it.Path
}

// quarantinePath keeps the item id in the name so two scans called scan001.pdf
// cannot overwrite each other on the way out of the share.
func (e *Engine) quarantinePath(it model.Item, share model.Share) string {
	return filepath.Join(e.opt.QuarantineDir, share.Name, it.ID+"-"+it.Name)
}

func progressKey(itemID, routeID string) string { return itemID + ":" + routeID }

// tracker mirrors the confirmed offset into the leg for the UI's progress bar.
// ponytail: one state-file write per chunk; at 5 MiB chunks that is noise.
type tracker struct {
	up   transfer.ChunkUploader
	sent func(int64)
}

func (t tracker) UploadChunk(ctx context.Context, offset int64, chunk []byte, size int64) (int64, error) {
	next, err := t.up.UploadChunk(ctx, offset, chunk, size)
	if err == nil {
		t.sent(next)
	}
	return next, err
}

// nopProgress keeps probe uploads out of the progress directory; a 34-byte file
// has nothing worth resuming.
type nopProgress struct{}

func (nopProgress) Load(string) (int64, bool, error) { return 0, false, nil }
func (nopProgress) Save(string, int64) error         { return nil }
func (nopProgress) Clear(string) error               { return nil }

func conflictBehavior(p model.ConflictPolicy) string {
	if p == model.ConflictOverwrite {
		return "replace"
	}
	return "rename"
}

func joinPath(folder, name string) string {
	if folder == "" {
		return name
	}
	return folder + "/" + name
}

// moveFile renames, falling back to copy and remove: the share root and the
// quarantine directory are separate trees and may be separate filesystems.
func moveFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}
