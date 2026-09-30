// Package watch turns files that land in the SMB share directories into queue
// items, one leg per route that wants a copy.
//
// The periodic scan is the mechanism and inotify is only there to shorten the
// latency: inotify drops events under load, and it never reports the files that
// were already on disk when the daemon started. A box that misses a scan is a
// box that loses paperwork, so the sweep runs whether or not inotify is alive.
package watch

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
)

const (
	defaultRescan    = 5 * time.Minute
	defaultPoll      = time.Second
	defaultStability = 5 * time.Second
)

// partialSuffixes are what scanners, SMB clients and browsers name a file while
// they are still writing it.
var partialSuffixes = []string{".tmp", ".part", ".crdownload", ".filepart"}

// sighting is the last stat of a candidate file and when that stat first held.
type sighting struct {
	size  int64
	mtime time.Time
	since time.Time
}

// logKey keeps the shout-once bookkeeping keyed by both fields; a path may
// contain any separator character we could otherwise splice in.
type logKey struct{ path, reason string }

type Watcher struct {
	st   *store.Store
	root string
	log  *slog.Logger

	rescan time.Duration
	poll   time.Duration
	kick   chan struct{}

	mu      sync.Mutex
	fsw     *fsnotify.Watcher
	seen    map[string]sighting
	logged  map[logKey]bool
	pending map[string]bool
}

// New watches <root>/<share.Name> for every enabled share.
// Kick asks for a scan now instead of at the next tick. Safe from any
// goroutine and safe before Run starts: the signal is dropped when one is
// already queued, because a scan that has not run yet will see the change.
func (w *Watcher) Kick() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func New(st *store.Store, root string, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	return &Watcher{
		st:      st,
		root:    filepath.Clean(root),
		log:     log,
		rescan:  defaultRescan,
		poll:    defaultPoll,
		kick:    make(chan struct{}, 1),
		seen:    map[string]sighting{},
		logged:  map[logKey]bool{},
		pending: map[string]bool{},
	}
}

// SetRescanInterval overrides the default 5 minute safety sweep.
func (w *Watcher) SetRescanInterval(d time.Duration) { w.rescan = d }

// SetPollInterval overrides the default 1 second stability poll.
func (w *Watcher) SetPollInterval(d time.Duration) { w.poll = d }

// Run blocks until ctx is done.
func (w *Watcher) Run(ctx context.Context) error {
	var events chan fsnotify.Event
	var errs chan error
	if fsw, err := fsnotify.NewWatcher(); err != nil {
		// Losing inotify costs latency, not correctness.
		w.log.Error("inotify unavailable, falling back to the periodic scan", "err", err)
	} else {
		defer fsw.Close()
		w.mu.Lock()
		w.fsw = fsw
		w.mu.Unlock()
		events, errs = fsw.Events, fsw.Errors
	}

	if err := w.Scan(ctx); err != nil {
		w.log.Warn("startup scan failed", "err", err)
	}
	rescanT := time.NewTicker(w.rescan)
	defer rescanT.Stop()
	pollT := time.NewTicker(w.poll)
	defer pollT.Stop()

	w.log.Info("watcher started", "root", w.root, "rescan", w.rescan, "poll", w.poll)
	for {
		select {
		case <-ctx.Done():
			w.log.Info("watcher stopping")
			return nil
		case <-rescanT.C:
			if err := w.Scan(ctx); err != nil {
				w.log.Warn("rescan failed", "err", err)
			}
		case <-w.kick:
			// A share created a moment ago has no inotify watch yet, because
			// watches are set in Scan. Without this, the first scan into a new
			// share waits for the rescan tick and the admin testing it concludes
			// the box is broken.
			if err := w.Scan(ctx); err != nil {
				w.log.Warn("scan after a share change failed", "err", err)
			}
		case <-pollT.C:
			w.drain()
		case ev := <-events:
			w.note(ev)
		case err := <-errs:
			w.log.Warn("inotify reported an error", "err", err)
		}
	}
}

// Scan does one pass over every share directory and queues what qualifies. Run
// calls it on startup and on every rescan tick; the tests call it directly.
func (w *Watcher) Scan(ctx context.Context) error {
	alive := map[string]bool{}
	for _, sh := range w.st.Shares() {
		if !sh.Enabled {
			continue
		}
		dir := filepath.Join(w.root, sh.Name)
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				// One unreadable subtree must not cost us the rest of the box.
				if p == dir {
					w.logOnce(dir, "unreadable", func() {
						w.log.Error("share directory cannot be read", "share", sh.Name, "dir", dir, "err", err)
					})
				}
				return nil
			}
			if d.IsDir() {
				// Samba's recycle bin and snapshot directories are not scans.
				if p != dir && strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
				w.watchDir(p)
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			alive[p] = true
			w.consider(sh, p)
			return nil
		})
		if err != nil {
			return err
		}
	}
	w.prune(alive)
	return nil
}

// consider queues one path if it qualifies. It reports whether the path is
// settled: queued, skipped or gone. A false means "still moving, ask again".
func (w *Watcher) consider(sh model.Share, p string) bool {
	name := filepath.Base(p)
	if skipName(name) || !extAllowed(name, sh.Rules.Extensions) {
		return true
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		w.forget(p)
		return true
	}
	if !w.unqueued(p, fi) {
		w.forget(p)
		return true
	}
	if !w.stable(p, fi, sh.Rules.StabilityDelay.Std()) {
		return false
	}
	if max := sh.Rules.MaxSizeBytes; max > 0 && fi.Size() > max {
		// A scan nobody hears about is worse than one that fails loudly.
		w.logOnce(p, "toobig", func() {
			w.log.Error("scan skipped: larger than the share limit", "path", p, "size", fi.Size(), "limit", max)
		})
		return true
	}
	legs := w.legs(sh, name)
	if len(legs) == 0 {
		// Item.Done needs every leg confirmed, so a legless item can never
		// finish and would sit in the queue forever. Leave the file on disk.
		w.logOnce(p, "nolegs", func() {
			w.log.Error("scan not queued: no enabled route accepts it", "path", p, "share", sh.Name)
		})
		return true
	}
	it, err := w.st.PutItem(model.Item{
		ShareID:    sh.ID,
		Path:       p,
		Name:       name,
		Size:       fi.Size(),
		Discovered: time.Now(),
		Legs:       legs,
	})
	if err != nil {
		w.log.Error("queueing scan failed", "path", p, "err", err)
		return false
	}
	w.forget(p)
	w.log.Info("queued scan", "item", it.ID, "share", sh.Name, "path", p, "size", it.Size, "legs", len(legs))
	return true
}

// unqueued reports whether the file now at p is one no item already describes.
// An MFP that scans to the same filename twice overwrites the first scan, and a
// plain path lookup would treat the second one as already handled and never
// upload it.
//
// The comparison is size and mtime against the item, never the item's state. A
// quarantined item is supposed to have had its file moved out of the share, but
// if the move failed the file is still sitting there, and trusting the state
// would queue that same file on every sweep forever.
func (w *Watcher) unqueued(p string, fi os.FileInfo) bool {
	known := w.st.ItemsByPath(p)
	for _, it := range known {
		if it.Size == fi.Size() && !fi.ModTime().After(it.Discovered) {
			return false
		}
	}
	for _, it := range known {
		// Re-queueing a file the engine has open would upload it twice.
		if !it.Done() && !it.Quarantined {
			w.logOnce(p, "inflight", func() {
				w.log.Warn("file changed while it was being uploaded; the new content will not be sent",
					"path", p, "item", it.ID)
			})
			return false
		}
	}
	for _, it := range known {
		// The item finished and the file was kept because the share does not
		// delete after upload. Drop the finished record so the new scan can take
		// its place. A quarantined record stays: it is what an admin acts on.
		if it.Done() && !it.Quarantined {
			if err := w.st.DeleteItem(it.ID); err != nil {
				w.log.Error("replacing a completed item failed", "item", it.ID, "err", err)
				return false
			}
		}
	}
	return true
}

// legs is one pending leg per enabled route that admits this extension.
func (w *Watcher) legs(sh model.Share, name string) []model.Leg {
	var legs []model.Leg
	for _, r := range w.st.RoutesForShare(sh.ID) {
		if !extAllowed(name, r.Filter) {
			continue
		}
		legs = append(legs, model.Leg{RouteID: r.ID, State: model.LegPending})
	}
	return legs
}

// stable reports whether size and mtime have held for the delay. A single write
// event proves nothing: MFPs write in bursts and pause mid-page.
func (w *Watcher) stable(p string, fi os.FileInfo, delay time.Duration) bool {
	if delay <= 0 {
		delay = defaultStability
	}
	now := time.Now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if prev, ok := w.seen[p]; ok && prev.size == fi.Size() && prev.mtime.Equal(fi.ModTime()) {
		return now.Sub(prev.since) >= delay
	}
	w.seen[p] = sighting{size: fi.Size(), mtime: fi.ModTime(), since: now}
	return false
}

// note turns an inotify event into a candidate. A rename inside the share
// arrives as a pair; the destination half is a Create, which is the only half
// that matters.
func (w *Watcher) note(ev fsnotify.Event) {
	if !ev.Has(fsnotify.Create) && !ev.Has(fsnotify.Write) {
		return
	}
	if fi, err := os.Stat(ev.Name); err == nil && fi.IsDir() {
		w.watchTree(ev.Name)
		return
	}
	w.mu.Lock()
	w.pending[ev.Name] = true
	w.mu.Unlock()
}

// watchTree watches a directory that appeared under a share, and takes its
// contents as candidates: files can land in it before the watch does.
func (w *Watcher) watchTree(dir string) {
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			w.watchDir(p)
			return nil
		}
		w.mu.Lock()
		w.pending[p] = true
		w.mu.Unlock()
		return nil
	})
}

// drain re-checks the paths inotify pointed at, keeping the ones still moving.
func (w *Watcher) drain() {
	w.mu.Lock()
	paths := make([]string, 0, len(w.pending))
	for p := range w.pending {
		paths = append(paths, p)
	}
	clear(w.pending)
	w.mu.Unlock()

	shares := w.st.Shares()
	for _, p := range paths {
		sh, ok := shareFor(shares, w.root, p)
		if !ok {
			continue
		}
		if !w.consider(sh, p) {
			w.mu.Lock()
			w.pending[p] = true
			w.mu.Unlock()
		}
	}
}

func (w *Watcher) watchDir(dir string) {
	w.mu.Lock()
	fsw := w.fsw
	w.mu.Unlock()
	if fsw == nil {
		return
	}
	if err := fsw.Add(dir); err != nil {
		w.log.Warn("cannot watch directory", "dir", dir, "err", err)
	}
}

func (w *Watcher) forget(p string) {
	w.mu.Lock()
	delete(w.seen, p)
	w.mu.Unlock()
}

func (w *Watcher) logOnce(p, reason string, f func()) {
	k := logKey{p, reason}
	w.mu.Lock()
	dup := w.logged[k]
	w.logged[k] = true
	w.mu.Unlock()
	if !dup {
		f()
	}
}

// prune drops bookkeeping for paths the last full pass no longer found, so the
// maps stay the size of the share directories rather than of their history.
func (w *Watcher) prune(alive map[string]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for p := range w.seen {
		if !alive[p] {
			delete(w.seen, p)
		}
	}
	for k := range w.logged {
		if !alive[k.path] {
			delete(w.logged, k)
		}
	}
}

func shareFor(shares []model.Share, root, p string) (model.Share, bool) {
	for _, sh := range shares {
		if !sh.Enabled {
			continue
		}
		if strings.HasPrefix(p, filepath.Join(root, sh.Name)+string(filepath.Separator)) {
			return sh, true
		}
	}
	return model.Share{}, false
}

func skipName(name string) bool {
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "~$") {
		return true
	}
	low := strings.ToLower(name)
	return slices.ContainsFunc(partialSuffixes, func(s string) bool { return strings.HasSuffix(low, s) })
}

// extAllowed treats an empty list as "everything", which is what both
// ShareRules.Extensions and Route.Filter mean when unset.
func extAllowed(name string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	return slices.ContainsFunc(allowed, func(a string) bool {
		return strings.EqualFold(strings.TrimPrefix(a, "."), ext)
	})
}
