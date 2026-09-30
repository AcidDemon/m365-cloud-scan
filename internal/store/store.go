// Package store keeps shares, destinations, routes and queue items in one JSON
// file. There is no database: the whole state of a box is a few dozen records,
// and a file that an admin can read during an incident is worth more than
// query power nobody needs.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
)

// ErrNotFound is returned by the update and delete helpers.
var ErrNotFound = errors.New("not found")

// shareName is what Samba, the filesystem and the {share} token all tolerate.
var shareName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

type state struct {
	Shares       []model.Share       `json:"shares"`
	Destinations []model.Destination `json:"destinations"`
	Routes       []model.Route       `json:"routes"`
	Items        []model.Item        `json:"items"`
	Uploads      []model.Upload      `json:"uploads"`
}

// maxUploads bounds the history whatever the retention setting says, so a busy
// box cannot grow its state file without limit.
const maxUploads = 2000

// Store is safe for concurrent use. Every mutation writes the whole file, which
// at this size costs less than tracking dirty records.
type Store struct {
	path string
	mu   sync.RWMutex
	st   state
}

// Open loads the state file, treating a missing file as an empty box.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &s.st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return s, nil
}

// save writes via a temp file and rename so a crash mid-write cannot truncate
// the state. The caller holds the lock.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// NewID mints a prefixed random id, e.g. "shr-9f2c1a7b".
func NewID(prefix string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return prefix + "-" + hex.EncodeToString(b)
}

// ValidShareName checks the name against what Samba and the filesystem accept.
func ValidShareName(n string) error {
	if !shareName.MatchString(n) {
		return errors.New("use 3 to 32 characters: lowercase letters, digits and hyphens, not starting or ending with a hyphen")
	}
	return nil
}

// --- shares ---

func (s *Store) Shares() []model.Share {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]model.Share(nil), s.st.Shares...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Share(id string) (model.Share, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sh := range s.st.Shares {
		if sh.ID == id {
			return sh, true
		}
	}
	return model.Share{}, false
}

// AddShare rejects a duplicate name. The name is the directory and the SMB
// share, so two of them cannot coexist.
func (s *Store) AddShare(sh model.Share) (model.Share, error) {
	if err := ValidShareName(sh.Name); err != nil {
		return model.Share{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.st.Shares {
		if e.Name == sh.Name {
			return model.Share{}, fmt.Errorf("a share named %q already exists", sh.Name)
		}
	}
	if sh.ID == "" {
		sh.ID = NewID("shr")
	}
	if sh.CreatedAt.IsZero() {
		sh.CreatedAt = time.Now()
	}
	s.st.Shares = append(s.st.Shares, sh)
	return sh, s.save()
}

func (s *Store) PutShare(sh model.Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.st.Shares {
		if e.ID == sh.ID {
			s.st.Shares[i] = sh
			return s.save()
		}
	}
	return ErrNotFound
}

// DeleteShare also drops the routes that fed from it; a route without a source
// is not a thing the rest of the code should ever have to reason about.
func (s *Store) DeleteShare(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.Shares)
	s.st.Shares = filter(s.st.Shares, func(sh model.Share) bool { return sh.ID != id })
	if len(s.st.Shares) == n {
		return ErrNotFound
	}
	s.st.Routes = filter(s.st.Routes, func(r model.Route) bool { return r.ShareID != id })
	s.st.Items = filter(s.st.Items, func(it model.Item) bool { return it.ShareID != id })
	return s.save()
}

// --- destinations ---

func (s *Store) Destinations() []model.Destination {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Destination(nil), s.st.Destinations...)
}

func (s *Store) Destination(id string) (model.Destination, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.st.Destinations {
		if d.ID == id {
			return d, true
		}
	}
	return model.Destination{}, false
}

func (s *Store) PutDestination(d model.Destination) (model.Destination, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = NewID("dst")
		s.st.Destinations = append(s.st.Destinations, d)
		return d, s.save()
	}
	for i, e := range s.st.Destinations {
		if e.ID == d.ID {
			s.st.Destinations[i] = d
			return d, s.save()
		}
	}
	return model.Destination{}, ErrNotFound
}

// DeleteDestination refuses while routes still point at it, so a delete can
// never silently stop a scan folder from being delivered.
func (s *Store) DeleteDestination(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var used int
	for _, r := range s.st.Routes {
		if r.DestinationID == id {
			used++
		}
	}
	if used > 0 {
		return fmt.Errorf("%d route(s) still use this destination", used)
	}
	n := len(s.st.Destinations)
	s.st.Destinations = filter(s.st.Destinations, func(d model.Destination) bool { return d.ID != id })
	if len(s.st.Destinations) == n {
		return ErrNotFound
	}
	return s.save()
}

// --- routes ---

func (s *Store) Routes() []model.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Route(nil), s.st.Routes...)
}

func (s *Store) Route(id string) (model.Route, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.st.Routes {
		if r.ID == id {
			return r, true
		}
	}
	return model.Route{}, false
}

// RoutesForShare returns only the enabled routes, which is what the watcher
// wants when it decides how many legs a new file gets.
func (s *Store) RoutesForShare(shareID string) []model.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Route
	for _, r := range s.st.Routes {
		if r.ShareID == shareID && r.Enabled {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) PutRoute(r model.Route) (model.Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		for _, e := range s.st.Routes {
			if e.ShareID == r.ShareID && e.DestinationID == r.DestinationID {
				return model.Route{}, errors.New("that share already routes to that destination")
			}
		}
		r.ID = NewID("rte")
		s.st.Routes = append(s.st.Routes, r)
		return r, s.save()
	}
	for i, e := range s.st.Routes {
		if e.ID == r.ID {
			s.st.Routes[i] = r
			return r, s.save()
		}
	}
	return model.Route{}, ErrNotFound
}

func (s *Store) DeleteRoute(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.Routes)
	s.st.Routes = filter(s.st.Routes, func(r model.Route) bool { return r.ID != id })
	if len(s.st.Routes) == n {
		return ErrNotFound
	}
	return s.save()
}

// --- items ---

func (s *Store) Items() []model.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.Item(nil), s.st.Items...)
}

func (s *Store) Item(id string) (model.Item, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, it := range s.st.Items {
		if it.ID == id {
			return it, true
		}
	}
	return model.Item{}, false
}

// ItemByPath returns the first item recorded at a path. A path can carry more
// than one item, so prefer ItemsByPath unless any of them will do.
func (s *Store) ItemByPath(p string) (model.Item, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, it := range s.st.Items {
		if it.Path == p {
			return it, true
		}
	}
	return model.Item{}, false
}

// ItemsByPath returns every item recorded at a path. More than one is normal
// after a file has been quarantined and a new scan has taken its place.
func (s *Store) ItemsByPath(p string) []model.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.Item
	for _, it := range s.st.Items {
		if it.Path == p {
			out = append(out, it)
		}
	}
	return out
}

func (s *Store) PutItem(it model.Item) (model.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if it.ID == "" {
		it.ID = NewID("itm")
		s.st.Items = append(s.st.Items, it)
		return it, s.save()
	}
	for i, e := range s.st.Items {
		if e.ID == it.ID {
			s.st.Items[i] = it
			return it, s.save()
		}
	}
	s.st.Items = append(s.st.Items, it)
	return it, s.save()
}

// UpdateItem applies fn under the write lock, so a leg's progress cannot be
// clobbered by a concurrent read-modify-write from another route's goroutine.
func (s *Store) UpdateItem(id string, fn func(*model.Item)) (model.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.st.Items {
		if s.st.Items[i].ID == id {
			fn(&s.st.Items[i])
			return s.st.Items[i], s.save()
		}
	}
	return model.Item{}, ErrNotFound
}

func (s *Store) DeleteItem(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.st.Items)
	s.st.Items = filter(s.st.Items, func(it model.Item) bool { return it.ID != id })
	if len(s.st.Items) == n {
		return ErrNotFound
	}
	return s.save()
}

// --- upload history ---

// Uploads returns the finished files, newest first.
func (s *Store) Uploads() []model.Upload {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]model.Upload(nil), s.st.Uploads...)
	sort.Slice(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	return out
}

// AppendUpload records a finished file and prunes anything older than keep.
// A keep of zero means the caller wants no pruning by age.
func (s *Store) AppendUpload(u model.Upload, keep time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u.ID == "" {
		u.ID = NewID("upl")
	}
	if u.At.IsZero() {
		u.At = time.Now()
	}
	s.st.Uploads = append(s.st.Uploads, u)
	if keep > 0 {
		cut := time.Now().Add(-keep)
		s.st.Uploads = filter(s.st.Uploads, func(e model.Upload) bool { return e.At.After(cut) })
	}
	if n := len(s.st.Uploads); n > maxUploads {
		s.st.Uploads = s.st.Uploads[n-maxUploads:]
	}
	return s.save()
}

func filter[T any](in []T, keep func(T) bool) []T {
	out := in[:0]
	for _, v := range in {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}
