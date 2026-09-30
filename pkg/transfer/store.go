package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProgressStore persists per-transfer byte offsets so an interrupted or
// restarted transfer resumes from where it stopped. A given key is driven by a
// single goroutine at a time.
type ProgressStore interface {
	// Load returns the saved offset for key; ok is false if none is saved.
	Load(key string) (offset int64, ok bool, err error)
	// Save records offset (the last fully-confirmed byte position) for key.
	Save(key string, offset int64) error
	// Clear removes any saved offset for key. Clearing a missing key is a no-op.
	Clear(key string) error
}

// FileProgressStore is a ProgressStore backed by one small file per key under
// Dir. Keys are hashed to fixed, filesystem-safe names. Writes are atomic
// (temp file + rename) so a saved offset is never torn; they are NOT fsynced,
// so a power loss may revert to the previous offset. That is safe, because
// resuming from a behind offset only re-sends already-transferred bytes. A
// corrupt offset file is treated as "no progress" on Load.
type FileProgressStore struct{ dir string }

// NewFileProgressStore creates the directory (0700) if needed and returns a store.
func NewFileProgressStore(dir string) (*FileProgressStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileProgressStore{dir: dir}, nil
}

func (s *FileProgressStore) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".offset")
}

func (s *FileProgressStore) Load(key string) (int64, bool, error) {
	p := s.path(key)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	n, perr := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if perr != nil {
		// A corrupt offset must not permanently wedge a transfer: discard it and
		// report "no progress" so the caller resumes from 0 (re-sending is safe).
		_ = os.Remove(p)
		return 0, false, nil
	}
	return n, true, nil
}

func (s *FileProgressStore) Save(key string, offset int64) error {
	p := s.path(key)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(offset, 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (s *FileProgressStore) Clear(key string) error {
	err := os.Remove(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Compile-time assurance the durable store satisfies the interface.
var _ ProgressStore = (*FileProgressStore)(nil)
