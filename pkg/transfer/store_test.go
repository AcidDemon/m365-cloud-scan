package transfer

import (
	"os"
	"testing"
)

func TestFileProgressStoreRoundTrip(t *testing.T) {
	s, err := NewFileProgressStore(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, ok, err := s.Load("job-A"); err != nil || ok {
		t.Fatalf("expected miss, got ok=%v err=%v", ok, err)
	}
	if err := s.Save("job-A", 4096); err != nil {
		t.Fatalf("save: %v", err)
	}
	off, ok, err := s.Load("job-A")
	if err != nil || !ok || off != 4096 {
		t.Fatalf("load: off=%d ok=%v err=%v", off, ok, err)
	}
	if err := s.Clear("job-A"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if _, ok, _ := s.Load("job-A"); ok {
		t.Fatalf("expected miss after clear")
	}
	if err := s.Clear("job-A"); err != nil {
		t.Fatalf("clear-missing: %v", err)
	}
}

func TestFileProgressStoreCorruptValueIsTreatedAsMiss(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewFileProgressStore(dir)
	bad := s.path("bad")
	if err := writeFileForTest(bad, "not-a-number"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A corrupt offset is treated as "no progress" (resume from 0), not an error.
	off, ok, err := s.Load("bad")
	if err != nil {
		t.Fatalf("corrupt value should not error, got %v", err)
	}
	if ok || off != 0 {
		t.Fatalf("corrupt value should be a miss, got off=%d ok=%v", off, ok)
	}
}

func TestFileProgressStoreKeysAreIsolated(t *testing.T) {
	s, _ := NewFileProgressStore(t.TempDir())
	_ = s.Save("a", 10)
	_ = s.Save("b", 20)
	if off, _, _ := s.Load("a"); off != 10 {
		t.Fatalf("a=%d want 10", off)
	}
	if off, _, _ := s.Load("b"); off != 20 {
		t.Fatalf("b=%d want 20", off)
	}
}

func writeFileForTest(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// --- shared test helpers (used by upload_test.go and download_test.go) ---

// memStore is an in-memory ProgressStore for tests.
type memStore struct{ m map[string]int64 }

func newMemStore() *memStore { return &memStore{m: map[string]int64{}} }

func (s *memStore) Load(key string) (int64, bool, error) {
	v, ok := s.m[key]
	return v, ok, nil
}
func (s *memStore) Save(key string, offset int64) error { s.m[key] = offset; return nil }
func (s *memStore) Clear(key string) error              { delete(s.m, key); return nil }

// bufferWriterAt is a growable io.WriterAt over an in-memory buffer.
type bufferWriterAt struct{ buf []byte }

func (w *bufferWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if need := off + int64(len(p)); int64(len(w.buf)) < need {
		grown := make([]byte, need)
		copy(grown, w.buf)
		w.buf = grown
	}
	copy(w.buf[off:], p)
	return len(p), nil
}
