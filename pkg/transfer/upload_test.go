package transfer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

// recordingUploader accumulates received bytes and can simulate failures and
// partial acceptance. It records the offset of the first chunk it accepted.
type recordingUploader struct {
	buf          []byte
	failuresLeft int
	acceptLen    func(chunkLen int) int // nil => accept whole chunk
	firstOffset  int64
	sawFirst     bool
}

func (u *recordingUploader) UploadChunk(ctx context.Context, offset int64, chunk []byte, size int64) (int64, error) {
	if u.failuresLeft > 0 {
		u.failuresLeft--
		return 0, &Transient{Err: errors.New("flaky upload")}
	}
	if !u.sawFirst {
		u.firstOffset = offset
		u.sawFirst = true
	}
	accept := len(chunk)
	if u.acceptLen != nil {
		accept = u.acceptLen(len(chunk))
	}
	if need := offset + int64(accept); int64(len(u.buf)) < need {
		grown := make([]byte, need)
		copy(grown, u.buf)
		u.buf = grown
	}
	copy(u.buf[offset:], chunk[:accept])
	return offset + int64(accept), nil
}

func fastPolicy(chunk int64) config.RetryPolicy {
	return config.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond, Jitter: 0, ChunkSize: chunk}
}

func bytesReaderAt(b []byte) *bytesAt { return &bytesAt{b} }

type bytesAt struct{ b []byte }

func (r *bytesAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, errors.New("EOF")
	}
	n := copy(p, r.b[off:])
	return n, nil
}

func TestUploadHappyPath(t *testing.T) {
	data := []byte("0123456789")
	up := &recordingUploader{}
	store := newMemStore()
	if err := Upload(context.Background(), fastPolicy(4), "job", bytesReaderAt(data), int64(len(data)), up, store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if string(up.buf) != string(data) {
		t.Fatalf("got %q want %q", up.buf, data)
	}
	if _, ok, _ := store.Load("job"); ok {
		t.Fatalf("progress should be cleared on success")
	}
}

func TestUploadResumesFromStore(t *testing.T) {
	data := []byte("0123456789")
	up := &recordingUploader{}
	store := newMemStore()
	_ = store.Save("job", 4)
	if err := Upload(context.Background(), fastPolicy(4), "job", bytesReaderAt(data), int64(len(data)), up, store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if up.firstOffset != 4 {
		t.Fatalf("resume started at %d want 4", up.firstOffset)
	}
	if string(up.buf[4:]) != string(data[4:]) {
		t.Fatalf("tail got %q want %q", up.buf[4:], data[4:])
	}
}

func TestUploadRetriesTransientChunk(t *testing.T) {
	data := []byte("0123456789")
	up := &recordingUploader{failuresLeft: 2}
	if err := Upload(context.Background(), fastPolicy(4), "job", bytesReaderAt(data), int64(len(data)), up, newMemStore()); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if string(up.buf) != string(data) {
		t.Fatalf("got %q want %q", up.buf, data)
	}
}

func TestUploadPartialAcceptResumes(t *testing.T) {
	data := []byte("0123456789")
	up := &recordingUploader{acceptLen: func(n int) int { return (n + 1) / 2 }}
	if err := Upload(context.Background(), fastPolicy(4), "job", bytesReaderAt(data), int64(len(data)), up, newMemStore()); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if string(up.buf) != string(data) {
		t.Fatalf("got %q want %q", up.buf, data)
	}
}

func TestUploadStallReturnsError(t *testing.T) {
	data := []byte("0123456789")
	up := &recordingUploader{acceptLen: func(n int) int { return 0 }}
	err := Upload(context.Background(), fastPolicy(4), "job", bytesReaderAt(data), int64(len(data)), up, newMemStore())
	if err == nil {
		t.Fatalf("expected stall error")
	}
}
