package transfer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

// bytesRangeReader serves ranges of an in-memory object and can simulate
// failures and short reads. It records the first offset it was asked to serve.
type bytesRangeReader struct {
	data         []byte
	failuresLeft int
	maxPerRead   int // if >0, return at most this many bytes per ReadRange
	firstOffset  int64
	sawFirst     bool
}

func (r *bytesRangeReader) ReadRange(ctx context.Context, offset, length int64) (io.ReadCloser, int64, error) {
	if r.failuresLeft > 0 {
		r.failuresLeft--
		return nil, 0, &Transient{Err: errors.New("flaky download")}
	}
	if !r.sawFirst {
		r.firstOffset = offset
		r.sawFirst = true
	}
	size := int64(len(r.data))
	if offset >= size {
		return io.NopCloser(bytes.NewReader(nil)), size, nil
	}
	end := offset + length
	if length <= 0 || end > size {
		end = size
	}
	chunk := r.data[offset:end]
	if r.maxPerRead > 0 && len(chunk) > r.maxPerRead {
		chunk = chunk[:r.maxPerRead]
	}
	return io.NopCloser(bytes.NewReader(chunk)), size, nil
}

// zeroProgressReader reports a non-zero size but always returns an empty body,
// forcing the download stall path.
type zeroProgressReader struct{ size int64 }

func (z zeroProgressReader) ReadRange(ctx context.Context, offset, length int64) (io.ReadCloser, int64, error) {
	return io.NopCloser(bytes.NewReader(nil)), z.size, nil
}

func TestDownloadHappyPath(t *testing.T) {
	data := []byte("abcdefghij")
	dst := &bufferWriterAt{}
	store := newMemStore()
	size, err := Download(context.Background(), fastPolicy(4), "job", dst, &bytesRangeReader{data: data}, store)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if size != 10 {
		t.Fatalf("size=%d want 10", size)
	}
	if string(dst.buf) != string(data) {
		t.Fatalf("got %q want %q", dst.buf, data)
	}
	if _, ok, _ := store.Load("job"); ok {
		t.Fatalf("progress should be cleared on success")
	}
}

func TestDownloadResumesFromStore(t *testing.T) {
	data := []byte("abcdefghij")
	dst := &bufferWriterAt{}
	store := newMemStore()
	_ = store.Save("job", 4)
	rr := &bytesRangeReader{data: data}
	size, err := Download(context.Background(), fastPolicy(4), "job", dst, rr, store)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if size != 10 {
		t.Fatalf("size=%d want 10", size)
	}
	if rr.firstOffset != 4 {
		t.Fatalf("resume served first range at %d want 4", rr.firstOffset)
	}
	if string(dst.buf[4:]) != string(data[4:]) {
		t.Fatalf("tail got %q want %q", dst.buf[4:], data[4:])
	}
	// Head must be untouched (bufferWriterAt zero-initializes); a resumed
	// download must not re-fetch or rewrite bytes [0,4).
	for i := 0; i < 4; i++ {
		if dst.buf[i] != 0 {
			t.Fatalf("head byte %d was written (0x%02x); resume should skip it", i, dst.buf[i])
		}
	}
}

func TestDownloadRetriesTransient(t *testing.T) {
	data := []byte("abcdefghij")
	dst := &bufferWriterAt{}
	rr := &bytesRangeReader{data: data, failuresLeft: 2}
	if _, err := Download(context.Background(), fastPolicy(4), "job", dst, rr, newMemStore()); err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(dst.buf) != string(data) {
		t.Fatalf("got %q want %q", dst.buf, data)
	}
}

func TestDownloadShortRange(t *testing.T) {
	data := []byte("abcdefghij")
	dst := &bufferWriterAt{}
	rr := &bytesRangeReader{data: data, maxPerRead: 2}
	size, err := Download(context.Background(), fastPolicy(4), "job", dst, rr, newMemStore())
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if size != 10 || string(dst.buf) != string(data) {
		t.Fatalf("size=%d buf=%q", size, dst.buf)
	}
}

func TestDownloadStallReturnsError(t *testing.T) {
	dst := &bufferWriterAt{}
	_, err := Download(context.Background(), fastPolicy(4), "job", dst, zeroProgressReader{size: 10}, newMemStore())
	if err == nil {
		t.Fatalf("expected stall error")
	}
}
