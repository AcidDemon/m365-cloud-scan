package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

// RangeReader reads up to length bytes of a remote object starting at offset and
// reports the object's total size. length<=0 means "to end". The caller closes
// the returned reader. A transient failure should be a *Transient.
type RangeReader interface {
	ReadRange(ctx context.Context, offset, length int64) (r io.ReadCloser, size int64, err error)
}

// Download writes the remote object to dst in p.ChunkSize ranges, resuming from
// the offset persisted under key in store, each range retried per p. It returns
// the object's total size. On success the saved progress for key is cleared.
// Integrity (hash) verification of the finished object is the caller's job.
func Download(ctx context.Context, p config.RetryPolicy, key string, dst io.WriterAt, rr RangeReader, store ProgressStore) (int64, error) {
	if p.ChunkSize <= 0 {
		return 0, fmt.Errorf("transfer: chunk size must be > 0, got %d", p.ChunkSize)
	}
	offset, ok, err := store.Load(key)
	if err != nil {
		return 0, err
	}
	if !ok || offset < 0 {
		offset = 0
	}
	var total int64 = -1
	for {
		start := offset
		var size, wrote int64
		if derr := Do(ctx, p, func(ctx context.Context, attempt int) error {
			r, sz, e := rr.ReadRange(ctx, start, p.ChunkSize)
			if e != nil {
				return e
			}
			if r == nil {
				return fmt.Errorf("transfer: RangeReader returned a nil reader at offset %d", start)
			}
			defer r.Close()
			size = sz
			if start >= sz {
				wrote = 0
				return nil
			}
			want := p.ChunkSize
			if start+want > sz {
				want = sz - start
			}
			buf := make([]byte, want)
			m, rerr := io.ReadFull(r, buf)
			if rerr != nil && !errors.Is(rerr, io.EOF) && !errors.Is(rerr, io.ErrUnexpectedEOF) {
				return &Transient{Err: rerr}
			}
			if m > 0 {
				if _, werr := dst.WriteAt(buf[:m], start); werr != nil {
					return werr
				}
			}
			wrote = int64(m)
			return nil
		}); derr != nil {
			return total, derr
		}
		total = size
		if total >= 0 && offset >= total {
			break
		}
		if wrote == 0 {
			return total, fmt.Errorf("transfer: download stalled at offset %d (size %d)", offset, total)
		}
		offset += wrote
		if err := store.Save(key, offset); err != nil {
			return total, err
		}
		if total >= 0 && offset >= total {
			break
		}
	}
	if err := store.Clear(key); err != nil {
		return total, err
	}
	return total, nil
}
