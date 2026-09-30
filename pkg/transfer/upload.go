package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

// ChunkUploader uploads one contiguous chunk and reports the next byte offset
// the server expects (== size when complete). Implementations wrap a Graph
// upload session; the interface is transport-agnostic for testability. A
// transient failure should be returned as a *Transient so Upload retries it.
type ChunkUploader interface {
	UploadChunk(ctx context.Context, offset int64, chunk []byte, size int64) (next int64, err error)
}

// Upload sends the size bytes of src through up in p.ChunkSize chunks,
// persisting the confirmed offset under key in store so an interrupted or
// restarted upload resumes mid-file. Each chunk is retried per p. On success
// the saved progress for key is cleared.
func Upload(ctx context.Context, p config.RetryPolicy, key string, src io.ReaderAt, size int64, up ChunkUploader, store ProgressStore) error {
	if p.ChunkSize <= 0 {
		return fmt.Errorf("transfer: chunk size must be > 0, got %d", p.ChunkSize)
	}
	offset, ok, err := store.Load(key)
	if err != nil {
		return err
	}
	if !ok || offset < 0 || offset > size {
		offset = 0
	}
	for offset < size {
		end := offset + p.ChunkSize
		if end > size {
			end = size
		}
		chunk := make([]byte, end-offset)
		n, rerr := src.ReadAt(chunk, offset)
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return rerr
		}
		if int64(n) != end-offset {
			return fmt.Errorf("transfer: short read at %d: got %d want %d", offset, n, end-offset)
		}
		start := offset
		var next int64
		if derr := Do(ctx, p, func(ctx context.Context, attempt int) error {
			nx, e := up.UploadChunk(ctx, start, chunk, size)
			if e != nil {
				return e
			}
			next = nx
			return nil
		}); derr != nil {
			return derr
		}
		if next <= offset {
			return fmt.Errorf("transfer: upload stalled at offset %d (server next=%d)", offset, next)
		}
		if next > size {
			next = size
		}
		offset = next
		if err := store.Save(key, offset); err != nil {
			return err
		}
	}
	return store.Clear(key)
}
