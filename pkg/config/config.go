package config

import (
	"errors"
	"fmt"
	"time"
)

// GraphUploadChunkMultiple is Graph's required upload-session chunk granularity
// (320 KiB). Chunk sizes must be a positive multiple of this.
const GraphUploadChunkMultiple = 320 * 1024 // 327680

// RetryPolicy governs both resumable transfer legs.
type RetryPolicy struct {
	MaxAttempts int           `json:"maxAttempts"`
	BaseDelay   time.Duration `json:"baseDelay"`
	MaxDelay    time.Duration `json:"maxDelay"`
	Jitter      float64       `json:"jitter"` // fraction in [0,1]
	ChunkSize   int64         `json:"chunkSizeBytes"`
}

// DefaultRetryPolicy is the shipped default (5 attempts, 5 MiB chunks).
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   500 * time.Millisecond,
		MaxDelay:    30 * time.Second,
		Jitter:      0.2,
		ChunkSize:   5 * 1024 * 1024, // 5 MiB = 16 * 320 KiB
	}
}

// Validate rejects unusable policies.
func (p RetryPolicy) Validate() error {
	if p.MaxAttempts < 1 {
		return fmt.Errorf("maxAttempts must be >= 1, got %d", p.MaxAttempts)
	}
	if p.BaseDelay <= 0 {
		return errors.New("baseDelay must be > 0")
	}
	if p.MaxDelay < p.BaseDelay {
		return errors.New("maxDelay must be >= baseDelay")
	}
	if p.Jitter < 0 || p.Jitter > 1 {
		return fmt.Errorf("jitter must be in [0,1], got %v", p.Jitter)
	}
	if p.ChunkSize <= 0 || p.ChunkSize%GraphUploadChunkMultiple != 0 {
		return fmt.Errorf("chunkSizeBytes must be a positive multiple of %d, got %d",
			GraphUploadChunkMultiple, p.ChunkSize)
	}
	return nil
}
