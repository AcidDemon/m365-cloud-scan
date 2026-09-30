package config

import (
	"testing"
	"time"
)

func TestDefaultRetryPolicyIsValid(t *testing.T) {
	if err := DefaultRetryPolicy().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
}

func TestRetryPolicyValidateRejectsBadCases(t *testing.T) {
	base := DefaultRetryPolicy()
	cases := []struct {
		name   string
		mutate func(p *RetryPolicy)
	}{
		{"MaxAttempts zero", func(p *RetryPolicy) { p.MaxAttempts = 0 }},
		{"MaxAttempts negative", func(p *RetryPolicy) { p.MaxAttempts = -1 }},
		{"BaseDelay zero", func(p *RetryPolicy) { p.BaseDelay = 0 }},
		{"BaseDelay negative", func(p *RetryPolicy) { p.BaseDelay = -time.Second }},
		{"MaxDelay below BaseDelay", func(p *RetryPolicy) { p.MaxDelay = p.BaseDelay / 2 }},
		{"Jitter above one", func(p *RetryPolicy) { p.Jitter = 1.5 }},
		{"Jitter negative", func(p *RetryPolicy) { p.Jitter = -0.1 }},
		{"ChunkSize zero", func(p *RetryPolicy) { p.ChunkSize = 0 }},
		{"ChunkSize negative", func(p *RetryPolicy) { p.ChunkSize = -GraphUploadChunkMultiple }},
		{"ChunkSize not a 320KiB multiple", func(p *RetryPolicy) { p.ChunkSize = 100_000 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base
			c.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("expected %s to be rejected, got nil", c.name)
			}
		})
	}
}

func TestRetryPolicyValidateAcceptsBoundaries(t *testing.T) {
	base := DefaultRetryPolicy()
	cases := []struct {
		name   string
		mutate func(p *RetryPolicy)
	}{
		{"Jitter zero", func(p *RetryPolicy) { p.Jitter = 0 }},
		{"Jitter one", func(p *RetryPolicy) { p.Jitter = 1.0 }},
		{"MaxDelay equals BaseDelay", func(p *RetryPolicy) { p.MaxDelay = p.BaseDelay }},
		{"MaxAttempts one", func(p *RetryPolicy) { p.MaxAttempts = 1 }},
		{"ChunkSize exactly one multiple", func(p *RetryPolicy) { p.ChunkSize = GraphUploadChunkMultiple }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base
			c.mutate(&p)
			if err := p.Validate(); err != nil {
				t.Errorf("expected %s to be valid, got %v", c.name, err)
			}
		})
	}
}
