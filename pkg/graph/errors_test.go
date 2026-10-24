package graph

import (
	"errors"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

func TestClassify2xxIsNil(t *testing.T) {
	if err := classify(204, "", nil); err != nil {
		t.Fatalf("2xx should be nil, got %v", err)
	}
}

func TestClassifyThrottle(t *testing.T) {
	for _, status := range []int{429, 503} {
		err := classify(status, "2", &APIError{Status: status})
		var tr *transfer.Transient
		if !errors.As(err, &tr) {
			t.Fatalf("status %d: want *transfer.Transient, got %T", status, err)
		}
		if tr.RetryAfter != 2*time.Second {
			t.Errorf("status %d: RetryAfter=%v want 2s", status, tr.RetryAfter)
		}
	}
}

func TestClassifyServerErrorsAreTransient(t *testing.T) {
	for _, status := range []int{500, 502, 504} {
		err := classify(status, "", &APIError{Status: status})
		var tr *transfer.Transient
		if !errors.As(err, &tr) {
			t.Fatalf("status %d: want *transfer.Transient, got %T", status, err)
		}
	}
}

func TestClassifyClientErrorIsTerminal(t *testing.T) {
	err := classify(404, "", &APIError{Status: 404, Code: "itemNotFound"})
	var tr *transfer.Transient
	if errors.As(err, &tr) {
		t.Fatalf("404 should be terminal, got Transient")
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("want *APIError status 404, got %T %v", err, err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if parseRetryAfter("5") != 5*time.Second {
		t.Error("'5' should be 5s")
	}
	if parseRetryAfter("") != 0 {
		t.Error("empty should be 0")
	}
	if parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT") != 0 {
		t.Error("HTTP-date should yield 0 (fall back to backoff)")
	}
}
