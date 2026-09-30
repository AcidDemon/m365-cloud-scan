package graph

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

// APIError is a non-2xx Microsoft Graph response.
type APIError struct {
	Status int
	Code   string // Graph error.code, if present
	Msg    string // Graph error.message, if present
	Body   string // raw body (truncated), for diagnostics
}

func (e *APIError) Error() string {
	return fmt.Sprintf("graph: HTTP %d %s: %s", e.Status, e.Code, e.Msg)
}

// classify maps an HTTP status into nil (2xx), a retryable *transfer.Transient,
// or a terminal *APIError. 429/503 are throttles (honor Retry-After); 500/502/504
// are transient (backoff); other non-2xx are terminal.
func classify(status int, retryAfter string, apiErr *APIError) error {
	if status >= 200 && status < 300 {
		return nil
	}
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return &transfer.Transient{Err: apiErr, RetryAfter: parseRetryAfter(retryAfter), Throttle: true}
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout:
		return &transfer.Transient{Err: apiErr}
	default:
		return apiErr
	}
}

// parseRetryAfter parses a Retry-After header. Only the integer delta-seconds
// form is honored; an HTTP-date (or anything unparseable) yields 0 so the retry
// engine falls back to its own backoff.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}
