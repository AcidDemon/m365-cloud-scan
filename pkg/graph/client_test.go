package graph

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

type staticToken string

func (s staticToken) Token(ctx context.Context) (string, error) { return string(s), nil }

func TestClientInjectsBearerAndReturnsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization=%q", got)
		}
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("tok-123"))
	resp, err := c.do(context.Background(), http.MethodGet, "/ping", nil, nil)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != `{"ok":true}` {
		t.Fatalf("body=%q", b)
	}
}

func TestClientDoThrottleOn429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(429)
		_, _ = io.WriteString(w, `{"error":{"code":"tooManyRequests","message":"slow down"}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("x"))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	var tr *transfer.Transient
	if !errors.As(err, &tr) || tr.RetryAfter != 3*time.Second {
		t.Fatalf("want throttle Transient w/ 3s, got %T %v", err, err)
	}
}

func TestClientDoTerminalOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":{"code":"itemNotFound","message":"nope"}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("x"))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "itemNotFound" {
		t.Fatalf("want APIError 404 itemNotFound, got %T %v", err, err)
	}
}

type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func TestClientDoTransportErrorIsTransient(t *testing.T) {
	c := NewClient(&http.Client{Transport: errRoundTripper{}}, "https://example.invalid", staticToken("x"))
	_, err := c.do(context.Background(), http.MethodGet, "/x", nil, nil)
	var tr *transfer.Transient
	if !errors.As(err, &tr) {
		t.Fatalf("transport error should be Transient, got %T %v", err, err)
	}
}
