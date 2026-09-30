package localui

import (
	"net"
	"net/http"
	"testing"
	"time"
)

// A pinned port that's already bound means another instance owns the UI: Run
// must return without erroring or blocking (single-instance) rather than start
// a second server.
func TestRunSingleInstanceOnBusyPort(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	s := New([]byte("x"))
	s.SetAddr(occupied.Addr().String()) // pin to the already-bound port
	done := make(chan error, 1)
	go func() { done <- s.Run(false) }() // openBrowser=false: no browser in tests
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run on a busy pinned port should be a single-instance no-op, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run blocked on a busy pinned port; expected single-instance early return")
	}
}

// runOnFreePort starts a server on an OS-assigned port and returns its base URL
// plus the channel Run's result lands on.
func runOnFreePort(t *testing.T, s *Server) (string, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // hand the port straight back; Run rebinds it
	s.SetAddr(addr)
	done := make(chan error, 1)
	go func() { done <- s.Run(false) }()
	for i := 0; i < 100; i++ { // wait for the listener to come up
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return "http://" + addr, done
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server never started listening")
	return "", done
}

// The wizard's Finish button calls Quit from inside a handler: the response must
// still reach the browser, and Run must then return so the process can exit.
func TestQuitFromHandlerReturnsRun(t *testing.T) {
	s := New([]byte("x"))
	s.Handle("/api/quit", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		s.Quit()
	})
	base, done := runOnFreePort(t, s)

	resp, err := http.Get(base + "/api/quit?t=" + s.token)
	if err != nil {
		t.Fatalf("quit request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("quit status = %d, want 200", resp.StatusCode)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after Quit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Quit")
	}
	s.Quit() // idempotent: a second call must not panic on a closed channel
}

// Nobody clicked Finish and the tab is gone: the idle watchdog ends the process.
func TestIdleTimeoutReturnsRun(t *testing.T) {
	s := New([]byte("x"))
	s.SetIdleTimeout(300 * time.Millisecond)
	base, done := runOnFreePort(t, s)

	// Traffic keeps it alive: after this fetch the window restarts.
	if resp, err := http.Get(base + "/"); err == nil {
		resp.Body.Close()
	}
	select {
	case <-done:
		t.Fatal("Run returned while requests were still arriving")
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run after idle timeout: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the idle window elapsed")
	}
}
