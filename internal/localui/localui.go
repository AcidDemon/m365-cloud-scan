// Package localui runs a loopback single-page UI server for the desktop tools
// (the onboarding wizard and the client settings GUI). It injects a per-run token
// into the page and enforces two defenses on the local server:
//   - reject any request whose Host isn't our loopback listener (defeats DNS
//     rebinding), and
//   - require the per-run token on every /api/* route (defeats cross-origin
//     access to state/credential routes: the attacker's page can't read ours).
//
// Pure Go; cross-compiles to Windows/macOS/Linux with no cgo.
package localui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pkg/browser"
)

// ephemeralAddr is the default listen address: an OS-assigned loopback port.
const ephemeralAddr = "127.0.0.1:0"

// Server serves a token-injected single-page UI plus JSON /api handlers.
type Server struct {
	token string
	index []byte
	mux   *http.ServeMux
	addr  string // loopback listen address; ephemeralAddr unless pinned
	idle  time.Duration
	quit  chan struct{}
	once  sync.Once
	seen  chan struct{} // request ticks for the idle watchdog; nil unless idle > 0
}

// New builds a Server that serves indexHTML at "/", with the placeholder
// "__CSRF__" replaced by a fresh per-run token.
func New(indexHTML []byte) *Server {
	s := &Server{token: randToken(), index: indexHTML, mux: http.NewServeMux(), addr: ephemeralAddr,
		quit: make(chan struct{})}
	s.mux.HandleFunc("/", s.serveIndex)
	return s
}

// SetIdleTimeout makes Run return once no request has arrived for d. Without it
// the server runs until Quit or a fatal error. That is fine for a long-lived
// settings window, but a one-shot wizard would outlive the browser tab that
// closed it.
func (s *Server) SetIdleTimeout(d time.Duration) {
	s.idle = d
	s.seen = make(chan struct{}, 1)
}

// Quit stops the server; Run then returns nil. Safe to call more than once and
// from a request handler (Run shuts down after in-flight requests finish, so
// the response to the caller still lands).
func (s *Server) Quit() { s.once.Do(func() { close(s.quit) }) }

// SetAddr pins the loopback listen address to a fixed port. That makes the app
// single-instance: if the port is already bound, Run treats it as "another
// instance already owns the UI", opens the browser to it, and returns without
// starting a duplicate server. (The running instance serves its own
// token-injected page, so the re-opened browser is fully functional.)
func (s *Server) SetAddr(addr string) { s.addr = addr }

// Handle registers a JSON API handler (path must start with /api/).
func (s *Server) Handle(pattern string, h http.HandlerFunc) { s.mux.HandleFunc(pattern, h) }

func (s *Server) serveIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = rw.Write(bytes.ReplaceAll(s.index, []byte("__CSRF__"), []byte(s.token)))
}

// Run listens on loopback, optionally opens the browser, and serves until error.
func (s *Server) Run(openBrowser bool) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		// A pinned port that won't bind means another instance already owns the
		// UI. Bring its window up instead of starting a second server, then exit.
		if s.addr != ephemeralAddr {
			if openBrowser {
				_ = browser.OpenURL("http://" + s.addr + "/")
			}
			return nil
		}
		return err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	allowed := map[string]bool{ln.Addr().String(): true, "localhost:" + port: true}
	addr := "http://" + ln.Addr().String() + "/"
	fmt.Println("UI running at", addr, "(a browser window should open)")
	if openBrowser {
		_ = browser.OpenURL(addr)
	}

	srv := &http.Server{Handler: s.tick(guard(s.mux, allowed, s.token))}
	if s.idle > 0 {
		go s.watchIdle()
	}
	go func() {
		<-s.quit
		// Graceful: in-flight requests finish, so the /api/quit caller still gets
		// its response before the process goes away.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// tick notifies the idle watchdog that a request arrived. No-op unless
// SetIdleTimeout was called.
func (s *Server) tick(next http.Handler) http.Handler {
	if s.seen == nil {
		return next
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		select {
		case s.seen <- struct{}{}:
		default: // watchdog already has a pending tick; it only needs to know "recently"
		}
		next.ServeHTTP(rw, r)
	})
}

// watchIdle quits the server once no request has arrived for the idle window.
func (s *Server) watchIdle() {
	t := time.NewTimer(s.idle)
	defer t.Stop()
	for {
		select {
		case <-s.seen:
			if !t.Stop() {
				<-t.C
			}
			t.Reset(s.idle)
		case <-t.C:
			fmt.Printf("no activity for %s, exiting\n", s.idle)
			s.Quit()
			return
		case <-s.quit:
			return
		}
	}
}

func guard(next http.Handler, allowedHosts map[string]bool, token string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !allowedHosts[r.Host] {
			http.Error(rw, "bad host", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			t := r.Header.Get("X-Session")
			if t == "" {
				t = r.URL.Query().Get("t")
			}
			if subtle.ConstantTimeCompare([]byte(t), []byte(token)) != 1 {
				http.Error(rw, "forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(rw, r)
	})
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// JSON is a tiny helper for handlers to write a JSON response.
func JSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}
