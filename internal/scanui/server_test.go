package scanui

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/graphref"
	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	pkgconfig "github.com/AcidDemon/m365-cloud-scan/pkg/config"
)

const testPassword = "hunter2-hunter2"

// fakeRunner stands in for the OS: it records every command and pretends to
// keep a Samba registry, so the share handlers can be driven end to end.
type fakeRunner struct {
	mu         sync.Mutex
	calls      []string
	stdins     []string
	shares     map[string]bool
	failPrefix string // commands starting with this fail
}

func newRunner() *fakeRunner { return &fakeRunner{shares: map[string]bool{}} }

func (f *fakeRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	f.stdins = append(f.stdins, string(stdin))
	f.mu.Unlock()

	if f.failPrefix != "" && strings.HasPrefix(cmd, f.failPrefix) {
		return nil, []byte("boom"), errors.New("exit status 1")
	}
	switch {
	case strings.HasPrefix(cmd, "net conf showshare"):
		if !f.shares[args[2]] {
			return nil, nil, errors.New("no such share")
		}
	case strings.HasPrefix(cmd, "net conf addshare"):
		f.shares[args[2]] = true
	case strings.HasPrefix(cmd, "net conf delshare"):
		delete(f.shares, args[2])
	case strings.HasPrefix(cmd, "systemctl is-active"):
		return []byte("active\n"), nil, nil
	case strings.HasPrefix(cmd, "smbd --version"):
		return []byte("Version 4.21.4\n"), nil, nil
	case strings.HasPrefix(cmd, "testparm"):
		return []byte("SMB2\n"), nil, nil
	}
	return nil, nil, nil
}

func (f *fakeRunner) gotStdin(want string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, in := range f.stdins {
		if in == want {
			return true
		}
	}
	return false
}

func (f *fakeRunner) ran(prefix string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type fakeEngine struct {
	retried []string
	testErr error
}

func (f *fakeEngine) Retry(id string) error { f.retried = append(f.retried, id); return nil }
func (f *fakeEngine) TestRoute(ctx context.Context, id string) error {
	return f.testErr
}

func newTestServer(t *testing.T) (*Server, *fakeRunner, *fakeEngine) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		TenantID:       "contoso.onmicrosoft.com",
		ClientID:       "app-0001",
		StatePath:      filepath.Join(dir, "state.json"),
		ShareRoot:      filepath.Join(dir, "srv"),
		QuarantineDir:  filepath.Join(dir, "quarantine"),
		UIPasswordFile: filepath.Join(dir, "ui-password"),
		NetBIOSName:    "m365scan",
		RetryPolicy: pkgconfig.RetryPolicy{
			MaxAttempts: 8,
			BaseDelay:   2 * time.Second,
			MaxDelay:    5 * time.Minute,
			Jitter:      0.2,
		},
	}
	run := newRunner()
	eng := &fakeEngine{}
	srv := NewServer(cfg, NewAuth(string(hash), []byte("session-secret"), time.Hour),
		st, smb.New(run, cfg.ShareRoot), eng, graphref.New(nil),
		[]byte(`<html data-csrf="__CSRF__"></html>`), slog.New(slog.DiscardHandler))
	return srv, run, eng
}

// session logs in and returns the token the page would echo in X-CSRF.
func session(t *testing.T, s *Server) string {
	t.Helper()
	rw := call(s, http.MethodPost, "/api/login", `{"password":"`+testPassword+`"}`, "", "")
	if rw.Code != http.StatusOK {
		t.Fatalf("login: HTTP %d", rw.Code)
	}
	var out struct{ CSRF string }
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.CSRF == "" {
		t.Fatal("login returned no csrf token")
	}
	return out.CSRF
}

// call drives the mux directly. tok is the session cookie, csrf the header, so
// a test can send one without the other.
func call(s *Server, method, path, body, tok, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if tok != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	}
	if csrf != "" {
		r.Header.Set("X-CSRF", csrf)
	}
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, r)
	return rw
}

// post is the ordinary authenticated mutation.
func post(t *testing.T, s *Server, path, body, tok string) map[string]any {
	t.Helper()
	rw := call(s, http.MethodPost, path, body, tok, tok)
	if rw.Code != http.StatusOK {
		t.Fatalf("POST %s: HTTP %d: %s", path, rw.Code, rw.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatalf("POST %s: %v: %s", path, err, rw.Body.String())
	}
	return out
}

func TestLoginRateLimit(t *testing.T) {
	s, _, _ := newTestServer(t)
	for i := range 5 {
		if rw := call(s, http.MethodPost, "/api/login", `{"password":"nope"}`, "", ""); rw.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got HTTP %d, want 401", i, rw.Code)
		}
	}
	if rw := call(s, http.MethodPost, "/api/login", `{"password":"nope"}`, "", ""); rw.Code != http.StatusTooManyRequests {
		t.Errorf("6th attempt: got HTTP %d, want 429", rw.Code)
	}
	// The lockout is per source, and the right password must not slip past it.
	if rw := call(s, http.MethodPost, "/api/login", `{"password":"`+testPassword+`"}`, "", ""); rw.Code != http.StatusTooManyRequests {
		t.Errorf("locked out but correct password: got HTTP %d, want 429", rw.Code)
	}
}

func TestSessionAndCSRF(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)

	tests := []struct {
		name       string
		method     string
		path       string
		tok, csrf  string
		wantStatus int
	}{
		{"no session", http.MethodGet, "/api/state", "", "", http.StatusUnauthorized},
		{"bad session", http.MethodGet, "/api/state", tok + "x", "", http.StatusUnauthorized},
		{"read with session", http.MethodGet, "/api/state", tok, "", http.StatusOK},
		{"post without csrf", http.MethodPost, "/api/shares/setenabled", tok, "", http.StatusForbidden},
		{"post with wrong csrf", http.MethodPost, "/api/shares/setenabled", tok, "other", http.StatusForbidden},
		{"post with csrf", http.MethodPost, "/api/shares/setenabled", tok, tok, http.StatusOK},
		// The method is part of the route, so a GET never reaches a mutation
		// handler and cannot bypass the CSRF check. It falls through to the
		// page route, which only serves "/".
		{"login is not a get", http.MethodGet, "/api/login", "", "", http.StatusNotFound},
		{"mutation is not a get", http.MethodGet, "/api/shares/add", tok, "", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := call(s, tc.method, tc.path, `{"id":"nope"}`, tc.tok, tc.csrf)
			if rw.Code != tc.wantStatus {
				t.Errorf("got HTTP %d, want %d: %s", rw.Code, tc.wantStatus, rw.Body.String())
			}
		})
	}
}

func TestServeIndexInjectsCSRF(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, r)

	if got := rw.Body.String(); !strings.Contains(got, tok) || strings.Contains(got, "__CSRF__") {
		t.Errorf("index did not get the session token: %s", got)
	}
	if got := rw.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestChangePassword(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)

	// A domain failure, not an auth one. 401 is what the page reads as "your
	// session is gone", so it used to drop the admin at the sign-in screen
	// rather than say the password was wrong.
	rw := call(s, http.MethodPost, "/api/password", `{"current":"wrong","new":"longenough1"}`, tok, tok)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "current password is wrong") {
		t.Fatalf("wrong current password: HTTP %d: %s", rw.Code, rw.Body.String())
	}
	if got := post(t, s, "/api/password", `{"current":"`+testPassword+`","new":"short"}`, tok)["error"]; got == nil {
		t.Error("a short password should be refused")
	}
	post(t, s, "/api/password", `{"current":"`+testPassword+`","new":"a-longer-password"}`, tok)
	if !s.auth.CheckPassword("a-longer-password") {
		t.Error("the new password was not applied")
	}
	if _, err := os.ReadFile(s.cfg.UIPasswordFile); err != nil {
		t.Errorf("the new hash was not persisted: %v", err)
	}
}

// reset-password writes a hash to disk while the daemon runs. Before the server
// adopted it, the command reported success and the box kept refusing the new
// password until someone restarted it.
func TestPasswordFileIsAdoptedWithoutARestart(t *testing.T) {
	s, _, _ := newTestServer(t)
	if !s.auth.CheckPassword(testPassword) {
		t.Fatal("the seeded password should work to begin with")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("ZweitesPasswort456"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfg.UIPasswordFile, hash, 0o600); err != nil {
		t.Fatal(err)
	}
	s.adoptPasswordFile()
	if !s.auth.CheckPassword("ZweitesPasswort456") {
		t.Error("the password written to the file should work without a restart")
	}
	if s.auth.CheckPassword(testPassword) {
		t.Error("the previous password should stop working")
	}
}
