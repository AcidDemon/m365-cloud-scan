// Package scanui serves the box's admin interface: one embedded page plus a
// JSON API over HTTPS, behind a password and a per-session CSRF token.
//
// Domain failures come back as {"error":"..."} with HTTP 200. The page shows
// the sentence to the admin. Only authentication uses status codes, because
// there the browser, not the page, has to react.
package scanui

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/graphref"
	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

const (
	sessionCookie = "m365scan_session"
	minPassword   = 8
)

// Uploader is the slice of the upload engine the UI drives. It is an interface
// only so the handler tests can run without a Graph endpoint.
type Uploader interface {
	Retry(itemID string) error
	TestRoute(ctx context.Context, routeID string) error
}

// Server holds everything the handlers need. Every dependency may be nil except
// the store and the auth: a box with no Graph credentials or no Samba still has
// to serve the page that says so.
type Server struct {
	cfg    config.Config
	auth   *Auth
	st     *store.Store
	sm     *smb.Manager
	eng    Uploader
	gc     *graphref.Ref
	onb    *onboarding
	rescan func()
	index  []byte
	log    *slog.Logger
	now    func() time.Time

	settingsPath string
	firewallPath string
	nftDir       string

	// Dedicated locks, deliberately not mu: both are held across shell-outs that
	// take hundreds of milliseconds, and mu is a short-hold state lock the
	// request path takes constantly.
	//
	// fwMu makes one network-access change atomic from render through validate,
	// rename, reload and the file write. Without it two saves share one temp
	// path and the kernel ends up holding one list while firewall.json holds
	// the other, and the wizard fires a full save on every keystroke-sized edit.
	fwMu sync.Mutex
	// shareMu covers handleShareAdd from its uniqueness check through useradd,
	// smbpasswd and the store write. Check-then-act across those shell-outs let
	// a double press pass the check twice and roll the second failure back over
	// the share the first one had just made.
	shareMu sync.Mutex

	mu       sync.Mutex
	settings Settings
	firewall []FWEntry
	// A firewall change that is applied but not yet written to disk. While
	// these are set the previous list comes back on its own, and a crash in
	// the meantime restores it too, because the file still holds fwPrev.
	fwTimer *time.Timer
	fwPrev  []FWEntry
	fwUntil time.Time
	// Bumped on every arm. A revert timer carries the generation it was created
	// with, so one that fires just as a newer change arms cannot take that
	// newer list down with the old one.
	fwGen    uint64
	certExp  time.Time
	tenant   config.Tenant
	pwHash   string
	graphErr error     // last Graph failure, for the tenant panel
	smbSeen  time.Time // when smbCache was filled
	smbCache smbInfo
}

// NewServer wires the handlers. index is the single-page HTML; "__CSRF__" in it
// is replaced per response with the caller's session token.
func NewServer(cfg config.Config, auth *Auth, st *store.Store, sm *smb.Manager, eng Uploader, gc *graphref.Ref, index []byte, log *slog.Logger) *Server {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Server{
		cfg: cfg, auth: auth, st: st, sm: sm, eng: eng, gc: gc, onb: &onboarding{},
		index: index, log: log, now: time.Now,
		settingsPath: settingsPath(cfg.StatePath),
		firewallPath: firewallPath(cfg.StatePath),
		nftDir:       "/etc/nftables.d",
	}
	s.settings = loadSettings(s.settingsPath, defaultSettings(cfg), log)
	fw, err := loadFirewall(s.firewallPath)
	if err != nil {
		// Serving an empty list is survivable and visible; what must not happen
		// is reapplyFirewall writing that emptiness into the kernel, which it
		// guards against by re-reading.
		log.Error("the allowed networks file is unreadable, the page will show none", "path", s.firewallPath, "err", err)
	}
	s.firewall = fw
	// Read once: a replaced certificate is a restart anyway, and /api/state is
	// polled often enough that re-reading the PEM per request is waste.
	s.pwHash = cfg.UIPasswordHash
	s.certExp = certExpiry(cfg.CertPath)
	if t, err := config.LoadTenant(cfg.TenantFile); err == nil {
		s.tenant = t
	}
	return s
}

// Handler returns the routed mux. The method is part of every pattern, so a GET
// can never reach a mutation handler and skip the CSRF check with it.
// SetRescan wires the watcher's Kick, so a share created here is watched at
// once rather than at the next rescan tick.
func (s *Server) SetRescan(fn func()) { s.rescan = fn }

// kickWatcher is safe to call when nothing was wired, which is what the tests do.
func (s *Server) kickWatcher() {
	if s.rescan != nil {
		s.rescan()
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serveIndex)
	mux.HandleFunc("POST /api/login", s.handleLogin)

	post := func(path string, h http.HandlerFunc) { mux.HandleFunc("POST "+path, s.requireSession(h)) }
	get := func(path string, h http.HandlerFunc) { mux.HandleFunc("GET "+path, s.requireSession(h)) }

	post("/api/logout", s.handleLogout)
	post("/api/password", s.handlePassword)
	post("/api/tenant/connect/start", s.handleTenantStart)
	post("/api/tenant/connect/poll", s.handleTenantPoll)
	post("/api/tenant/connect/finish", s.handleTenantFinish)
	post("/api/tenant/test", s.handleTenantTest)

	get("/api/state", s.handleState)

	post("/api/shares/add", s.handleShareAdd)
	post("/api/shares/update", s.handleShareUpdate)
	post("/api/shares/remove", s.handleShareRemove)
	post("/api/shares/rotatepw", s.handleShareRotatePW)
	post("/api/shares/setenabled", s.handleShareSetEnabled)

	post("/api/destinations/save", s.handleDestinationSave)
	post("/api/destinations/remove", s.handleDestinationRemove)

	post("/api/routes/save", s.handleRouteSave)
	post("/api/routes/remove", s.handleRouteRemove)
	post("/api/routes/setenabled", s.handleRouteSetEnabled)
	post("/api/routes/test", s.handleRouteTest)

	get("/api/sp/sites", s.handleSPSites)
	get("/api/sp/drives", s.handleSPDrives)
	get("/api/sp/children", s.handleSPChildren)
	post("/api/sp/mkdir", s.handleSPMkdir)

	post("/api/queue/retry", s.handleQueueRetry)
	post("/api/queue/remove", s.handleQueueRemove)

	get("/api/settings", s.handleGetSettings)
	post("/api/settings", s.handleSetSettings)

	get("/api/firewall", s.handleGetFirewall)
	post("/api/firewall", s.handleSetFirewall)
	post("/api/firewall/confirm", s.handleConfirmFirewall)
	return mux
}

// Serve loads or creates the UI certificate and serves TLS on the bind address.
func (s *Server) Serve() error {
	// Before the certificate, deliberately. This is the only thing that puts an
	// unconfirmed ruleset back to the list on disk after a crash, and it depends
	// on nothing but what NewServer already loaded — behind the cert load, a box
	// whose certificate is unreadable would serve nothing AND keep rules nobody
	// ever confirmed, with no way in to correct them.
	s.reapplyFirewall()
	cert, err := LoadOrCreateCert(s.cfg.UICertPath, s.cfg.UIKeyPath, s.certHosts()...)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.UIBindAddr)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:      s.cfg.UIBindAddr,
		Handler:   s.Handler(),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	s.log.Info("admin UI listening", "addr", s.cfg.UIBindAddr, "certFor", strings.Join(s.certHosts(), " "))
	return srv.ServeTLS(ln, "", "")
}

// certHost is the name the admin types. A wildcard bind address says nothing
// about that, so the box name is the better subject.
// certHosts lists everything the admin UI might be reached as. The box has no
// DNS record and its address comes from DHCP, so the certificate has to cover
// the NetBIOS name, the machine name, loopback for a forwarded port, and every
// address the box currently holds.
func (s *Server) certHosts() []string {
	// The .local name is what mDNS hands out, so the certificate has to carry it
	// or the browser warns about exactly the name we told people to use.
	hosts := []string{s.cfg.NetBIOSName, strings.ToLower(s.cfg.NetBIOSName) + ".local"}
	if h, _, err := net.SplitHostPort(s.cfg.UIBindAddr); err == nil && h != "" && h != "0.0.0.0" && h != "::" {
		hosts = append(hosts, h)
	}
	if hn, err := os.Hostname(); err == nil {
		hosts = append(hosts, hn)
	}
	hosts = append(hosts, "127.0.0.1", "::1")
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return hosts
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		hosts = append(hosts, ipn.IP.String())
	}
	return hosts
}

func (s *Server) serveIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page carries a per-session CSRF token, so a cached copy would hand a
	// logged-out token to the next admin.
	rw.Header().Set("Cache-Control", "no-store")
	_, _ = rw.Write(bytes.ReplaceAll(s.index, []byte("__CSRF__"), []byte(sessionValue(r))))
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		tok := sessionValue(r)
		if !s.auth.ValidToken(tok, s.now()) {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF")), []byte(tok)) != 1 {
				http.Error(rw, "bad csrf", http.StatusForbidden)
				return
			}
		}
		next(rw, r)
	}
}

// adoptPasswordFile picks up a password set by `m365-scan reset-password` while
// the daemon was running. Without it the command reports success, writes the
// file, and the box keeps rejecting the new password until someone restarts it,
// which is exactly the situation reset-password exists to get out of.
func (s *Server) adoptPasswordFile() {
	if s.cfg.UIPasswordFile == "" {
		return
	}
	raw, err := os.ReadFile(s.cfg.UIPasswordFile)
	if err != nil {
		return
	}
	hash := strings.TrimSpace(string(raw))
	if hash == "" {
		return
	}
	s.mu.Lock()
	changed := hash != s.pwHash
	if changed {
		s.pwHash = hash
	}
	s.mu.Unlock()
	if changed {
		s.auth.SetPasswordHash(hash)
		s.log.Info("adopted the admin password from the password file", "path", s.cfg.UIPasswordFile)
	}
}

func (s *Server) handleLogin(rw http.ResponseWriter, r *http.Request) {
	// Cheap: one small read per sign-in attempt, and only sign-ins.
	s.adoptPasswordFile()
	ip := clientIP(r)
	if !s.auth.Allow(ip, s.now()) {
		http.Error(rw, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	var b struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&b)
	if !s.auth.CheckPassword(b.Password) {
		s.auth.RecordFailure(ip, s.now())
		s.log.Warn("failed admin login", "ip", ip)
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.auth.Reset(ip)
	tok := s.auth.IssueToken(s.now())
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	// The cookie is HttpOnly, so the page cannot read the token it has to echo
	// in X-CSRF; it gets it here and on every reload through __CSRF__.
	writeJSON(rw, map[string]any{"ok": true, "csrf": tok})
}

func (s *Server) handleLogout(rw http.ResponseWriter, r *http.Request) {
	http.SetCookie(rw, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(rw, map[string]any{"ok": true})
}

func (s *Server) handlePassword(rw http.ResponseWriter, r *http.Request) {
	var b struct{ Current, New string }
	if !decode(rw, r, &b) {
		return
	}
	// Not 401: the page treats that as "your session died" and drops you back to
	// the sign-in screen, so mistyping the current password logged the admin out
	// instead of telling them. It is a domain failure like every other one here.
	if !s.auth.CheckPassword(b.Current) {
		failText(rw, "the current password is wrong")
		return
	}
	if len(b.New) < minPassword {
		failText(rw, "the new password must be at least 8 characters")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(b.New), 12)
	if err != nil {
		fail(rw, err)
		return
	}
	s.auth.SetPasswordHash(string(hash))
	// Persist, or the next restart brings back the hash from config.json.
	if s.cfg.UIPasswordFile != "" {
		if err := os.WriteFile(s.cfg.UIPasswordFile, hash, 0o600); err != nil {
			failText(rw, "the password was changed but could not be saved: "+err.Error())
			return
		}
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// setTenant records what onboarding produced, so the tenant panel and the
// destination picker stop depending on a Graph call that Sites.Selected forbids.
func (s *Server) setTenant(t config.Tenant) {
	s.mu.Lock()
	s.tenant = t
	s.certExp = certExpiry(t.CertPath)
	s.graphErr = nil
	s.mu.Unlock()
}

// grantedSites is every site the box may write to, which under Sites.Selected
// is also every site it can see.
func (s *Server) grantedSites() []config.TenantSite {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]config.TenantSite(nil), s.tenant.Sites...)
}

// certExpiry reads NotAfter out of the Graph app certificate. Anything
// unreadable yields the zero time, which the UI renders as unknown.
func certExpiry(path string) time.Time {
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	for block, rest := pem.Decode(raw); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			return c.NotAfter
		}
	}
	return time.Time{}
}

// graphClient reports the Graph client, or the reason there is none.
func (s *Server) graphClient() (*graph.Client, error) {
	if s.gc == nil || s.gc.Get() == nil {
		return nil, errors.New("this box is not connected to Microsoft 365 yet")
	}
	return s.gc.Get(), nil
}

// noteGraph remembers the outcome of the last Graph call so the tenant panel
// can say "connected" without a probe on every poll of /api/state.
func (s *Server) noteGraph(err error) {
	s.mu.Lock()
	s.graphErr = err
	s.mu.Unlock()
}

func sessionValue(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(rw http.ResponseWriter, v any) {
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(v)
}

// decode reads a JSON body, answering the caller itself when it is malformed.
func decode(rw http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		failText(rw, "the request could not be read: "+err.Error())
		return false
	}
	return true
}

func fail(rw http.ResponseWriter, err error) { failText(rw, err.Error()) }

func failText(rw http.ResponseWriter, msg string) {
	writeJSON(rw, map[string]any{"error": msg})
}
