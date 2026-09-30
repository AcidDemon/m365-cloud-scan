package scanui

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/auth"
	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/deviceauth"
	"github.com/AcidDemon/m365-cloud-scan/internal/provision"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

// onboarding is the state of the connect wizard. There is at most one at a
// time: two admins racing to register the same app would only confuse each
// other, and the flow takes a minute at most.
type onboarding struct {
	mu       sync.Mutex
	code     deviceauth.Code
	started  time.Time
	token    deviceauth.Token
	sites    []map[string]any
	failed   string
	finished bool
}

// stage reports where the wizard is, which is all the page needs to decide what
// to draw.
func (o *onboarding) stage() string {
	switch {
	case o.failed != "":
		return "failed"
	case o.finished:
		return "done"
	case o.token.AccessToken != "":
		return "sites"
	case o.code.UserCode != "":
		return "waiting"
	}
	return "idle"
}

func (s *Server) handleTenantStart(rw http.ResponseWriter, r *http.Request) {
	code, err := deviceauth.New(nil).Start(r.Context())
	if err != nil {
		fail(rw, err)
		return
	}
	// Reset the fields, never the struct: assigning over it would replace the
	// mutex that is being held, and unlocking a zeroed mutex is fatal.
	s.onb.mu.Lock()
	s.onb.code, s.onb.started = code, time.Now()
	s.onb.token, s.onb.sites = deviceauth.Token{}, nil
	s.onb.failed, s.onb.finished = "", false
	s.onb.mu.Unlock()
	writeJSON(rw, map[string]any{
		"stage": "waiting", "userCode": code.UserCode,
		"verificationUrl": code.VerificationURI, "expiresIn": code.ExpiresIn,
	})
}

// handleTenantPoll is called every few seconds by the page while the admin is
// signing in. It returns the sites to choose from as soon as the token lands.
func (s *Server) handleTenantPoll(rw http.ResponseWriter, r *http.Request) {
	s.onb.mu.Lock()
	defer s.onb.mu.Unlock()
	if s.onb.code.UserCode == "" {
		writeJSON(rw, map[string]any{"stage": "idle"})
		return
	}
	if s.onb.token.AccessToken == "" {
		tok, err := deviceauth.New(nil).Poll(r.Context(), s.onb.code.DeviceCode)
		switch {
		case errors.Is(err, deviceauth.ErrPending):
			writeJSON(rw, map[string]any{"stage": "waiting", "userCode": s.onb.code.UserCode,
				"verificationUrl": s.onb.code.VerificationURI})
			return
		case err != nil:
			s.onb.failed = err.Error()
			writeJSON(rw, map[string]any{"stage": "failed", "error": err.Error()})
			return
		}
		s.onb.token = tok
		sites, err := provision.New(tok.AccessToken, nil).Sites(r.Context(), "")
		if err != nil {
			s.onb.failed = err.Error()
			writeJSON(rw, map[string]any{"stage": "failed", "error": err.Error()})
			return
		}
		s.onb.sites = sites
	}
	granted := []string{}
	for _, si := range s.grantedSites() {
		granted = append(granted, si.ID)
	}
	writeJSON(rw, map[string]any{"stage": s.onb.stage(), "sites": s.onb.sites,
		"granted": granted, "tenantId": s.onb.token.TenantID, "signedInAs": s.onb.token.UPN})
}

// handleTenantFinish registers the app, attaches a certificate this box just
// generated, and starts using it. No restart: the Graph client is shared through
// a reference the engine reads on every pass.
func (s *Server) handleTenantFinish(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Sites []string `json:"sites"`
	}
	if !decode(rw, r, &b) {
		return
	}
	s.onb.mu.Lock()
	defer s.onb.mu.Unlock()
	if s.onb.token.AccessToken == "" {
		failText(rw, "sign in first")
		return
	}
	if len(b.Sites) == 0 {
		failText(rw, "pick at least one site the box may write to")
		return
	}

	certPath := s.cfg.CertPath
	if certPath == "" {
		certPath = filepath.Join(filepath.Dir(s.cfg.TenantFile), "scan.pem")
	}
	// A certificate on the Entra app is useless to this box unless the box holds
	// the matching private key. If scan.pem is missing (a fresh box, or an
	// earlier attempt that never persisted the key), force a fresh certificate
	// instead of proceeding to read a file that will never exist.
	_, statErr := os.Stat(certPath)
	haveLocalKey := statErr == nil

	ctx := context.WithoutCancel(r.Context())
	res, err := provision.New(s.onb.token.AccessToken, func(f string, a ...any) { s.log.Info("onboarding: "+f, a...) }).
		Onboard(ctx, b.Sites, !haveLocalKey)
	if err != nil {
		s.onb.failed = err.Error()
		fail(rw, err)
		return
	}
	if res.CertPEM == "" && !haveLocalKey {
		failText(rw, "the app already has a certificate but this box has no private key for it. Remove the certificate from the app registration in Entra and connect again")
		return
	}
	// Keep the names the wizard already showed: an app-only Sites.Selected token
	// cannot look them up again.
	byID := map[string]map[string]any{}
	for _, si := range s.onb.sites {
		byID[str(si["id"])] = si
	}
	// Adding a site later runs the same flow, so merge rather than replace: a
	// second visit that granted one site would otherwise revoke the rest from
	// the box's point of view, and every destination on them would break.
	granted := s.grantedSites()
	for _, id := range res.Sites {
		found := false
		for i, ex := range granted {
			if ex.ID == id {
				if ex.Name == "" {
					granted[i].Name, granted[i].URL = str(byID[id]["name"]), str(byID[id]["webUrl"])
				}
				found = true
				break
			}
		}
		if !found {
			granted = append(granted, config.TenantSite{
				ID: id, Name: str(byID[id]["name"]), URL: str(byID[id]["webUrl"]),
			})
		}
	}
	t := config.Tenant{
		TenantID: s.onb.token.TenantID, ClientID: res.AppID,
		CertPath: certPath, Sites: granted, UPN: s.onb.token.UPN,
	}
	if err := config.SaveTenant(s.cfg.TenantFile, t, res.CertPEM); err != nil {
		fail(rw, err)
		return
	}

	s.cfg.TenantID, s.cfg.ClientID, s.cfg.CertPath = t.TenantID, t.ClientID, t.CertPath
	ts, err := auth.NewCertTokenSource(t.TenantID, t.ClientID, t.CertPath)
	if err != nil {
		fail(rw, err)
		return
	}
	s.gc.Set(graph.NewClient(&http.Client{Timeout: 5 * time.Minute}, s.cfg.GraphBaseURL, ts))
	s.setTenant(t)
	s.onb.finished = true
	s.noteGraph(nil)
	s.log.Info("tenant connected", "tenant", t.TenantID, "app", t.ClientID, "sites", len(t.Sites))
	writeJSON(rw, map[string]any{"stage": "done", "appId": t.ClientID, "sites": len(t.Sites)})
}

// handleTenantTest proves the box can actually reach Graph with what it was
// given, which is the question "is it connected" really asks.
func (s *Server) handleTenantTest(rw http.ResponseWriter, r *http.Request) {
	gc, err := s.graphClient()
	if err != nil {
		failText(rw, err.Error())
		return
	}
	// Prove the box can use what it was granted. Searching would fail with 401
	// even on a perfectly healthy connection, because Sites.Selected does not
	// allow enumeration.
	granted := s.grantedSites()
	if len(granted) == 0 {
		failText(rw, "no site has been granted to this box yet")
		return
	}
	drives, err := gc.Drives(r.Context(), granted[0].ID)
	s.noteGraph(err)
	if err != nil {
		failText(rw, err.Error())
		return
	}
	writeJSON(rw, map[string]any{"ok": true, "site": granted[0].Name, "libraries": len(drives)})
}

func str(v any) string { x, _ := v.(string); return x }
