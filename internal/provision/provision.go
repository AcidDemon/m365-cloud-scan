// Package provision creates what the box needs in a customer tenant: one Entra
// app registration with application Sites.Selected, a certificate the box has
// just generated for itself, and a write grant on each SharePoint site the
// admin picked.
//
// Every step is get-or-create, so running it twice is safe. The private key
// never leaves this machine: only the public certificate is uploaded, which is
// the one real improvement over doing this on a laptop and carrying the result
// on a USB stick.
package provision

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

const graphBase = "https://graph.microsoft.com/v1.0"
const graphAppID = "00000003-0000-0000-c000-000000000000"

// AppName is the display name the box registers itself under.
const AppName = "M365CloudScan-Box"

// Result is what the box has to remember after onboarding.
type Result struct {
	TenantID string
	AppID    string
	CertPEM  string // cert plus private key; empty means the app already had one
	Sites    []string
}

// Provisioner talks to Graph with an admin's delegated token, carrying
// Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All and
// Sites.FullControl.All.
type Provisioner struct {
	Token string
	HTTP  *http.Client
	log   func(string, ...any)
}

func New(token string, logf func(string, ...any)) *Provisioner {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Provisioner{Token: token, HTTP: http.DefaultClient, log: logf}
}

// Onboard registers the app, attaches a freshly generated certificate and
// grants write on each site id in sites.
func (p *Provisioner) Onboard(ctx context.Context, sites []string, forceNewCert bool) (Result, error) {
	var r Result
	if len(sites) == 0 {
		return r, fmt.Errorf("pick at least one SharePoint site for the box to write to")
	}

	// Sites.Selected exists twice on the Graph service principal, as a delegated
	// scope and as an application role. The box runs unattended, so it needs the
	// role.
	gsp, err := p.get(ctx, "/servicePrincipals?$filter=appId+eq+'"+graphAppID+"'")
	if err != nil {
		return r, fmt.Errorf("graph service principal: %w", err)
	}
	list, _ := gsp["value"].([]any)
	if len(list) == 0 {
		return r, fmt.Errorf("the Microsoft Graph service principal is missing from this tenant")
	}
	graphSP, _ := list[0].(map[string]any)
	graphSPID := str(graphSP["id"])
	ssRole := findRole(graphSP["appRoles"], "Sites.Selected")
	if ssRole == "" {
		return r, fmt.Errorf("this tenant does not offer the Sites.Selected application role")
	}

	app, err := p.ensureApp(ctx, AppName, map[string]any{
		"displayName":    AppName,
		"signInAudience": "AzureADMyOrg",
		"requiredResourceAccess": []any{map[string]any{
			"resourceAppId":  graphAppID,
			"resourceAccess": []any{map[string]any{"id": ssRole, "type": "Role"}},
		}},
	})
	if err != nil {
		return r, fmt.Errorf("app registration: %w", err)
	}
	r.AppID = str(app["appId"])

	// Re-onboarding must not rotate a certificate out from under a box that is
	// already using it: that fails every token request with AADSTS700027. But a
	// certificate on the app is useless to a box that never got the private key,
	// so forceNewCert (the caller has no local key) replaces it instead.
	if forceNewCert || !hasValidCert(app) {
		certPEM, certDERb64, err := genCert(AppName)
		if err != nil {
			return r, fmt.Errorf("certificate: %w", err)
		}
		if err := p.setAppCert(ctx, str(app["id"]), certDERb64); err != nil {
			return r, fmt.Errorf("attach certificate: %w", err)
		}
		r.CertPEM = certPEM
	} else {
		p.log("the app already has a valid certificate, keeping it")
	}

	sp, err := p.ensureSP(ctx, r.AppID)
	if err != nil {
		return r, fmt.Errorf("service principal: %w", err)
	}
	if err := p.ensureAppRole(ctx, sp, graphSPID, ssRole); err != nil {
		return r, fmt.Errorf("admin consent: %w", err)
	}
	for _, site := range sites {
		if err := p.ensureSitePermission(ctx, site, r.AppID, AppName); err != nil {
			return r, fmt.Errorf("grant on site %s: %w", site, err)
		}
		r.Sites = append(r.Sites, site)
	}
	p.log("app %s ready on %d site(s)", r.AppID, len(r.Sites))
	return r, nil
}

// Sites lists the sites an admin may choose from. Sites.Selected grants are per
// site, so this is a multi-select rather than a single root site.
func (p *Provisioner) Sites(ctx context.Context, query string) ([]map[string]any, error) {
	if query == "" {
		query = "*"
	}
	out, err := p.get(ctx, "/sites?search="+url.QueryEscape(query))
	if err != nil {
		return nil, err
	}
	raw, _ := out["value"].([]any)
	sites := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		sites = append(sites, map[string]any{
			"id": str(m["id"]), "name": str(m["displayName"]), "webUrl": str(m["webUrl"]),
		})
	}
	return sites, nil
}

func (p *Provisioner) ensureApp(ctx context.Context, displayName string, spec map[string]any) (map[string]any, error) {
	qs := url.Values{"$filter": {"displayName eq '" + displayName + "'"}}.Encode()
	if existing, _ := p.get(ctx, "/applications?"+qs); existing != nil {
		if v, ok := existing["value"].([]any); ok && len(v) > 0 {
			if m, ok := v[0].(map[string]any); ok {
				return m, nil // ponytail: reuse as-is; fresh-tenant path is the create branch
			}
		}
	}
	return p.post(ctx, "/applications", spec)
}

// ensureSP returns the service principal for appID, creating it (with retry for
// AAD app→SP replication lag) if absent.
func (p *Provisioner) ensureSP(ctx context.Context, appID string) (string, error) {
	if existing, _ := p.get(ctx, "/servicePrincipals(appId='"+appID+"')"); existing != nil {
		if id := str(existing["id"]); id != "" {
			return id, nil
		}
	}
	var lastErr error
	for i := 0; i < 5; i++ {
		sp, err := p.post(ctx, "/servicePrincipals", map[string]any{"appId": appID})
		if err == nil {
			return str(sp["id"]), nil
		}
		lastErr = err
		time.Sleep(8 * time.Second)
	}
	return "", lastErr
}

// hasValidCert reports whether the app already carries a non-expired signing cert,
// so re-onboarding can keep it instead of rotating a live fetcher's credential.
func hasValidCert(app map[string]any) bool {
	kcs, _ := app["keyCredentials"].([]any)
	for _, kc := range kcs {
		m, _ := kc.(map[string]any)
		if end, ok := m["endDateTime"].(string); ok {
			if t, err := time.Parse(time.RFC3339, end); err == nil && t.After(time.Now()) {
				return true
			}
		}
	}
	return false
}

// setAppCert PATCHes the app's keyCredentials to exactly the given cert.
func (p *Provisioner) setAppCert(ctx context.Context, appObjID, certDERb64 string) error {
	body := map[string]any{"keyCredentials": []any{map[string]any{
		"type": "AsymmetricX509Cert", "usage": "Verify", "key": certDERb64,
	}}}
	_, err := p.do(ctx, http.MethodPatch, "/applications/"+appObjID, body)
	return err
}

func (p *Provisioner) ensureAppRole(ctx context.Context, spID, graphSPID, roleID string) error {
	body := map[string]any{"principalId": spID, "resourceId": graphSPID, "appRoleId": roleID}
	_, err := p.post(ctx, "/servicePrincipals/"+spID+"/appRoleAssignments", body)
	return tolerateExists(err)
}

func (p *Provisioner) ensureSitePermission(ctx context.Context, siteID, appID, name string) error {
	body := map[string]any{
		"roles":               []string{"write"},
		"grantedToIdentities": []any{map[string]any{"application": map[string]any{"id": appID, "displayName": name}}},
	}
	_, err := p.post(ctx, fmt.Sprintf("/sites/%s/permissions", siteID), body)
	return tolerateExists(err)
}

// --- HTTP helpers ---

func (p *Provisioner) get(ctx context.Context, path string) (map[string]any, error) {
	return p.do(ctx, http.MethodGet, path, nil)
}
func (p *Provisioner) post(ctx context.Context, path string, body any) (map[string]any, error) {
	return p.do(ctx, http.MethodPost, path, body)
}

func (p *Provisioner) do(ctx context.Context, method, path string, body any) (map[string]any, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, graphBase+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, &apiError{status: resp.StatusCode, body: string(raw)}
	}
	var out map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out, nil
}

type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("graph HTTP %d: %s", e.status, e.body) }

// tolerateExists swallows "already exists / duplicate" errors so re-runs are idempotent.
func tolerateExists(err error) error {
	if err == nil {
		return nil
	}
	var ae *apiError
	if bytes.Contains([]byte(err.Error()), []byte("exist")) || bytes.Contains([]byte(err.Error()), []byte("Permission entity already")) {
		return nil
	}
	if b, ok := err.(*apiError); ok && (b.status == http.StatusConflict) {
		return nil
	}
	_ = ae
	return err
}

func findRole(list any, value string) string {
	arr, ok := list.([]any)
	if !ok {
		return ""
	}
	for _, e := range arr {
		if m, ok := e.(map[string]any); ok && m["value"] == value {
			return str(m["id"])
		}
	}
	return ""
}

func str(v any) string { s, _ := v.(string); return s }

// genCert makes a self-signed 2048-bit cert, returning (PEM cert+key bundle,
// base64 DER of the cert for the Graph keyCredential).
func genCert(cn string) (pemBundle, derB64 string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return buf.String(), base64.StdEncoding.EncodeToString(der), nil
}
