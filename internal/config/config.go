// Package config resolves the scan daemon's configuration: the JSON file on
// disk, then defaults for everything that has a sensible one, then M365SCAN_*
// environment overrides for the values a deployment injects.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	pkgconfig "github.com/AcidDemon/m365-cloud-scan/pkg/config"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

// Config is the resolved runtime configuration of the daemon.
type Config struct {
	TenantID string
	ClientID string
	CertPath string // PEM bundle (cert+key) for app-only Graph auth

	StatePath     string
	ShareRoot     string
	QuarantineDir string
	ProgressDir   string

	UIBindAddr      string
	UICertPath      string
	UIKeyPath       string
	UIPasswordHash  string
	UIPasswordFile  string // where a password change is persisted; see LoadConfig
	TenantFile      string // where onboarding through the admin UI is persisted
	UISessionSecret string

	NetBIOSName    string
	RetryPolicy    pkgconfig.RetryPolicy
	RescanInterval time.Duration
	GraphBaseURL   string
}

// fileConfig is the on-disk shape. Durations are strings ("5m") so the file
// stays hand-editable.
type fileConfig struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	CertPath string `json:"certPath"`

	StatePath     string `json:"statePath"`
	ShareRoot     string `json:"shareRoot"`
	QuarantineDir string `json:"quarantineDir"`
	ProgressDir   string `json:"progressDir"`

	UI struct {
		BindAddr      string `json:"bindAddr"`
		CertPath      string `json:"certPath"`
		KeyPath       string `json:"keyPath"`
		PasswordHash  string `json:"passwordHash"`
		PasswordFile  string `json:"passwordFile"`
		SessionSecret string `json:"sessionSecret"`
	} `json:"ui"`

	NetBIOSName    string `json:"netbiosName"`
	RescanInterval string `json:"rescanInterval"`
	GraphBaseURL   string `json:"graphBaseUrl"`

	Retry struct {
		MaxAttempts int     `json:"maxAttempts"`
		BaseDelay   string  `json:"baseDelay"`
		MaxDelay    string  `json:"maxDelay"`
		Jitter      float64 `json:"jitter"`
		ChunkSize   int64   `json:"chunkSizeBytes"`
	} `json:"retry"`
}

// Defaults for everything the box installs at a fixed path.
const (
	defaultCertPath       = "/etc/m365-scan/scan.pem"
	defaultStatePath      = "/var/lib/m365-scan/state.json"
	defaultShareRoot      = "/srv/m365-scan"
	defaultQuarantineDir  = "/var/lib/m365-scan/quarantine"
	defaultProgressDir    = "/var/lib/m365-scan/progress"
	defaultUIBindAddr     = "0.0.0.0:8444"
	defaultUICertPath     = "/etc/m365-scan/ui-cert.pem"
	defaultUIKeyPath      = "/etc/m365-scan/ui-key.pem"
	defaultUIPasswordFile = "/var/lib/m365-scan/ui-password"
	defaultNetBIOSName    = "m365scan"
	defaultRescanInterval = 5 * time.Minute
	// minSecretBytes is 128 bits of session-signing key. The file carries it as
	// hex, because hex is what serve() decodes: `openssl rand -hex 32`.
	minSecretBytes = 16
)

// netbiosName is what the SMB name resolution layer accepts: 15 characters, no
// dots, no separators.
var netbiosName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}$`)

// ValidNetBIOSName reports whether s can be a NetBIOS name. The admin UI and
// the Samba manager check the same rule, so it lives in one place.
func ValidNetBIOSName(s string) bool { return netbiosName.MatchString(s) }

// LoadConfig reads and resolves the config. It does not call Validate; the
// caller does, so every problem can be reported in one go at startup.
//
// A password changed through the web UI is written to UIPasswordFile and wins
// over the hash in the JSON file, which config management rewrites.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("scan: read config %q: %w", path, err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return Config{}, fmt.Errorf("scan: parse config %q: %w", path, err)
	}

	c := Config{
		TenantID:        fc.TenantID,
		ClientID:        fc.ClientID,
		CertPath:        firstNonEmpty(fc.CertPath, defaultCertPath),
		StatePath:       firstNonEmpty(fc.StatePath, defaultStatePath),
		ShareRoot:       firstNonEmpty(fc.ShareRoot, defaultShareRoot),
		QuarantineDir:   firstNonEmpty(fc.QuarantineDir, defaultQuarantineDir),
		ProgressDir:     firstNonEmpty(fc.ProgressDir, defaultProgressDir),
		UIBindAddr:      firstNonEmpty(fc.UI.BindAddr, defaultUIBindAddr),
		UICertPath:      firstNonEmpty(fc.UI.CertPath, defaultUICertPath),
		UIKeyPath:       firstNonEmpty(fc.UI.KeyPath, defaultUIKeyPath),
		UIPasswordHash:  fc.UI.PasswordHash,
		UIPasswordFile:  firstNonEmpty(fc.UI.PasswordFile, defaultUIPasswordFile),
		UISessionSecret: fc.UI.SessionSecret,
		NetBIOSName:     firstNonEmpty(fc.NetBIOSName, defaultNetBIOSName),
		GraphBaseURL:    firstNonEmpty(fc.GraphBaseURL, graph.DefaultBaseURL),
	}
	if c.RescanInterval, err = durationOr(fc.RescanInterval, defaultRescanInterval); err != nil {
		return Config{}, fmt.Errorf("scan: rescanInterval: %w", err)
	}
	if c.RetryPolicy, err = retryPolicy(fc); err != nil {
		return Config{}, err
	}

	applyEnvOverrides(&c)
	if hash, err := os.ReadFile(c.UIPasswordFile); err == nil && len(strings.TrimSpace(string(hash))) > 0 {
		c.UIPasswordHash = strings.TrimSpace(string(hash))
	}
	c.TenantFile = firstNonEmpty(c.TenantFile, filepath.Join(filepath.Dir(c.StatePath), "tenant.json"))
	if t, err := LoadTenant(c.TenantFile); err == nil {
		c.TenantID, c.ClientID, c.CertPath = t.TenantID, t.ClientID, t.CertPath
	}
	return c, nil
}

// Tenant is what onboarding through the admin UI leaves behind. It lives beside
// the state rather than in config.json, which Ansible owns and rewrites.
type Tenant struct {
	TenantID string `json:"tenantId"`
	ClientID string `json:"clientId"`
	CertPath string `json:"certPath"`
	// Sites carries names as well as ids. An app-only Sites.Selected token
	// cannot enumerate sites, so this list is the only thing the destination
	// picker has to offer.
	Sites []TenantSite `json:"sites,omitempty"`
	UPN   string       `json:"onboardedBy,omitempty"`
}

type TenantSite struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"webUrl,omitempty"`
}

// Domain is the part of the signed-in account an admin recognises. The tenant
// id is a GUID, which tells nobody anything.
func (t Tenant) Domain() string {
	if i := strings.LastIndex(t.UPN, "@"); i >= 0 {
		return t.UPN[i+1:]
	}
	return ""
}

func LoadTenant(path string) (Tenant, error) {
	var t Tenant
	b, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return t, fmt.Errorf("parse %s: %w", path, err)
	}
	if t.TenantID == "" || t.ClientID == "" || t.CertPath == "" {
		return Tenant{}, fmt.Errorf("%s is incomplete", path)
	}
	return t, nil
}

// SaveTenant writes the overlay and the certificate together, both 0600: the
// bundle holds the private key the box authenticates with.
func SaveTenant(path string, t Tenant, certPEM string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if certPEM != "" {
		if err := os.WriteFile(t.CertPath, []byte(certPEM), 0o600); err != nil {
			return err
		}
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// defaultRetryPolicy is faster off the mark than the shipped default and gives
// up later: someone waits at the MFP for the scan to appear, and a short Graph
// outage must not quarantine good scans. The delays double from 2s to 256s.
func defaultRetryPolicy() pkgconfig.RetryPolicy {
	p := pkgconfig.DefaultRetryPolicy()
	p.MaxAttempts = 8
	p.BaseDelay = 2 * time.Second
	p.MaxDelay = 5 * time.Minute
	p.Jitter = 0.2
	return p
}

// retryPolicy starts from the default and overlays whatever the file set, so a
// partial retry block is valid.
func retryPolicy(fc fileConfig) (pkgconfig.RetryPolicy, error) {
	p := defaultRetryPolicy()
	if fc.Retry.MaxAttempts != 0 {
		p.MaxAttempts = fc.Retry.MaxAttempts
	}
	if fc.Retry.Jitter != 0 {
		p.Jitter = fc.Retry.Jitter
	}
	if fc.Retry.ChunkSize != 0 {
		p.ChunkSize = fc.Retry.ChunkSize
	}
	var err error
	if fc.Retry.BaseDelay != "" {
		if p.BaseDelay, err = time.ParseDuration(fc.Retry.BaseDelay); err != nil {
			return pkgconfig.RetryPolicy{}, fmt.Errorf("scan: retry.baseDelay: %w", err)
		}
	}
	if fc.Retry.MaxDelay != "" {
		if p.MaxDelay, err = time.ParseDuration(fc.Retry.MaxDelay); err != nil {
			return pkgconfig.RetryPolicy{}, fmt.Errorf("scan: retry.maxDelay: %w", err)
		}
	}
	return p, nil
}

// applyEnvOverrides lets a deployment inject identifiers and secrets without
// baking them into the JSON file. An unset variable leaves the file value.
func applyEnvOverrides(c *Config) {
	for env, set := range map[string]func(string){
		"M365SCAN_TENANT_ID":         func(v string) { c.TenantID = v },
		"M365SCAN_CLIENT_ID":         func(v string) { c.ClientID = v },
		"M365SCAN_CERT_PATH":         func(v string) { c.CertPath = v },
		"M365SCAN_STATE_PATH":        func(v string) { c.StatePath = v },
		"M365SCAN_SHARE_ROOT":        func(v string) { c.ShareRoot = v },
		"M365SCAN_QUARANTINE_DIR":    func(v string) { c.QuarantineDir = v },
		"M365SCAN_PROGRESS_DIR":      func(v string) { c.ProgressDir = v },
		"M365SCAN_UI_BIND_ADDR":      func(v string) { c.UIBindAddr = v },
		"M365SCAN_UI_CERT_PATH":      func(v string) { c.UICertPath = v },
		"M365SCAN_UI_KEY_PATH":       func(v string) { c.UIKeyPath = v },
		"M365SCAN_UI_PASSWORD_HASH":  func(v string) { c.UIPasswordHash = v },
		"M365SCAN_UI_PASSWORD_FILE":  func(v string) { c.UIPasswordFile = v },
		"M365SCAN_UI_SESSION_SECRET": func(v string) { c.UISessionSecret = v },
		"M365SCAN_NETBIOS_NAME":      func(v string) { c.NetBIOSName = v },
		"M365SCAN_GRAPH_BASE_URL":    func(v string) { c.GraphBaseURL = v },
	} {
		if v := os.Getenv(env); v != "" {
			set(v)
		}
	}
}

// Validate collects every problem instead of stopping at the first, so a
// half-provisioned box needs one restart to fix rather than five.
// TenantReady reports whether the box has everything it needs to talk to Graph.
// A box without it still runs: scans queue up and the admin UI says so.
func (c Config) TenantReady() error {
	var missing []string
	for name, v := range map[string]string{"tenantId": c.TenantID, "clientId": c.ClientID, "certPath": c.CertPath} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("not onboarded yet: %s", strings.Join(missing, ", "))
}

func (c Config) Validate() error {
	var problems []string
	// The tenant fields are deliberately absent: a box is installed before it is
	// onboarded, and it has to serve its admin UI in that state so someone can
	// see why it is not connected. Graph readiness is reported by TenantReady.
	for name, v := range map[string]string{
		"statePath":        c.StatePath,
		"shareRoot":        c.ShareRoot,
		"quarantineDir":    c.QuarantineDir,
		"progressDir":      c.ProgressDir,
		"ui.bindAddr":      c.UIBindAddr,
		"ui.certPath":      c.UICertPath,
		"ui.keyPath":       c.UIKeyPath,
		"ui.passwordHash":  c.UIPasswordHash,
		"ui.sessionSecret": c.UISessionSecret,
		"netbiosName":      c.NetBIOSName,
		"graphBaseUrl":     c.GraphBaseURL,
	} {
		if strings.TrimSpace(v) == "" {
			problems = append(problems, "missing "+name)
		}
	}
	// Decoded here rather than only in serve(): a base64 secret is long enough to
	// pass a length check and still kill startup under Restart=always, which on a
	// box nobody is watching looks like the daemon simply never came up.
	if c.UISessionSecret != "" {
		b, err := hex.DecodeString(c.UISessionSecret)
		switch {
		case err != nil:
			problems = append(problems, "ui.sessionSecret must be hex: openssl rand -hex 32")
		case len(b) < minSecretBytes:
			problems = append(problems, fmt.Sprintf("ui.sessionSecret must be at least %d hex characters, got %d", minSecretBytes*2, len(c.UISessionSecret)))
		}
	}
	if c.NetBIOSName != "" && !netbiosName.MatchString(c.NetBIOSName) {
		problems = append(problems, "netbiosName must be up to 15 letters, digits or hyphens")
	}
	if c.RescanInterval <= 0 {
		problems = append(problems, "rescanInterval must be > 0")
	}
	if err := c.RetryPolicy.Validate(); err != nil {
		problems = append(problems, "retry: "+err.Error())
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("scan: bad config: %s", strings.Join(problems, "; "))
	}
	return nil
}

func durationOr(s string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
