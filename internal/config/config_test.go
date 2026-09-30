package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	c, err := LoadConfig(write(t, `{"tenantId":"t","clientId":"c","ui":{"passwordHash":"$2a$","sessionSecret":"0123456789abcdef0123456789abcdef"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got, want string }{
		{"certPath", c.CertPath, defaultCertPath},
		{"statePath", c.StatePath, defaultStatePath},
		{"shareRoot", c.ShareRoot, defaultShareRoot},
		{"quarantineDir", c.QuarantineDir, defaultQuarantineDir},
		{"progressDir", c.ProgressDir, defaultProgressDir},
		{"ui.bindAddr", c.UIBindAddr, "0.0.0.0:8444"},
		{"ui.certPath", c.UICertPath, defaultUICertPath},
		{"ui.keyPath", c.UIKeyPath, defaultUIKeyPath},
		{"netbiosName", c.NetBIOSName, "m365scan"},
		{"graphBaseUrl", c.GraphBaseURL, "https://graph.microsoft.com/v1.0"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
	if c.RescanInterval != 5*time.Minute {
		t.Errorf("rescanInterval = %v", c.RescanInterval)
	}
	// Quick first retries for the person waiting at the MFP, a tail long enough
	// to ride out a short Graph outage: 2s, 4s, 8s up to 256s.
	if c.RetryPolicy.MaxAttempts != 8 || c.RetryPolicy.BaseDelay != 2*time.Second ||
		c.RetryPolicy.MaxDelay != 5*time.Minute || c.RetryPolicy.Jitter != 0.2 ||
		c.RetryPolicy.ChunkSize != 5*1024*1024 {
		t.Errorf("retry = %+v", c.RetryPolicy)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a minimal config should validate: %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	p := write(t, `{
	  "tenantId":"t","clientId":"c",
	  "shareRoot":"/data/scans",
	  "rescanInterval":"90s",
	  "ui":{"bindAddr":"127.0.0.1:9000","passwordHash":"$2a$","sessionSecret":"0123456789abcdef0123456789abcdef"},
	  "retry":{"maxAttempts":9,"baseDelay":"1s"}
	}`)
	t.Setenv("M365SCAN_TENANT_ID", "from-env")
	t.Setenv("M365SCAN_UI_BIND_ADDR", "0.0.0.0:1443")

	c, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.TenantID != "from-env" || c.UIBindAddr != "0.0.0.0:1443" {
		t.Errorf("env did not win: %+v", c)
	}
	if c.ShareRoot != "/data/scans" || c.RescanInterval != 90*time.Second {
		t.Errorf("file values lost: %+v", c)
	}
	// A partial retry block overlays the default.
	if c.RetryPolicy.MaxAttempts != 9 || c.RetryPolicy.BaseDelay != time.Second || c.RetryPolicy.MaxDelay != 5*time.Minute {
		t.Errorf("retry = %+v", c.RetryPolicy)
	}
}

// A password changed in the UI must outlive a config-management rewrite of
// config.json.
func TestPasswordFileWins(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "ui-password")
	if err := os.WriteFile(pwFile, []byte("$2a$12$fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(write(t, `{"tenantId":"t","clientId":"c","ui":{"passwordHash":"$2a$12$fromjson","passwordFile":"`+pwFile+`","sessionSecret":"0123456789abcdef0123456789abcdef"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.UIPasswordHash != "$2a$12$fromfile" {
		t.Errorf("passwordHash = %q", c.UIPasswordHash)
	}
}

func TestValidateReportsEverything(t *testing.T) {
	c := Config{RescanInterval: -1, NetBIOSName: "not.a.netbios.name", UISessionSecret: "short"}
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		"missing statePath",
		"missing shareRoot", "missing quarantineDir", "missing progressDir",
		"missing ui.bindAddr", "missing ui.certPath", "missing ui.keyPath", "missing ui.passwordHash",
		"missing graphBaseUrl", "netbiosName must be", "ui.sessionSecret must be",
		"rescanInterval must be > 0", "retry:",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
}

// The tenant fields are not part of Validate: a box runs before it is onboarded.
func TestValidateIgnoresTenantFieldsAndTenantReadyReportsThem(t *testing.T) {
	c := Config{RescanInterval: -1}
	if err := c.Validate(); strings.Contains(err.Error(), "tenantId") {
		t.Fatalf("Validate must not demand tenant fields, a fresh box has none: %v", err)
	}
	err := c.TenantReady()
	if err == nil {
		t.Fatal("TenantReady should report an unonboarded box")
	}
	for _, want := range []string{"tenantId", "clientId", "certPath"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	ready := Config{TenantID: "t", ClientID: "c", CertPath: "/etc/m365-scan/scan.pem"}
	if err := ready.TenantReady(); err != nil {
		t.Errorf("a configured tenant should be ready: %v", err)
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("a missing file should fail")
	}
	if _, err := LoadConfig(write(t, `{`)); err == nil {
		t.Error("broken JSON should fail")
	}
	if _, err := LoadConfig(write(t, `{"rescanInterval":"every now and then"}`)); err == nil {
		t.Error("a bad duration should fail")
	}
	if _, err := LoadConfig(write(t, `{"retry":{"maxDelay":"nope"}}`)); err == nil {
		t.Error("a bad retry duration should fail")
	}
}
