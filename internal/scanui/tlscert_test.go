package scanui

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCert(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")

	c1, err := LoadOrCreateCert(cp, kp, "box.local")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(c1.Certificate) == 0 {
		t.Fatal("empty certificate")
	}
	// Second call must load the SAME persisted cert, not mint a new one.
	c2, err := LoadOrCreateCert(cp, kp, "box.local")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Error("second call regenerated the cert instead of loading it")
	}
}

func TestLoadOrCreateCertWithIP(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	ip := "192.168.1.50"

	c, err := LoadOrCreateCert(cp, kp, ip)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(c.Certificate) == 0 {
		t.Fatal("empty certificate")
	}

	// Parse the leaf cert and verify IP and ExtKeyUsage.
	cert, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	// Verify IP is in IPAddresses.
	parsedIP := net.ParseIP(ip)
	found := false
	for _, addr := range cert.IPAddresses {
		if addr.Equal(parsedIP) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("IP %s not found in cert.IPAddresses: %v", ip, cert.IPAddresses)
	}

	// Verify ExtKeyUsageServerAuth is present.
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
			break
		}
	}
	if !hasServerAuth {
		t.Errorf("ExtKeyUsageServerAuth not found in cert.ExtKeyUsage: %v", cert.ExtKeyUsage)
	}
}

// A box is reached by address as often as by name, so a certificate that covers
// only one of them adds a name-mismatch warning to the self-signed one.
func TestCertCoversEveryNameAndAddress(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ui-cert.pem")
	keyPath := filepath.Join(dir, "ui-key.pem")
	if _, err := LoadOrCreateCert(certPath, keyPath, "m365scan", "127.0.0.1", "192.168.60.10", "m365scan", ""); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(c.DNSNames); got != 1 || c.DNSNames[0] != "m365scan" {
		t.Errorf("want the name once, got %v", c.DNSNames)
	}
	for _, want := range []string{"127.0.0.1", "192.168.60.10"} {
		if err := c.VerifyHostname(want); err != nil {
			t.Errorf("certificate does not cover %s: %v", want, err)
		}
	}
	if err := c.VerifyHostname("m365scan"); err != nil {
		t.Errorf("certificate does not cover its own name: %v", err)
	}
	if _, err := LoadOrCreateCert(filepath.Join(dir, "b.pem"), filepath.Join(dir, "b-key.pem")); err == nil {
		t.Error("issuing a certificate for nothing should fail")
	}
}
