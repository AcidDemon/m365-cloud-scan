package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeGetter is a tokenGetter that records the scopes it was asked for and
// returns a canned token/error, so Token can be tested without a real tenant.
type fakeGetter struct {
	gotScopes []string
	tok       string
	err       error
}

func (f *fakeGetter) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.gotScopes = opts.Scopes
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.tok, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestTokenPassesDefaultScopeAndReturnsToken(t *testing.T) {
	f := &fakeGetter{tok: "abc"}
	s := newCertTokenSource(f, GraphDefaultScope)
	got, err := s.Token(context.Background())
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if got != "abc" {
		t.Fatalf("token=%q want abc", got)
	}
	if len(f.gotScopes) != 1 || f.gotScopes[0] != GraphDefaultScope {
		t.Fatalf("scopes=%v want [%s]", f.gotScopes, GraphDefaultScope)
	}
}

func TestTokenPropagatesError(t *testing.T) {
	sentinel := errors.New("boom")
	s := newCertTokenSource(&fakeGetter{err: sentinel}, GraphDefaultScope)
	got, err := s.Token(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("err=%v want sentinel", err)
	}
	if got != "" {
		t.Fatalf("token=%q want empty on error", got)
	}
}

func TestNewCertTokenSourceParsesPEM(t *testing.T) {
	pemPath := filepath.Join(t.TempDir(), "fetcher.pem")
	writeSelfSignedPEM(t, pemPath)
	s, err := NewCertTokenSource("tenant-id", "client-id", pemPath)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if s == nil || s.getter == nil {
		t.Fatalf("expected a usable source")
	}
	if s.scope != GraphDefaultScope {
		t.Fatalf("scope=%q want %s", s.scope, GraphDefaultScope)
	}
}

func TestNewCertTokenSourceBadPath(t *testing.T) {
	if _, err := NewCertTokenSource("t", "c", filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Fatalf("expected error for missing cert file")
	}
}

// writeSelfSignedPEM writes an unencrypted RSA cert+key PEM bundle (the format
// the fetcher cert provisioning produces) so the parse path is exercised.
func writeSelfSignedPEM(t *testing.T, path string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "M365Print-Fetcher-Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
