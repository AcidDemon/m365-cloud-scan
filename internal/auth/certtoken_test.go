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
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
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

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

// The engine waits out network failures instead of spending the retry budget,
// and it can only tell one apart if the net.Error survives azidentity. A
// refusal from Entra ID must not pass for one.
func TestTokenKeepsTheNetworkErrorReachable(t *testing.T) {
	pemPath := filepath.Join(t.TempDir(), "fetcher.pem")
	writeSelfSignedPEM(t, pemPath)
	for _, tc := range []struct {
		name    string
		do      transportFunc
		network bool
	}{
		{"DNS down", func(r *http.Request) (*http.Response, error) {
			return nil, &net.DNSError{Err: "no such host", Name: r.URL.Hostname(), IsNotFound: true}
		}, true},
		{"tenant refuses", func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusBadRequest, Request: r, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(`{"error":"invalid_tenant"}`))}, nil
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newCertTokenSourceWith("tenant-id", "client-id", pemPath,
				policy.ClientOptions{Transport: tc.do})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.Token(context.Background())
			var ne net.Error
			if err == nil || errors.As(err, &ne) != tc.network {
				t.Fatalf("err = %T %v, want a net.Error in the chain: %v", err, err, tc.network)
			}
		})
	}
}

// Entra answering 5xx or 429 is an outage on its side, so the engine has to
// wait it out rather than spend the retry budget. A 4xx refusal must not.
func TestEntraOutageIsTransient(t *testing.T) {
	pemPath := filepath.Join(t.TempDir(), "fetcher.pem")
	writeSelfSignedPEM(t, pemPath)
	for _, tc := range []struct {
		status     int
		retryAfter string
		transient  bool
		wait       time.Duration
	}{
		{http.StatusServiceUnavailable, "", true, 0},
		{http.StatusTooManyRequests, "7", true, 7 * time.Second},
		{http.StatusBadRequest, "", false, 0},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			do := transportFunc(func(r *http.Request) (*http.Response, error) {
				// Tenant discovery succeeds, so the failure is the token request.
				if r.Method == http.MethodGet {
					return &http.Response{StatusCode: http.StatusOK, Request: r, Header: http.Header{},
						Body: io.NopCloser(strings.NewReader(`{"issuer":"https://login.microsoftonline.com/tenant-id/v2.0",` +
							`"authorization_endpoint":"https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",` +
							`"token_endpoint":"https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token"}`))}, nil
				}
				h := http.Header{}
				if tc.retryAfter != "" {
					h.Set("Retry-After", tc.retryAfter)
				}
				return &http.Response{StatusCode: tc.status, Request: r, Header: h,
					Body: io.NopCloser(strings.NewReader(`{"error":"temporarily_unavailable"}`))}, nil
			})
			// Only the transport is swapped, so azcore's retries are the ones
			// that ship. The deadline keeps MSAL from adding its own 30s and
			// is shorter than the Retry-After, which azcore would sleep on.
			s, err := newCertTokenSourceWith("tenant-id", "client-id", pemPath,
				policy.ClientOptions{Transport: do})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = s.Token(ctx)
			var tr *transfer.Transient
			if err == nil || errors.As(err, &tr) != tc.transient {
				t.Fatalf("err = %T %v, want a *transfer.Transient: %v", err, err, tc.transient)
			}
			if tc.transient && tr.RetryAfter != tc.wait {
				t.Errorf("RetryAfter = %v, want %v", tr.RetryAfter, tc.wait)
			}
		})
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
