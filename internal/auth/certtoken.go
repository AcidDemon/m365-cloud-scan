// Package auth adapts an Entra app-only certificate credential to the
// graph.TokenSource interface the Graph client consumes. The fetcher
// authenticates app-only with a certificate (never a client secret) and the
// .default scope.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// GraphDefaultScope requests all statically-configured application permissions
// for Microsoft Graph; app-only flows use ".default" rather than per-resource
// scopes.
const GraphDefaultScope = "https://graph.microsoft.com/.default"

// tokenGetter is the subset of an azidentity credential that CertTokenSource
// needs. It is an interface so tests inject a fake and never touch a tenant.
// *azidentity.ClientCertificateCredential satisfies it.
type tokenGetter interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// CertTokenSource yields bearer tokens for Graph from an app-only certificate
// credential. It implements graph.TokenSource; the underlying credential caches
// and silently refreshes tokens, so Token is cheap to call per request.
type CertTokenSource struct {
	getter tokenGetter
	scope  string
}

var _ graph.TokenSource = (*CertTokenSource)(nil)

// newCertTokenSource wraps any tokenGetter; used by the constructor and tests.
func newCertTokenSource(g tokenGetter, scope string) *CertTokenSource {
	return &CertTokenSource{getter: g, scope: scope}
}

// Token acquires (or returns a cached) access token for the configured scope.
// A failure to reach Entra ID comes back as the network error itself, and
// Entra answering 5xx or 429 as a *transfer.Transient, so the engine can wait
// out the outage instead of spending the retry budget. Any other answer, such
// as an AADSTS refusal of the certificate, stays the error azidentity gave.
func (s *CertTokenSource) Token(ctx context.Context) (string, error) {
	var netErr error
	at, err := s.getter.GetToken(context.WithValue(ctx, netErrKey{}, &netErr),
		policy.TokenRequestOptions{Scopes: []string{s.scope}})
	if err != nil {
		if netErr != nil {
			return "", fmt.Errorf("auth: reach Entra ID: %w", netErr)
		}
		// MSAL hands azidentity the response that failed, which keeps it as
		// RawResponse.
		var afe *azidentity.AuthenticationFailedError
		if errors.As(err, &afe) && afe.RawResponse != nil &&
			(afe.RawResponse.StatusCode == http.StatusTooManyRequests || afe.RawResponse.StatusCode >= 500) {
			secs, _ := strconv.Atoi(afe.RawResponse.Header.Get("Retry-After"))
			return "", &transfer.Transient{Err: err, RetryAfter: time.Duration(secs) * time.Second}
		}
		return "", err
	}
	return at.Token, nil
}

// netErrKey carries a slot through GetToken. azidentity flattens whatever MSAL
// returns into the message of an AuthenticationFailedError, which has no
// Unwrap, so a DNS failure would otherwise look like a refused certificate.
type netErrKey struct{}

// recordNetErr sits under the credential's retry policy and notes the transport
// outcome of every request. Each one overwrites the last, because an earlier
// request that failed did not cause the final error if a later one was sent.
type recordNetErr struct{}

func (recordNetErr) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if slot, ok := req.Raw().Context().Value(netErrKey{}).(*error); ok {
		*slot = err
	}
	return resp, err
}

// NewCertTokenSource builds a CertTokenSource from a PEM bundle (unencrypted
// certificate + private key, the format the fetcher provisioning produces) for
// the given tenant and application (client) id. The private key never leaves
// the process.
func NewCertTokenSource(tenantID, clientID, certPEMPath string) (*CertTokenSource, error) {
	return newCertTokenSourceWith(tenantID, clientID, certPEMPath, policy.ClientOptions{})
}

// newCertTokenSourceWith lets a test swap the HTTP transport underneath the
// real credential.
func newCertTokenSourceWith(tenantID, clientID, certPEMPath string, co policy.ClientOptions) (*CertTokenSource, error) {
	pemData, err := os.ReadFile(certPEMPath)
	if err != nil {
		return nil, fmt.Errorf("auth: read cert %q: %w", certPEMPath, err)
	}
	certs, key, err := azidentity.ParseCertificates(pemData, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: parse cert %q: %w", certPEMPath, err)
	}
	co.PerRetryPolicies = append(co.PerRetryPolicies, recordNetErr{})
	// azcore would sleep on a Retry-After of up to 60s, but MSAL gives each
	// call 30s, and a call cut short mid-sleep loses the response that says
	// Entra is busy. The engine waits out outages itself, so try once.
	co.Retry.MaxRetries = -1
	cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key,
		&azidentity.ClientCertificateCredentialOptions{ClientOptions: co})
	if err != nil {
		return nil, fmt.Errorf("auth: new client certificate credential: %w", err)
	}
	return newCertTokenSource(cred, GraphDefaultScope), nil
}
