// Package auth adapts an Entra app-only certificate credential to the
// graph.TokenSource interface the Graph client consumes. The fetcher
// authenticates app-only with a certificate (never a client secret) and the
// .default scope.
package auth

import (
	"context"
	"fmt"
	"os"

	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
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
func (s *CertTokenSource) Token(ctx context.Context) (string, error) {
	at, err := s.getter.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{s.scope}})
	if err != nil {
		return "", err
	}
	return at.Token, nil
}

// NewCertTokenSource builds a CertTokenSource from a PEM bundle (unencrypted
// certificate + private key, the format the fetcher provisioning produces) for
// the given tenant and application (client) id. The private key never leaves
// the process.
func NewCertTokenSource(tenantID, clientID, certPEMPath string) (*CertTokenSource, error) {
	pemData, err := os.ReadFile(certPEMPath)
	if err != nil {
		return nil, fmt.Errorf("auth: read cert %q: %w", certPEMPath, err)
	}
	certs, key, err := azidentity.ParseCertificates(pemData, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: parse cert %q: %w", certPEMPath, err)
	}
	cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, certs, key, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: new client certificate credential: %w", err)
	}
	return newCertTokenSource(cred, GraphDefaultScope), nil
}
