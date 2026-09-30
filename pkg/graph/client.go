package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

// DefaultBaseURL is the Graph v1.0 endpoint.
const DefaultBaseURL = "https://graph.microsoft.com/v1.0"

// TokenSource yields a bearer token for Graph calls. Implementations wrap
// azidentity credentials; injected so this package stays auth-agnostic.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Client is a thin Microsoft Graph REST client.
type Client struct {
	http   *http.Client
	base   string
	tokens TokenSource
}

// NewClient builds a Client. A nil httpClient uses http.DefaultClient; an empty
// base uses DefaultBaseURL.
func NewClient(httpClient *http.Client, base string, tokens TokenSource) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{http: httpClient, base: strings.TrimRight(base, "/"), tokens: tokens}
}

// newRequest builds a request, injecting the bearer token and Accept header. If
// urlStr starts with "/" it is appended to the client base; otherwise it is used
// as an absolute URL. hdr entries are set (overwriting) after the defaults.
func (c *Client) newRequest(ctx context.Context, method, urlStr string, body io.Reader, hdr map[string]string) (*http.Request, error) {
	if strings.HasPrefix(urlStr, "/") {
		urlStr = c.base + urlStr
	}
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	tok, err := c.tokens.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("graph: acquire token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return req, nil
}

// do sends a request. On 2xx it returns the response with the body OPEN (the
// caller must close it). On a non-2xx status it returns classify(...) and closes
// the body. A transport-level error is returned as a retryable *transfer.Transient.
func (c *Client) do(ctx context.Context, method, urlStr string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, urlStr, body, hdr)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &transfer.Transient{Err: err}
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	return nil, classify(resp.StatusCode, resp.Header.Get("Retry-After"), decodeError(resp))
}

// decodeError reads (a bounded prefix of) a non-2xx body and builds an APIError,
// pulling Graph's {"error":{"code","message"}} envelope when present.
func decodeError(resp *http.Response) *APIError {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	ae := &APIError{Status: resp.StatusCode, Body: string(b)}
	var wrap struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &wrap) == nil {
		ae.Code = wrap.Error.Code
		ae.Msg = wrap.Error.Message
	}
	return ae
}
