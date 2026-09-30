// Package deviceauth runs the OAuth device-code flow, which is what lets the
// box onboard itself: the admin signs in on their own machine and the box never
// sees the password.
//
// It authenticates against Microsoft's Graph PowerShell public client, so no
// app registration has to exist yet. That is the bootstrap problem solved: the
// first thing the box does with this token is register its own app.
package deviceauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// PublicClient is Microsoft's own Graph PowerShell client id, present in
	// every tenant.
	PublicClient = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
	authBase     = "https://login.microsoftonline.com/organizations/oauth2/v2.0"
)

// Scopes are what provisioning needs: register an app, consent to its role, and
// grant it write on the chosen sites.
var Scopes = strings.Join([]string{
	"https://graph.microsoft.com/Application.ReadWrite.All",
	"https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All",
	"https://graph.microsoft.com/Sites.FullControl.All",
	"offline_access",
}, " ")

// Code is what the admin has to act on.
type Code struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// Token carries the delegated access token plus the tenant it belongs to.
type Token struct {
	AccessToken string
	TenantID    string
	UPN         string
}

// ErrPending means the admin has not finished signing in yet.
var ErrPending = fmt.Errorf("authorization pending")

type Client struct{ HTTP *http.Client }

func New(h *http.Client) *Client {
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{HTTP: h}
}

// Start asks for a code to show the admin.
func (c *Client) Start(ctx context.Context) (Code, error) {
	var code Code
	form := url.Values{"client_id": {PublicClient}, "scope": {Scopes}}
	if err := c.form(ctx, authBase+"/devicecode", form, &code); err != nil {
		return Code{}, err
	}
	if code.Interval <= 0 {
		code.Interval = 5
	}
	return code, nil
}

// Poll asks once whether the admin has finished. ErrPending means keep waiting;
// anything else is final.
func (c *Client) Poll(ctx context.Context, deviceCode string) (Token, error) {
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"client_id":   {PublicClient},
		"device_code": {deviceCode},
	}
	if err := c.form(ctx, authBase+"/token", form, &out); err != nil && out.Error == "" {
		return Token{}, err
	}
	switch out.Error {
	case "":
	case "authorization_pending", "slow_down":
		return Token{}, ErrPending
	case "expired_token":
		return Token{}, fmt.Errorf("the code expired, start again")
	case "authorization_declined":
		return Token{}, fmt.Errorf("the sign-in was declined")
	default:
		return Token{}, fmt.Errorf("%s: %s", out.Error, out.Description)
	}
	tid, upn := claims(out.AccessToken)
	return Token{AccessToken: out.AccessToken, TenantID: tid, UPN: upn}, nil
}

func (c *Client) form(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%s answered something that is not JSON: %w", endpoint, err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	return nil
}

// claims reads the tenant and the signed-in account out of the token without
// verifying it. The token is only ever sent back to the issuer, so this is for
// display and for stamping the config, never for a decision.
func claims(jwt string) (tenantID, upn string) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct {
		TID string `json:"tid"`
		UPN string `json:"upn"`
	}
	_ = json.Unmarshal(raw, &c)
	return c.TID, c.UPN
}
