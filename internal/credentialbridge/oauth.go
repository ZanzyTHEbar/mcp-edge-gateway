package credentialbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

type Client struct {
	resource string
	store    *credentialStore
	http     *http.Client
}

type metadata struct {
	Issuer               string   `json:"issuer"`
	TokenEndpoint        string   `json:"token_endpoint"`
	DeviceEndpoint       string   `json:"device_authorization_endpoint"`
	RegistrationEndpoint string   `json:"registration_endpoint"`
	GrantTypes           []string `json:"grant_types_supported"`
	AuthMethods          []string `json:"token_endpoint_auth_methods_supported"`
}

func New(resource, directory string) (*Client, error) {
	u, err := secureURL(resource)
	if err != nil {
		return nil, fmt.Errorf("service URL: %w", err)
	}
	if u.RawQuery != "" {
		return nil, errors.New("service URL must not include a query")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	store, err := newCredentialStore(u.String(), directory)
	if err != nil {
		return nil, err
	}
	return &Client{
		resource: u.String(), store: store,
		http: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("expected an absolute URL without user information or fragment")
	}
	if u.Scheme == "https" {
		return u, nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return u, nil
	}
	return nil, errors.New("HTTPS is required except on loopback addresses")
}

func (c *Client) edgeURL(raw string) (string, error) {
	u, err := secureURL(raw)
	if err != nil {
		return "", err
	}
	base, _ := url.Parse(c.resource)
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) {
		return "", errors.New("MCP Edge metadata must use the service URL's origin")
	}
	return u.String(), nil
}

func (c *Client) discover(ctx context.Context) (metadata, string, error) {
	base, _ := url.Parse(c.resource)
	prmURL := base.Scheme + "://" + base.Host + "/.well-known/oauth-protected-resource" + base.EscapedPath()
	var prm struct {
		Resource string   `json:"resource"`
		Issuers  []string `json:"authorization_servers"`
		Scopes   []string `json:"scopes_supported"`
	}
	if err := c.requestJSON(ctx, http.MethodGet, prmURL, nil, "", &prm); err != nil {
		return metadata{}, "", err
	}
	if prm.Resource != c.resource || len(prm.Issuers) != 1 || len(prm.Scopes) != 1 || !strings.HasPrefix(prm.Scopes[0], "mcp:") {
		return metadata{}, "", errors.New("expected single-service MCP Edge protected resource metadata")
	}
	issuerURL, err := c.edgeURL(prm.Issuers[0])
	if err != nil {
		return metadata{}, "", err
	}
	issuer, _ := url.Parse(issuerURL)
	metadataURL := issuer.Scheme + "://" + issuer.Host + "/.well-known/oauth-authorization-server" + issuer.EscapedPath()
	var m metadata
	if err := c.requestJSON(ctx, http.MethodGet, metadataURL, nil, "", &m); err != nil {
		return metadata{}, "", err
	}
	if m.Issuer != issuerURL || !slices.Contains(m.GrantTypes, deviceGrant) || !slices.Contains(m.AuthMethods, "none") {
		return metadata{}, "", errors.New("issuer mismatch or server does not support public device authorization")
	}
	for _, endpoint := range []string{m.TokenEndpoint, m.DeviceEndpoint} {
		if _, err := c.edgeURL(endpoint); err != nil {
			return metadata{}, "", err
		}
	}
	return m, prm.Scopes[0], nil
}

// Login is explicit: serving stdio never starts an interactive authorization.
// Existing credentials remain intact until the new grant has succeeded.
func (c *Client) Login(ctx context.Context, clientID string, output io.Writer) error {
	m, scope, err := c.discover(ctx)
	if err != nil {
		return err
	}
	if clientID == "" {
		previous, readErr := c.store.read(ctx)
		if readErr == nil && previous.Issuer == m.Issuer && previous.Scope == scope {
			clientID = previous.ClientID
		} else if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
	}
	if clientID == "" {
		endpoint, err := c.edgeURL(m.RegistrationEndpoint)
		if err != nil {
			return fmt.Errorf("public registration is unavailable; use --client-id with a registered public device client: %w", err)
		}
		body, _ := json.Marshal(map[string]any{
			"client_name":   "mcp-edge-credential-bridge",
			"grant_types":   []string{deviceGrant, "refresh_token"},
			"redirect_uris": []string{}, "response_types": []string{},
			"token_endpoint_auth_method": "none", "scope": scope,
		})
		var registered struct {
			ClientID string `json:"client_id"`
		}
		if err := c.requestJSON(ctx, http.MethodPost, endpoint, bytes.NewReader(body), "application/json", &registered); err != nil {
			return fmt.Errorf("public device registration failed; use --client-id if registration is operator-only: %w", err)
		}
		clientID = registered.ClientID
		if clientID == "" {
			return errors.New("registration did not return a client ID")
		}
	}
	form := url.Values{"client_id": {clientID}, "scope": {scope}, "resource": {c.resource}}
	var device oauth2.DeviceAuthResponse
	if err := c.requestJSON(ctx, http.MethodPost, m.DeviceEndpoint, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded", &device); err != nil {
		return err
	}
	if device.DeviceCode == "" || device.UserCode == "" || !time.Now().Before(device.Expiry) || device.Interval < 0 || device.Interval > 1800 {
		return errors.New("invalid device authorization response")
	}
	if _, err := secureURL(device.VerificationURI); err != nil {
		return err
	}
	verification := device.VerificationURI
	if device.VerificationURIComplete != "" {
		if _, err := secureURL(device.VerificationURIComplete); err != nil {
			return err
		}
		verification = device.VerificationURIComplete
	}
	if _, err := fmt.Fprintf(output, "Open on any device: %s\nUser code: %s\nWaiting for approval...\n", verification, device.UserCode); err != nil {
		return err
	}
	cfg := oauth2.Config{ClientID: clientID, Scopes: []string{scope}, Endpoint: oauth2.Endpoint{TokenURL: m.TokenEndpoint, AuthStyle: oauth2.AuthStyleInParams}}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, c.http)
	token, err := cfg.DeviceAccessToken(ctx, &device, oauth2.SetAuthURLParam("resource", c.resource))
	if err != nil {
		return oauthError("device authorization", err)
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return errors.New("expected an OAuth bearer token")
	}
	record := credential{Resource: c.resource, Issuer: m.Issuer, TokenEndpoint: m.TokenEndpoint, ClientID: clientID, Scope: scope, Token: token}
	if err := c.store.update(ctx, func(*credential) (*credential, error) { return &record, nil }); err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "Signed in. The stdio bridge is ready.")
	return err
}

func (c *Client) requestJSON(ctx context.Context, method, endpoint string, body io.Reader, contentType string, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("OAuth request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("OAuth request returned HTTP %d", res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(result); err != nil {
		return fmt.Errorf("invalid OAuth JSON response: %w", err)
	}
	return nil
}

// Token errors can contain response bodies with credentials; never print them.
func oauthError(operation string, err error) error {
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) {
		switch rejected.ErrorCode {
		case "authorization_pending", "slow_down", "access_denied", "expired_token", "invalid_grant", "invalid_client", "unauthorized_client":
			return fmt.Errorf("%s: %s; run login again if needed", operation, rejected.ErrorCode)
		default:
			return fmt.Errorf("%s: OAuth request rejected", operation)
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%s failed; check connectivity and run login again", operation)
}
