package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type staticResolver struct{}

func (staticResolver) Resolve(ctx context.Context, serviceID string, subjectSub string) (UpstreamTarget, error) {
	return UpstreamTarget{}, ErrTenantUpstreamNotConfigured
}

type urlResolver struct {
	targets map[string]string
}

func (r urlResolver) Resolve(ctx context.Context, serviceID string, subjectSub string) (UpstreamTarget, error) {
	rawURL, ok := r.targets[serviceID]
	if !ok {
		return UpstreamTarget{}, ErrServiceNotFound
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return UpstreamTarget{}, err
	}
	return UpstreamTarget{BaseURL: parsedURL}, nil
}

func TestOAuthMetadataEndpoints(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com", payload["issuer"])
	require.Equal(t, "https://mcp.example.com/oauth/register", payload["registration_endpoint"])
	require.Contains(t, payload["scopes_supported"], "mcp:mealie")
	require.Contains(t, payload["code_challenge_methods_supported"], "S256")

	req = httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com", payload["resource"])
	require.Contains(t, payload["authorization_servers"], "https://mcp.example.com")
}

func TestOAuthRegistrationAuthorizationCodeAndIntrospection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		require.Empty(t, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{
		targets: map[string]string{
			"mealie": upstream.URL,
		},
	})
	handler := server.Handler()

	registrationBody := `{
		"client_name":"open-webui",
		"redirect_uris":["https://openwebui.example.com/oauth/callback"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"mcp:mealie"
	}`

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.NotEmpty(t, registration.ClientID)
	require.Empty(t, registration.ClientSecret)
	require.Equal(t, "none", registration.TokenEndpointAuthMethod)

	initialAuthorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(registration.RedirectURIs[0])+
			"&scope="+url.QueryEscape("mcp:mealie")+
			"&state="+url.QueryEscape("test-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)

	res = httptest.NewRecorder()
	handler.ServeHTTP(res, initialAuthorizeRequest)

	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)

	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)

	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())

	sessionCookie := res.Result().Cookies()[0]

	authorizeRequest := httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	authorizeRequest.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)

	require.Equal(t, http.StatusFound, res.Code)

	location, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https://openwebui.example.com/oauth/callback", location.Scheme+"://"+location.Host+location.Path)

	authCode := location.Query().Get("code")
	require.NotEmpty(t, authCode)
	require.Equal(t, "test-state", location.Query().Get("state"))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", registration.RedirectURIs[0])
	tokenForm.Set("client_id", registration.ClientID)
	tokenForm.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)

	var tokenPayload map[string]any
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &tokenPayload))
	accessToken, ok := tokenPayload["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)
	refreshToken, ok := tokenPayload["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)

	introspectionForm := url.Values{}
	introspectionForm.Set("token", accessToken)

	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)

	var introspection tokenIntrospectionResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, registration.ClientID, introspection.ClientID)
	require.Equal(t, "fixture-user", introspection.Sub)
	require.Equal(t, "mcp:mealie", introspection.Scope)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)

	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshToken)
	refreshForm.Set("client_id", registration.ClientID)

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)

	var refreshPayload map[string]any
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &refreshPayload))
	newAccessToken, ok := refreshPayload["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, newAccessToken)
	require.NotEqual(t, accessToken, newAccessToken)

	introspectionForm.Set("token", accessToken)
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.False(t, introspection.Active)

	introspectionForm.Set("token", newAccessToken)
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, registration.ClientID, introspection.ClientID)
}

func TestBrowserLoginStateSurvivesFailedCallback(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	initialAuthorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id=test-client"+
			"&redirect_uri="+url.QueryEscape("https://example.com/callback")+
			"&scope="+url.QueryEscape("mcp:mealie")+
			"&state="+url.QueryEscape("test-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, initialAuthorizeRequest)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)

	failedCallback := *loginRedirect
	query := failedCallback.Query()
	query.Set("fixture", "0")
	failedCallback.RawQuery = query.Encode()

	req := httptest.NewRequest(http.MethodGet, failedCallback.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "delegated_login_failed")

	req = httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())
}

func TestOAuthRegistrationRejectsUnsupportedMetadata(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{
		"client_name":"bad-client",
		"redirect_uris":["https://a.example/callback","https://b.example/callback"],
		"token_endpoint_auth_method":"private_key_jwt"
	}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "exactly one redirect URI is required")
}

func TestOAuthRegistrationRequiresOperatorBearerToken(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{
		"client_name":"open-webui",
		"redirect_uris":["https://openwebui.example.com/oauth/callback"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "operator bearer token is required")
}

func TestOAuthIntrospectionRequiresOperatorBearerToken(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {"abc"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "operator bearer token is required")
}

func TestNewServerFailsWithoutExplicitAuthMode(t *testing.T) {
	_, err := NewServer(
		Config{
			PublicBaseURL:        "https://mcp.example.com",
			FixtureOperatorToken: "fixture-operator-token",
		},
		zerolog.New(httptest.NewRecorder()),
		staticResolver{},
	)
	require.ErrorContains(t, err, "requires Authentik OIDC configuration unless fixture mode is explicitly enabled")
}

func newTestEdgeServer(t *testing.T, resolver Resolver) *Server {
	t.Helper()
	if resolver == nil {
		resolver = staticResolver{}
	}

	server, err := NewServer(
		Config{
			PlatformEnv:           "test",
			PublicBaseURL:         "https://mcp.example.com",
			CookieSecure:          false,
			EnableFixtureMode:     true,
			FixtureAuthSubjectSub: "fixture-user",
			FixtureAuthGroups:     []string{"mcp-users", "mcp-service-mealie"},
			FixtureOperatorToken:  "fixture-operator-token",
		},
		zerolog.New(httptest.NewRecorder()),
		resolver,
	)
	require.NoError(t, err)
	return server
}
