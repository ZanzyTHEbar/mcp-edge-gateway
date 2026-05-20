package edge

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/ids"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestValidateCIMDURLRejectsPrivateHosts(t *testing.T) {
	t.Parallel()

	parsed, err := url.Parse("https://127.0.0.1/client.json")
	require.NoError(t, err)
	require.ErrorContains(t, validateCIMDURL(context.Background(), parsed), "public addresses only")

	parsed, err = url.Parse("http://client.example.com/client.json")
	require.NoError(t, err)
	require.ErrorContains(t, validateCIMDURL(context.Background(), parsed), "HTTPS URL")
}

func TestValidateRedirectURIRejectsUnsafeSchemes(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateRedirectURI("https://client.example.com/callback"))
	require.NoError(t, validateRedirectURI("http://127.0.0.1:33418/callback"))
	require.ErrorContains(t, validateRedirectURI("javascript:alert(1)"), "scheme must be https or loopback http")
	require.ErrorContains(t, validateRedirectURI("data:text/plain,ok"), "scheme must be https or loopback http")
	require.ErrorContains(t, validateRedirectURI("http://client.example.com/callback"), "loopback")
}

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
	require.Equal(t, "https://mcp.example.com/oauth/device_authorization", payload["device_authorization_endpoint"])
	require.Contains(t, payload["grant_types_supported"], oauthGrantDeviceCode)
	require.Contains(t, payload["scopes_supported"], "mcp:mealie")
	require.Contains(t, payload["code_challenge_methods_supported"], "S256")
	require.Equal(t, true, payload["resource_indicators_supported"])
	require.Equal(t, true, payload["client_id_metadata_document_supported"])

	req = httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com", payload["issuer"])

	req = httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com", payload["resource"])
	require.Contains(t, payload["authorization_servers"], "https://mcp.example.com")

	req = httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mealie", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com/mealie/mcp", payload["resource"])
	require.Equal(t, "Mealie", payload["resource_name"])
	require.Contains(t, payload["authorization_servers"], "https://mcp.example.com/mealie")
	require.Contains(t, payload["scopes_supported"], "mcp:mealie")
	require.NotContains(t, payload["scopes_supported"], "mcp:actualbudget")

	req = httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server/mealie", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "https://mcp.example.com/mealie", payload["issuer"])
	require.Equal(t, "https://mcp.example.com/oauth/register/mealie", payload["registration_endpoint"])
	require.Equal(t, "https://mcp.example.com/oauth/authorize/mealie", payload["authorization_endpoint"])
	require.Contains(t, payload["scopes_supported"], "mcp:mealie")
	require.NotContains(t, payload["scopes_supported"], "mcp:actualbudget")
}

func TestOAuthServiceScopedDCRAndAuthorizeNarrowBroadScope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{targets: map[string]string{"mealie": upstream.URL}})
	handler := server.Handler()
	redirectURI := "https://client.example.com/oauth/callback"
	broadScope := strings.Join(server.catalogCache.Scopes(), " ")

	registrationBody := `{
		"client_name":"service-scoped-client",
		"redirect_uris":["` + redirectURI + `"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"` + broadScope + `"
	}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register/mealie", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.Equal(t, "mcp:mealie", registration.Scope)

	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize/mealie?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope="+url.QueryEscape(broadScope)+
			"&state="+url.QueryEscape("service-scoped-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())

	callbackRequest = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	callbackRequest.AddCookie(res.Result().Cookies()[0])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)

	redirectLocation, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, redirectURI, redirectLocation.Scheme+"://"+redirectLocation.Host+redirectLocation.Path)
	require.Equal(t, "service-scoped-state", redirectLocation.Query().Get("state"))
	authCode := redirectLocation.Query().Get("code")
	require.NotEmpty(t, authCode)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", redirectURI)
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

	introspectionForm := url.Values{"token": {accessToken}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var introspection tokenIntrospectionResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, "mcp:mealie", introspection.Scope)
	require.Equal(t, "https://mcp.example.com/mealie/mcp", introspection.Resource)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())
}

func TestDesktopClientOAuthSmokeUsesDiscoveryResourceAndLoopbackRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{targets: map[string]string{"mealie": upstream.URL}})
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var discovery struct {
		Services []struct {
			ID                           string `json:"id"`
			URL                          string `json:"url"`
			Resource                     string `json:"resource"`
			ProtectedResourceMetadataURL string `json:"protected_resource_metadata_url"`
			Scope                        string `json:"scope"`
		} `json:"services"`
	}
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &discovery))

	var mealieService struct {
		ID                           string `json:"id"`
		URL                          string `json:"url"`
		Resource                     string `json:"resource"`
		ProtectedResourceMetadataURL string `json:"protected_resource_metadata_url"`
		Scope                        string `json:"scope"`
	}
	for _, service := range discovery.Services {
		if service.ID == "mealie" {
			mealieService = service
			break
		}
	}
	require.Equal(t, "https://mcp.example.com/mealie/mcp", mealieService.URL)
	require.Equal(t, mealieService.URL, mealieService.Resource)
	require.Equal(t, "https://mcp.example.com/.well-known/oauth-protected-resource/mealie", mealieService.ProtectedResourceMetadataURL)
	require.Equal(t, "mcp:mealie", mealieService.Scope)

	redirectURI := "http://127.0.0.1:33418/oauth/callback"
	registrationBody := `{
		"client_name":"desktop-smoke-client",
		"redirect_uris":["` + redirectURI + `"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"` + mealieService.Scope + `"
	}`

	req = httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.Equal(t, []string{redirectURI}, registration.RedirectURIs)

	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope="+url.QueryEscape(mealieService.Scope)+
			"&resource="+url.QueryEscape(mealieService.Resource)+
			"&state="+url.QueryEscape("desktop-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())

	callbackRequest = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	callbackRequest.AddCookie(res.Result().Cookies()[0])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)

	redirectLocation, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:33418/oauth/callback", redirectLocation.Scheme+"://"+redirectLocation.Host+redirectLocation.Path)
	require.Equal(t, "desktop-state", redirectLocation.Query().Get("state"))
	authCode := redirectLocation.Query().Get("code")
	require.NotEmpty(t, authCode)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", redirectURI)
	tokenForm.Set("client_id", registration.ClientID)
	tokenForm.Set("resource", mealieService.Resource)
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

	introspectionForm := url.Values{"token": {accessToken}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var introspection tokenIntrospectionResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, mealieService.Scope, introspection.Scope)
	require.Equal(t, mealieService.Resource, introspection.Resource)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())
}

func TestOAuthAuthorizeAndTokenDeriveMissingResourceFromSingleScope(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{targets: map[string]string{"mealie": upstream.URL}})
	handler := server.Handler()
	redirectURI := "https://client.example.com/oauth/callback"
	resource := "https://mcp.example.com/mealie/mcp"
	scope := "mcp:mealie"

	registrationBody := `{
		"client_name":"grok-smoke-client",
		"redirect_uris":["` + redirectURI + `"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"` + scope + `"
	}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))

	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope="+url.QueryEscape(scope)+
			"&state="+url.QueryEscape("grok-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())

	callbackRequest = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	callbackRequest.AddCookie(res.Result().Cookies()[0])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)

	redirectLocation, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, redirectURI, redirectLocation.Scheme+"://"+redirectLocation.Host+redirectLocation.Path)
	require.Equal(t, "grok-state", redirectLocation.Query().Get("state"))
	authCode := redirectLocation.Query().Get("code")
	require.NotEmpty(t, authCode)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", redirectURI)
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

	introspectionForm := url.Values{"token": {accessToken}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var introspection tokenIntrospectionResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, scope, introspection.Scope)
	require.Equal(t, resource, introspection.Resource)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())
}

func TestOAuthGlobalMultiScopeAuthorizeWithoutResourceFails(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()
	redirectURI := "https://client.example.com/oauth/callback"
	broadScope := "mcp:mealie mcp:actualbudget"

	registrationBody := `{
		"client_name":"global-multiscope-client",
		"redirect_uris":["` + redirectURI + `"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"` + broadScope + `"
	}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))

	subject := AuthenticatedSubject{Sub: "fixture-user", Groups: []string{"mcp-users", "mcp-service-mealie", "mcp-service-actualbudget"}}
	require.NoError(t, server.stateStore.UpsertSubject(context.Background(), IdentityClaims{Sub: subject.Sub, Groups: subject.Groups}))
	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&scope="+url.QueryEscape(broadScope)+
			"&state="+url.QueryEscape("global-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	authorizeRequest = authorizeRequest.WithContext(WithAuthenticatedSubject(authorizeRequest.Context(), subject))
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)

	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "invalid_resource")
	require.Contains(t, res.Body.String(), "exactly one mcp")
}

func TestOAuthRegistrationAllowsDeviceOnlyClientWithoutRedirectURI(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	body := `{
    "client_name":"headless-cli",
    "grant_types":["` + oauthGrantDeviceCode + `","refresh_token"],
    "response_types":[],
    "token_endpoint_auth_method":"none",
    "scope":"mcp:mealie"
  }`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusCreated, res.Code)
	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.Empty(t, registration.RedirectURIs)
	require.Empty(t, registration.ResponseTypes)
	require.ElementsMatch(t, []string{oauthGrantDeviceCode, oauthGrantRefreshToken}, registration.GrantTypes)

	clientInfo, err := server.stateStore.GetByID(context.Background(), registration.ClientID)
	require.NoError(t, err)
	require.True(t, clientAllowsGrant(clientInfo, oauthGrantDeviceCode))
	require.True(t, clientAllowsGrant(clientInfo, oauthGrantRefreshToken))
	require.False(t, clientAllowsGrant(clientInfo, oauthGrantAuthorizationCode))
}

func TestOAuthRegistrationValidatesGrantSpecificMetadata(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "authorization code requires redirect",
			body: `{"client_name":"bad-auth-code","grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"mcp:mealie"}`,
		},
		{
			name: "device only requires empty response types",
			body: `{"client_name":"bad-device","grant_types":["` + oauthGrantDeviceCode + `"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"mcp:mealie"}`,
		},
		{
			name: "unsupported grant",
			body: `{"client_name":"bad-grant","grant_types":["client_credentials"],"response_types":[],"token_endpoint_auth_method":"none","scope":"mcp:mealie"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer fixture-operator-token")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)

			require.Equal(t, http.StatusBadRequest, res.Code)
			require.Contains(t, res.Body.String(), "invalid_client_metadata")
		})
	}
}

func TestOAuthAuthorizeRejectsClientWithoutAuthorizationCodeGrant(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	body := `{
    "client_name":"headless-cli",
    "grant_types":["` + oauthGrantDeviceCode + `"],
    "response_types":[],
    "token_endpoint_auth_method":"none",
    "scope":"mcp:mealie"
  }`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))

	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape("http://127.0.0.1:33418/oauth/callback")+
			"&scope="+url.QueryEscape("mcp:mealie")+
			"&resource="+url.QueryEscape("https://mcp.example.com/mealie/mcp")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)

	authorizeRequest = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	authorizeRequest.AddCookie(res.Result().Cookies()[0])
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, authorizeRequest)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "unauthorized_client")
}

func TestOAuthDeviceAuthorizationIssuesTokenAfterApproval(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{targets: map[string]string{"mealie": upstream.URL}})
	handler := server.Handler()

	registrationBody := `{
    "client_name":"headless-cli",
    "grant_types":["` + oauthGrantDeviceCode + `","refresh_token"],
    "response_types":[],
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

	deviceForm := url.Values{}
	deviceForm.Set("client_id", registration.ClientID)
	deviceForm.Set("scope", "mcp:mealie")
	deviceForm.Set("resource", "https://mcp.example.com/mealie/mcp")
	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(deviceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	var deviceResponse deviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &deviceResponse))
	require.NotEmpty(t, deviceResponse.DeviceCode)
	require.NotEmpty(t, deviceResponse.UserCode)
	require.Equal(t, "https://mcp.example.com/oauth/device", deviceResponse.VerificationURI)
	require.Contains(t, deviceResponse.VerificationURIComplete, url.QueryEscape(deviceResponse.UserCode))

	devicePage := httptest.NewRequest(http.MethodGet, "/oauth/device?user_code="+url.QueryEscape(deviceResponse.UserCode), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, devicePage)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())
	sessionCookie := res.Result().Cookies()[0]

	devicePage = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	devicePage.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, devicePage)
	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "no-store", res.Header().Get("Cache-Control"))
	require.Equal(t, "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'", res.Header().Get("Content-Security-Policy"))
	require.Equal(t, "no-referrer", res.Header().Get("Referrer-Policy"))
	require.Equal(t, "DENY", res.Header().Get("X-Frame-Options"))
	require.Contains(t, res.Body.String(), "Approve MCP Device")
	require.Contains(t, res.Body.String(), html.EscapeString(deviceResponse.UserCode))
	csrfToken := extractDeviceCSRFToken(t, res.Body.String())

	approvalForm := url.Values{}
	approvalForm.Set("user_code", deviceResponse.UserCode)
	approvalForm.Set("action", "approve")
	approvalRequest := httptest.NewRequest(http.MethodPost, "/oauth/device", strings.NewReader(approvalForm.Encode()))
	approvalRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approvalRequest.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, approvalRequest)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.Contains(t, res.Body.String(), "invalid_csrf_token")

	approvalForm.Set("csrf_token", csrfToken)
	approvalRequest = httptest.NewRequest(http.MethodPost, "/oauth/device", strings.NewReader(approvalForm.Encode()))
	approvalRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approvalRequest.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, approvalRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), "approved")

	deviceRecord, ok, err := server.stateStore.GetDeviceAuthorizationByDeviceCode(context.Background(), deviceResponse.DeviceCode)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, deviceAuthorizationStatusApproved, deviceRecord.Status)

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", oauthGrantDeviceCode)
	tokenForm.Set("device_code", deviceResponse.DeviceCode)
	tokenForm.Set("client_id", registration.ClientID)
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
	require.Equal(t, "mcp:mealie", tokenPayload["scope"])
	require.Equal(t, "https://mcp.example.com/mealie/mcp", tokenPayload["resource"])
	require.NotEmpty(t, tokenPayload["refresh_token"])

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())
}

func TestOAuthServiceScopedDeviceAuthorizationNarrowsBroadScope(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()
	broadScope := strings.Join(server.catalogCache.Scopes(), " ")

	registrationBody := `{
    "client_name":"service-scoped-headless-cli",
    "grant_types":["` + oauthGrantDeviceCode + `","refresh_token"],
    "response_types":[],
    "token_endpoint_auth_method":"none",
    "scope":"` + broadScope + `"
  }`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register/mealie", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)

	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.Equal(t, "mcp:mealie", registration.Scope)

	deviceForm := url.Values{}
	deviceForm.Set("client_id", registration.ClientID)
	deviceForm.Set("scope", broadScope)
	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization/mealie", strings.NewReader(deviceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)

	var deviceResponse deviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &deviceResponse))
	require.NotEmpty(t, deviceResponse.DeviceCode)

	deviceRecord, ok, err := server.stateStore.GetDeviceAuthorizationByDeviceCode(context.Background(), deviceResponse.DeviceCode)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "mcp:mealie", deviceRecord.Scope)
	require.Equal(t, "mealie", deviceRecord.ServiceID)
	require.Equal(t, "https://mcp.example.com/mealie/mcp", deviceRecord.Resource)

	wrongResourceForm := url.Values{}
	wrongResourceForm.Set("client_id", registration.ClientID)
	wrongResourceForm.Set("scope", broadScope)
	wrongResourceForm.Set("resource", "https://mcp.example.com/actualbudget/mcp")
	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization/mealie", strings.NewReader(wrongResourceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "invalid_resource")

	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization/not-a-service", strings.NewReader(deviceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func TestOAuthDeviceAuthorizationDenyRequiresCSRFAndRejectsPolling(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	registrationBody := `{
    "client_name":"headless-cli",
    "grant_types":["` + oauthGrantDeviceCode + `"],
    "response_types":[],
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

	deviceForm := url.Values{}
	deviceForm.Set("client_id", registration.ClientID)
	deviceForm.Set("scope", "mcp:mealie")
	deviceForm.Set("resource", "https://mcp.example.com/mealie/mcp")
	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(deviceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	var deviceResponse deviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &deviceResponse))

	devicePage := httptest.NewRequest(http.MethodGet, "/oauth/device?user_code="+url.QueryEscape(deviceResponse.UserCode), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, devicePage)
	require.Equal(t, http.StatusFound, res.Code)

	loginRedirect, err := url.Parse(res.Header().Get("Location"))
	require.NoError(t, err)
	callbackRequest := httptest.NewRequest(http.MethodGet, loginRedirect.String(), nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, callbackRequest)
	require.Equal(t, http.StatusFound, res.Code)
	require.NotEmpty(t, res.Result().Cookies())
	sessionCookie := res.Result().Cookies()[0]

	devicePage = httptest.NewRequest(http.MethodGet, res.Header().Get("Location"), nil)
	devicePage.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, devicePage)
	require.Equal(t, http.StatusOK, res.Code)
	csrfToken := extractDeviceCSRFToken(t, res.Body.String())

	denyForm := url.Values{}
	denyForm.Set("user_code", deviceResponse.UserCode)
	denyForm.Set("action", "deny")
	denyRequest := httptest.NewRequest(http.MethodPost, "/oauth/device", strings.NewReader(denyForm.Encode()))
	denyRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denyRequest.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, denyRequest)
	require.Equal(t, http.StatusForbidden, res.Code)
	require.Contains(t, res.Body.String(), "invalid_csrf_token")

	deviceRecord, ok, err := server.stateStore.GetDeviceAuthorizationByDeviceCode(context.Background(), deviceResponse.DeviceCode)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, deviceAuthorizationStatusPending, deviceRecord.Status)

	denyForm.Set("csrf_token", csrfToken)
	denyRequest = httptest.NewRequest(http.MethodPost, "/oauth/device", strings.NewReader(denyForm.Encode()))
	denyRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	denyRequest.AddCookie(sessionCookie)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, denyRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), "denied")

	tokenForm := url.Values{"grant_type": {oauthGrantDeviceCode}, "device_code": {deviceResponse.DeviceCode}, "client_id": {registration.ClientID}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "access_denied")
}

func TestOAuthDeviceAuthorizationPendingPoll(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	registrationBody := `{"client_name":"headless-cli","grant_types":["` + oauthGrantDeviceCode + `"],"response_types":[],"token_endpoint_auth_method":"none","scope":"mcp:mealie"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))

	deviceForm := url.Values{"client_id": {registration.ClientID}, "scope": {"mcp:mealie"}, "resource": {"https://mcp.example.com/mealie/mcp"}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/device_authorization", strings.NewReader(deviceForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	var deviceResponse deviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &deviceResponse))

	tokenForm := url.Values{"grant_type": {oauthGrantDeviceCode}, "device_code": {deviceResponse.DeviceCode}, "client_id": {registration.ClientID}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "authorization_pending")

	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "slow_down")

	deviceRecord, ok, err := server.stateStore.GetDeviceAuthorizationByDeviceCode(context.Background(), deviceResponse.DeviceCode)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 10*time.Second, deviceRecord.Interval)
}

func TestOAuthOperatorTokenMintIntrospectAndRevoke(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	server := newTestEdgeServer(t, urlResolver{targets: map[string]string{"mealie": upstream.URL}})
	handler := server.Handler()
	require.NoError(t, server.stateStore.UpsertSubject(context.Background(), IdentityClaims{Sub: "fixture-user", Groups: []string{"mcp-users", "mcp-service-mealie"}}))

	body := `{"subject_sub":"fixture-user","scope":"mcp:mealie","expires_in_seconds":900,"reason":"nightly automation"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/operator-tokens", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "operator bearer token is required")

	req = httptest.NewRequest(http.MethodPost, "/oauth/operator-tokens", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	var minted operatorTokenResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &minted))
	require.NotEmpty(t, minted.AccessToken)
	require.NotEmpty(t, minted.SessionID)
	require.Equal(t, int64(900), minted.ExpiresIn)
	require.Equal(t, "mcp:mealie", minted.Scope)
	require.Equal(t, "https://mcp.example.com/mealie/mcp", minted.Resource)
	require.Equal(t, oauthSessionIssuedViaOperator, minted.IssuedVia)

	introspectionForm := url.Values{"token": {minted.AccessToken}}
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	var introspection tokenIntrospectionResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, minted.SessionID, introspection.SessionID)
	require.Equal(t, operatorTokenMintClientID, introspection.ClientID)
	require.Equal(t, "fixture-user", introspection.Sub)
	require.Equal(t, "mcp:mealie", introspection.Scope)
	require.Equal(t, "https://mcp.example.com/mealie/mcp", introspection.Resource)
	require.Equal(t, oauthSessionIssuedViaOperator, introspection.IssuedVia)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+minted.AccessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)
	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())

	normalSessionID := ids.New()
	normalToken := models.NewToken()
	normalToken.SetClientID("normal-oauth-client")
	normalToken.SetUserID("fixture-user")
	normalToken.SetScope("mcp:mealie")
	normalToken.SetAccess("normal-access-token")
	normalToken.SetAccessCreateAt(time.Now().UTC())
	normalToken.SetAccessExpiresIn(time.Hour)
	setTokenInfoSessionID(normalToken, normalSessionID.String())
	setTokenInfoResource(normalToken, "https://mcp.example.com/mealie/mcp")
	setTokenInfoIssuedVia(normalToken, oauthSessionIssuedViaOAuth)
	require.NoError(t, server.stateStore.Create(context.Background(), normalToken))

	req = httptest.NewRequest(http.MethodDelete, "/oauth/operator-tokens/"+normalSessionID.String(), nil)
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)

	introspectionForm.Set("token", "normal-access-token")
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.True(t, introspection.Active)
	require.Equal(t, normalSessionID.String(), introspection.SessionID)
	require.Equal(t, oauthSessionIssuedViaOAuth, introspection.IssuedVia)
	introspectionForm.Set("token", minted.AccessToken)

	req = httptest.NewRequest(http.MethodDelete, "/oauth/operator-tokens/"+minted.SessionID, nil)
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNoContent, res.Code)

	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(introspectionForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &introspection))
	require.False(t, introspection.Active)
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
		"client_name":"example-client",
		"redirect_uris":["https://client.example.com/oauth/callback"],
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
			"&resource="+url.QueryEscape("https://mcp.example.com/mealie/mcp")+
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
	require.Equal(t, "https://client.example.com/oauth/callback", location.Scheme+"://"+location.Host+location.Path)

	authCode := location.Query().Get("code")
	require.NotEmpty(t, authCode)
	require.Equal(t, "test-state", location.Query().Get("state"))

	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", registration.RedirectURIs[0])
	tokenForm.Set("client_id", registration.ClientID)
	tokenForm.Set("resource", "https://mcp.example.com/mealie/mcp")
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
	require.Equal(t, "https://mcp.example.com/mealie/mcp", introspection.Resource)

	serviceRequest := httptest.NewRequest(http.MethodGet, "/mealie/mcp", nil)
	serviceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, serviceRequest)

	require.Equal(t, http.StatusOK, res.Code)
	require.JSONEq(t, `{"ok":true}`, res.Body.String())

	wrongServiceRequest := httptest.NewRequest(http.MethodGet, "/actualbudget/mcp", nil)
	wrongServiceRequest.Header.Set("Authorization", "Bearer "+accessToken)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, wrongServiceRequest)

	require.Equal(t, http.StatusForbidden, res.Code)
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `scope="mcp:actualbudget"`)
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/actualbudget"`)

	otherRegistrationBody := `{
		"client_name":"other-client",
		"redirect_uris":["https://other.example.com/oauth/callback"],
		"grant_types":["authorization_code","refresh_token"],
		"response_types":["code"],
		"token_endpoint_auth_method":"none",
		"scope":"mcp:mealie"
	}`
	req = httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(otherRegistrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusCreated, res.Code)
	var otherRegistration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &otherRegistration))

	store := server.stateStore.(*memoryEdgeStateStore)
	store.mu.RLock()
	issuedBeforeWrongRefresh := countAuditEvents(store.auditEvents, "oauth.token.issued", "issued")
	store.mu.RUnlock()

	wrongRefreshForm := url.Values{}
	wrongRefreshForm.Set("grant_type", "refresh_token")
	wrongRefreshForm.Set("refresh_token", refreshToken)
	wrongRefreshForm.Set("client_id", otherRegistration.ClientID)
	wrongRefreshForm.Set("resource", "https://mcp.example.com/mealie/mcp")
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(wrongRefreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.NotEqual(t, http.StatusOK, res.Code)
	store.mu.RLock()
	require.Equal(t, issuedBeforeWrongRefresh, countAuditEvents(store.auditEvents, "oauth.token.issued", "issued"))
	store.mu.RUnlock()

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refreshToken)
	refreshForm.Set("client_id", registration.ClientID)
	refreshForm.Set("resource", "https://mcp.example.com/mealie/mcp")

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

	store.mu.RLock()
	events := append([]edgeAuditEvent(nil), store.auditEvents...)
	store.mu.RUnlock()

	requireAuditEvent(t, events, "oauth.client.registered", "created")
	requireAuditEvent(t, events, "browser_login.started", "started")
	requireAuditEvent(t, events, "browser_login.completed", "completed")
	requireAuditEvent(t, events, "oauth.authorize.allowed", "allowed")
	requireAuditEvent(t, events, "oauth.token.issued", "issued")
	requireAuditEvent(t, events, "oauth.introspect", "active")
	requireAuditEvent(t, events, "oauth.introspect", "inactive")
	requireAuditEvent(t, events, "mcp.service.access.allowed", "allowed")
}

func countAuditEvents(events []edgeAuditEvent, eventType string, status string) int {
	count := 0
	for _, event := range events {
		if event.EventType == eventType && event.EventStatus == status {
			count++
		}
	}
	return count
}

func TestOAuthAuthorizeRejectsScopeOutsideClientRegistration(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	registrationBody := `{
		"client_name":"example-client",
		"redirect_uris":["https://client.example.com/oauth/callback"],
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

	subject := AuthenticatedSubject{Sub: "fixture-user", Groups: []string{"mcp-users", "mcp-service-actualbudget"}}
	require.NoError(t, server.stateStore.UpsertSubject(context.Background(), IdentityClaims{Sub: subject.Sub, Groups: subject.Groups}))
	authorizeRequest := httptest.NewRequest(
		http.MethodGet,
		"/oauth/authorize?response_type=code&client_id="+url.QueryEscape(registration.ClientID)+
			"&redirect_uri="+url.QueryEscape(registration.RedirectURIs[0])+
			"&scope="+url.QueryEscape("mcp:actualbudget")+
			"&resource="+url.QueryEscape("https://mcp.example.com/actualbudget/mcp")+
			"&state="+url.QueryEscape("test-state")+
			"&code_challenge="+url.QueryEscape("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")+
			"&code_challenge_method=S256",
		nil,
	)
	authorizeRequest = authorizeRequest.WithContext(WithAuthenticatedSubject(authorizeRequest.Context(), subject))
	res = httptest.NewRecorder()
	server.oauth.handleAuthorize(res, authorizeRequest)

	require.Equal(t, http.StatusForbidden, res.Code)
	require.Contains(t, res.Body.String(), "invalid_scope")

	store := server.stateStore.(*memoryEdgeStateStore)
	store.mu.RLock()
	events := append([]edgeAuditEvent(nil), store.auditEvents...)
	store.mu.RUnlock()
	foundDenied := false
	for _, event := range events {
		if event.EventType == "oauth.authorize.denied" && event.EventStatus == "invalid_scope" {
			foundDenied = true
		}
		require.False(t, event.EventType == "oauth.authorize.allowed" && event.EventStatus == "allowed")
	}
	require.True(t, foundDenied)
}

func requireAuditEvent(t *testing.T, events []edgeAuditEvent, eventType string, status string) {
	t.Helper()
	for _, event := range events {
		if event.EventType == eventType && event.EventStatus == status {
			require.NotEmpty(t, event.CorrelationID)
			return
		}
	}
	require.Failf(t, "missing audit event", "event_type=%s status=%s events=%+v", eventType, status, events)
}

func extractDeviceCSRFToken(t *testing.T, body string) string {
	t.Helper()
	matches := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindStringSubmatch(body)
	require.Len(t, matches, 2)
	return matches[1]
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
	require.Contains(t, res.Body.String(), "unsupported token endpoint auth method")
}

func TestOAuthRegistrationRequiresOperatorBearerToken(t *testing.T) {
	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{
		"client_name":"example-client",
		"redirect_uris":["https://client.example.com/oauth/callback"]
	}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "operator bearer token is required")
}

func TestOAuthRegistrationAllowsPublicDCRWhenEnabled(t *testing.T) {
	cfg := testEdgeConfig()
	cfg.DCREnabled = true
	server, err := NewServer(cfg, zerolog.New(httptest.NewRecorder()), staticResolver{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(`{
		"client_name":"example-client",
		"redirect_uris":["https://client.example.com/oauth/callback","https://client.example.com/alternate"],
		"scope":"mcp:mealie"
	}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	require.Equal(t, http.StatusCreated, res.Code)
	var registration clientRegistrationResponse
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &registration))
	require.Len(t, registration.RedirectURIs, 2)
	require.Equal(t, "none", registration.TokenEndpointAuthMethod)
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
		testEdgeConfig(),
		zerolog.New(httptest.NewRecorder()),
		resolver,
	)
	require.NoError(t, err)
	return server
}
