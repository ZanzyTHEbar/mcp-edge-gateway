package edge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/ids"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	oauth2server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/rs/zerolog"
)

const (
	tokenEndpointAuthMethodNone        = "none"
	tokenEndpointAuthMethodClientPost  = "client_secret_post"
	tokenEndpointAuthMethodClientBasic = "client_secret_basic"

	oauthGrantAuthorizationCode = "authorization_code"
	oauthGrantRefreshToken      = "refresh_token"
	oauthGrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	operatorTokenMintClientID   = "mcp-edge-operator-token-mint"
	operatorTokenMaxTTL         = 30 * 24 * time.Hour
	operatorTokenReasonMaxLen   = 1024
)

type OAuthService struct {
	logger        zerolog.Logger
	publicBaseURL string
	operatorToken string
	catalog       *CatalogCache
	grants        GrantAuthorizer
	browserAuth   *AuthRuntime
	stateStore    edgeStateStore
	manager       *manage.Manager
	server        *oauth2server.Server
	dcrEnabled    bool
	cimdEnabled   bool
}

type registeredClient struct {
	ID                      string
	Secret                  string
	Name                    string
	RedirectURIs            []string
	GrantTypes              []string
	ResponseTypes           []string
	TokenEndpointAuthMethod string
	Scopes                  []string
	CreatedAt               time.Time
}

type clientRegistrationRequest struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type clientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
}

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

type tokenIntrospectionResponse struct {
	Active    bool   `json:"active"`
	SessionID string `json:"session_id,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Resource  string `json:"resource,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	IssuedVia string `json:"issued_via,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
}

type operatorTokenRequest struct {
	SubjectSub       string `json:"subject_sub"`
	Scope            string `json:"scope"`
	Resource         string `json:"resource"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
	Reason           string `json:"reason"`
}

type operatorTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
	Resource    string `json:"resource"`
	SessionID   string `json:"session_id"`
	IssuedVia   string `json:"issued_via"`
}

type refreshClientIDContextKey struct{}
type expectedResourceContextKey struct{}

func NewOAuthService(cfg Config, logger zerolog.Logger, catalogCache *CatalogCache, stateStore edgeStateStore, grants GrantAuthorizer, browserAuth *AuthRuntime) (*OAuthService, error) {
	if stateStore == nil {
		return nil, fmt.Errorf("edge oauth state store is required")
	}
	if catalogCache == nil {
		return nil, fmt.Errorf("edge oauth catalog cache is required")
	}
	operatorToken, err := resolveConfiguredSecret(cfg.OperatorTokenPath, cfg.FixtureOperatorToken)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(operatorToken) == "" {
		return nil, fmt.Errorf("mcp-edge operator token is required to protect registration and introspection endpoints")
	}
	publicBaseURL := strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	manager := manage.NewDefaultManager()
	manager.MapTokenStorage(stateStore)
	manager.MapClientStorage(stateStore)
	manager.SetExtractExtensionHandler(func(tgr *oauth2.TokenGenerateRequest, ti oauth2.ExtendableTokenInfo) {
		resource := ""
		if tgr.Request != nil {
			resource = tgr.Request.FormValue("resource")
		}
		if strings.TrimSpace(resource) == "" && tokenInfoResource(ti) == "" {
			if serviceID, err := singleServiceFromScope(tgr.Scope); err == nil {
				if service, ok := catalogCache.ServiceByID(serviceID); ok {
					resource = publicBaseURL + service.PublicPath
				}
			}
		}
		setTokenInfoResource(ti, resource)
	})
	manager.SetValidateURIHandler(func(baseURI, redirectURI string) error {
		redirectURI = strings.TrimSpace(redirectURI)
		for _, registeredURI := range strings.Split(baseURI, "\n") {
			if strings.TrimSpace(registeredURI) == redirectURI {
				return nil
			}
		}
		return oauth2errors.ErrInvalidRedirectURI
	})
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.SetRefreshTokenCfg(manage.DefaultRefreshTokenCfg)

	srv := oauth2server.NewServer(newOAuthServerConfig(), manager)
	srv.SetClientInfoHandler(resolveClientCredentials)
	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		subject, ok := SubjectFromContext(r.Context())
		if !ok || strings.TrimSpace(subject.Sub) == "" {
			return "", oauth2errors.ErrAccessDenied
		}
		return subject.Sub, nil
	})
	srv.SetClientScopeHandler(func(tgr *oauth2.TokenGenerateRequest) (bool, error) {
		if !scopeStringAllowed(tgr.Scope, catalogCache.Scopes()) {
			return false, nil
		}
		lookupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		clientInfo, err := stateStore.GetByID(lookupCtx, tgr.ClientID)
		if err != nil {
			return false, err
		}
		return clientAllowsScope(clientInfo, tgr.Scope), nil
	})

	return &OAuthService{
		logger:        logger,
		publicBaseURL: publicBaseURL,
		operatorToken: operatorToken,
		catalog:       catalogCache,
		grants:        grants,
		browserAuth:   browserAuth,
		stateStore:    stateStore,
		manager:       manager,
		server:        srv,
		dcrEnabled:    cfg.DCREnabled,
		cimdEnabled:   cfg.CIMDEnabled,
	}, nil
}

func (o *OAuthService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", o.handleAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server/", o.handleAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", o.handleAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", o.handleProtectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", o.handleProtectedResourceMetadata)
	mux.HandleFunc("/oauth/register", o.handleClientRegistration)
	mux.HandleFunc("/oauth/register/", o.handleClientRegistration)
	mux.HandleFunc("/oauth/authorize", o.handleAuthorize)
	mux.HandleFunc("/oauth/authorize/", o.handleAuthorize)
	mux.HandleFunc("/oauth/device_authorization", o.handleDeviceAuthorization)
	mux.HandleFunc("/oauth/device_authorization/", o.handleDeviceAuthorization)
	mux.HandleFunc("/oauth/device", o.handleDeviceVerification)
	mux.HandleFunc("/oauth/token", o.handleToken)
	mux.HandleFunc("/oauth/introspect", o.handleIntrospect)
	mux.HandleFunc("/oauth/operator-tokens", o.handleOperatorTokens)
	mux.HandleFunc("/oauth/operator-tokens/", o.handleOperatorToken)
}

func (o *OAuthService) ValidateBearerToken(r *http.Request) (oauth2.TokenInfo, error) {
	return o.server.ValidationBearerToken(r)
}

func (o *OAuthService) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "metadata requires GET")
		return
	}
	serviceID, serviceScoped, err := o.serviceIDFromWellKnownPath(r.URL.Path)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
		return
	}

	issuer := o.publicBaseURL
	authorizationEndpoint := o.publicBaseURL + "/oauth/authorize"
	deviceAuthorizationEndpoint := o.publicBaseURL + "/oauth/device_authorization"
	registrationEndpoint := o.publicBaseURL + "/oauth/register"
	scopes := o.catalog.Scopes()
	if serviceScoped {
		issuer = o.serviceIssuer(serviceID)
		authorizationEndpoint = o.publicBaseURL + "/oauth/authorize/" + serviceID
		deviceAuthorizationEndpoint = o.publicBaseURL + "/oauth/device_authorization/" + serviceID
		registrationEndpoint = o.publicBaseURL + "/oauth/register/" + serviceID
		scopes = []string{"mcp:" + serviceID}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                authorizationEndpoint,
		"device_authorization_endpoint":         deviceAuthorizationEndpoint,
		"token_endpoint":                        o.publicBaseURL + "/oauth/token",
		"registration_endpoint":                 registrationEndpoint,
		"introspection_endpoint":                o.publicBaseURL + "/oauth/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{oauthGrantAuthorizationCode, oauthGrantRefreshToken, oauthGrantDeviceCode},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{tokenEndpointAuthMethodNone, tokenEndpointAuthMethodClientPost, tokenEndpointAuthMethodClientBasic},
		"scopes_supported":                      scopes,
		"resource_indicators_supported":         true,
		"client_id_metadata_document_supported": true,
		"dynamic_client_registration_supported": o.dcrEnabled,
	})
}

func (o *OAuthService) serviceIDFromWellKnownPath(path string) (string, bool, error) {
	if path == "/.well-known/openid-configuration" {
		return "", false, nil
	}
	return o.serviceIDFromPath(path, "/.well-known/oauth-authorization-server")
}

func (o *OAuthService) serviceIDFromPath(path string, prefix string) (string, bool, error) {
	if path == prefix {
		return "", false, nil
	}
	if !strings.HasPrefix(path, prefix+"/") {
		return "", false, fmt.Errorf("unsupported service-scoped path")
	}
	serviceID := strings.TrimPrefix(path, prefix+"/")
	if serviceID == "" || strings.Contains(serviceID, "/") {
		return "", true, fmt.Errorf("requested service is not registered")
	}
	if _, ok := o.catalog.ServiceByID(serviceID); !ok {
		return "", true, fmt.Errorf("requested service is not registered")
	}
	return serviceID, true, nil
}

func (o *OAuthService) serviceIssuer(serviceID string) string {
	return o.publicBaseURL + "/" + strings.Trim(strings.TrimSpace(serviceID), "/")
}

func (o *OAuthService) narrowRequestScopeToService(r *http.Request, serviceID string) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("unable to parse request parameters")
	}
	scope, err := o.scopeForServiceContext(r.Form.Get("scope"), serviceID)
	if err != nil {
		return err
	}
	setRequestFormValue(r, "scope", scope)
	return nil
}

func (o *OAuthService) scopeForServiceContext(scope string, serviceID string) (string, error) {
	serviceScope := "mcp:" + serviceID
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return serviceScope, nil
	}
	if !scopeStringAllowed(scope, o.catalog.Scopes()) {
		return "", fmt.Errorf("requested scopes are not supported")
	}
	if !scopeIncludesService(scope, serviceID) {
		return "", fmt.Errorf("requested scope must include the service scope")
	}
	// Service-scoped endpoints intentionally collapse broad catalog scope sets to
	// the one service scope for this issuer/resource, preserving one-resource tokens.
	return serviceScope, nil
}

func (o *OAuthService) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "device authorization requires POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "unable to parse request parameters")
		return
	}
	serviceID, serviceScoped, err := o.serviceIDFromPath(r.URL.Path, "/oauth/device_authorization")
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
		return
	}
	if serviceScoped {
		if err := o.narrowRequestScopeToService(r, serviceID); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_scope", err.Error())
			return
		}
	}
	clientID, clientSecret, err := resolveClientCredentials(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), clientID)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !verifyClientSecretForTokenRequest(clientInfo, clientSecret) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !clientAllowsGrant(clientInfo, oauthGrantDeviceCode) {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for device_code grant")
		return
	}
	scope := strings.TrimSpace(r.Form.Get("scope"))
	if scope == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", "exactly one mcp:<service> scope is required")
		return
	}
	if !scopeStringAllowed(scope, o.catalog.Scopes()) || !clientAllowsScope(clientInfo, scope) {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not supported")
		return
	}
	serviceID, err = singleServiceFromScope(scope)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	resource, err := o.validateResourceIndicator(r, scope)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", err.Error())
		return
	}
	deviceCode, err := randomToken(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "device_code_generation_failed", "unable to issue device code")
		return
	}
	userCode, err := generateUserCode()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "user_code_generation_failed", "unable to issue user code")
		return
	}
	now := time.Now().UTC()
	ttl := 10 * time.Minute
	interval := 5 * time.Second
	record := deviceAuthorization{
		ID:              ids.New(),
		ClientID:        clientID,
		ServiceID:       serviceID,
		Resource:        resource,
		Scope:           scope,
		DeviceCodeHash:  hashOpaqueValue(deviceCode),
		UserCodeHash:    hashOpaqueValue(normalizeUserCode(userCode)),
		UserCodeDisplay: userCode,
		Interval:        interval,
		ExpiresAt:       now.Add(ttl),
		CreatedAt:       now,
	}
	if err := o.stateStore.CreateDeviceAuthorization(r.Context(), record); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "device_authorization_store_failed", "unable to persist device authorization")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{EventType: "oauth.device.created", EventStatus: "created", ServiceID: serviceID, Payload: map[string]any{"client_id": clientID, "scope": scope, "resource": resource}})
	verificationURI := o.publicBaseURL + "/oauth/device"
	writeJSON(w, http.StatusOK, deviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + url.QueryEscape(userCode),
		ExpiresIn:               int64(ttl / time.Second),
		Interval:                int64(interval / time.Second),
	})
}

func (o *OAuthService) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "metadata requires GET")
		return
	}

	serviceID := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource/")
	if serviceID != r.URL.Path {
		serviceID = strings.Trim(serviceID, "/")
		service, ok := o.catalog.ServiceByID(serviceID)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
			return
		}
		o.writeProtectedResourceMetadata(w, o.publicBaseURL+service.PublicPath, []string{"mcp:" + service.ServiceID}, service.DisplayName, []string{o.serviceIssuer(service.ServiceID)})
		return
	}

	o.writeProtectedResourceMetadata(w, o.publicBaseURL, o.catalog.Scopes(), "mcp-edge", []string{o.publicBaseURL})
}

func (o *OAuthService) writeProtectedResourceMetadata(w http.ResponseWriter, resource string, scopes []string, resourceName string, authorizationServers []string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                              resource,
		"authorization_servers":                 authorizationServers,
		"scopes_supported":                      scopes,
		"bearer_methods_supported":              []string{"header"},
		"resource_documentation":                o.publicBaseURL + "/health",
		"resource_name":                         resourceName,
		"authorization_details_types_supported": []string{},
	})
}

func (o *OAuthService) handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "client registration requires POST")
		return
	}
	serviceID, serviceScoped, err := o.serviceIDFromPath(r.URL.Path, "/oauth/register")
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
		return
	}
	if !o.dcrEnabled && !o.requireOperatorToken(w, r) {
		return
	}

	var req clientRegistrationRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	allowedScopes := o.catalog.Scopes()
	if serviceScoped {
		scope, err := o.scopeForServiceContext(req.Scope, serviceID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
			return
		}
		req.Scope = scope
		allowedScopes = []string{scope}
	}

	record, err := normalizeClientRegistration(req, allowedScopes)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}

	clientID := ids.New().String()
	clientSecret := ""
	if record.TokenEndpointAuthMethod != tokenEndpointAuthMethodNone {
		clientSecret, err = generateClientSecret()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "secret_generation_failed", "unable to issue client secret")
			return
		}
	}
	record.ID = clientID
	record.Secret = clientSecret
	record.CreatedAt = time.Now().UTC()
	createdBySubject := ""
	if subject, ok := SubjectFromContext(r.Context()); ok {
		createdBySubject = subject.Sub
	}
	if err := o.stateStore.CreateClient(r.Context(), record, createdBySubject); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "client_store_failed", "unable to persist client registration")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{
		ActorSubjectSub: createdBySubject,
		EventType:       "oauth.client.registered",
		EventStatus:     "created",
		Payload: map[string]any{
			"client_id":                  record.ID,
			"token_endpoint_auth_method": record.TokenEndpointAuthMethod,
			"scopes":                     record.Scopes,
		},
	})
	response := clientRegistrationResponse{
		ClientID:                record.ID,
		ClientIDIssuedAt:        record.CreatedAt.Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              record.Name,
		RedirectURIs:            append([]string(nil), record.RedirectURIs...),
		GrantTypes:              append([]string(nil), record.GrantTypes...),
		ResponseTypes:           append([]string(nil), record.ResponseTypes...),
		TokenEndpointAuthMethod: record.TokenEndpointAuthMethod,
		Scope:                   strings.Join(record.Scopes, " "),
	}
	if record.Secret != "" {
		response.ClientSecret = record.Secret
	}

	writeJSON(w, http.StatusCreated, response)
}

func (o *OAuthService) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "authorize supports GET and POST")
		return
	}
	serviceID, serviceScoped, err := o.serviceIDFromPath(r.URL.Path, "/oauth/authorize")
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
		return
	}
	if serviceScoped {
		if err := o.narrowRequestScopeToService(r, serviceID); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_scope", err.Error())
			return
		}
	}

	subject, ok := SubjectFromContext(r.Context())
	if !ok {
		if o.browserAuth != nil {
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusUnauthorized, "login_required", "browser login continuation is only supported for GET authorize requests")
				return
			}
			o.browserAuth.BeginBrowserLogin(w, r, r.URL.String())
			return
		}
		writeJSONError(w, http.StatusUnauthorized, "login_required", "browser authentication is required before authorization")
		return
	}
	if strings.TrimSpace(r.FormValue("scope")) == "" {
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: subject.Sub,
			EventType:       "oauth.authorize.denied",
			EventStatus:     "invalid_scope",
		})
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", "at least one mcp:<service> scope is required")
		return
	}
	resource, err := o.validateResourceIndicator(r, r.FormValue("scope"))
	if err != nil {
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: subject.Sub,
			EventType:       "oauth.authorize.denied",
			EventStatus:     "invalid_resource",
		})
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", err.Error())
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), expectedResourceContextKey{}, resource))
	if o.grants != nil {
		allowed, err := o.grants.AllowedScopes(r.Context(), subject.Sub, r.FormValue("scope"))
		if err != nil {
			o.logger.Error().Err(err).Str("subject_sub", subject.Sub).Msg("scope authorization lookup failed")
			o.recordAuditEvent(r.Context(), edgeAuditEvent{
				ActorSubjectSub: subject.Sub,
				EventType:       "oauth.authorize.denied",
				EventStatus:     "authorization_unavailable",
			})
			writeJSONError(w, http.StatusServiceUnavailable, "authorization_unavailable", "unable to validate subject service grants")
			return
		}
		if !allowed {
			o.recordAuditEvent(r.Context(), edgeAuditEvent{
				ActorSubjectSub: subject.Sub,
				EventType:       "oauth.authorize.denied",
				EventStatus:     "service_not_granted",
				Payload: map[string]any{
					"scope": r.FormValue("scope"),
				},
			})
			writeJSONError(w, http.StatusForbidden, "service_not_granted", "requested scope is not granted for this subject")
			return
		}
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), r.FormValue("client_id"))
	if err != nil && o.cimdEnabled {
		clientInfo, err = o.registerClientMetadataDocument(r.Context(), r.FormValue("client_id"))
	}
	if err != nil {
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: subject.Sub,
			EventType:       "oauth.authorize.denied",
			EventStatus:     "invalid_client",
			Payload: map[string]any{
				"client_id": r.FormValue("client_id"),
				"scope":     r.FormValue("scope"),
			},
		})
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "OAuth client is not registered or is disabled")
		return
	}
	if !clientAllowsGrant(clientInfo, oauthGrantAuthorizationCode) {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for authorization_code grant")
		return
	}
	if !clientAllowsScope(clientInfo, r.FormValue("scope")) {
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: subject.Sub,
			EventType:       "oauth.authorize.denied",
			EventStatus:     "invalid_scope",
			Payload: map[string]any{
				"client_id": r.FormValue("client_id"),
				"scope":     r.FormValue("scope"),
			},
		})
		writeJSONError(w, http.StatusForbidden, "invalid_scope", "requested scope is not registered for this OAuth client")
		return
	}
	if err := o.server.HandleAuthorizeRequest(w, r); err != nil {
		o.logger.Error().Err(err).Msg("oauth authorize request failed")
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: subject.Sub,
			EventType:       "oauth.authorize.denied",
			EventStatus:     "oauth_server_rejected",
			Payload: map[string]any{
				"client_id": r.FormValue("client_id"),
				"scope":     r.FormValue("scope"),
			},
		})
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{
		ActorSubjectSub: subject.Sub,
		EventType:       "oauth.authorize.allowed",
		EventStatus:     "allowed",
		Payload: map[string]any{
			"client_id": r.FormValue("client_id"),
			"scope":     r.FormValue("scope"),
		},
	})
}

func (o *OAuthService) handleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "device verification supports GET and POST")
		return
	}
	if r.Method == http.MethodGet {
		o.handleDeviceVerificationGet(w, r)
		return
	}
	o.handleDeviceVerificationPost(w, r)
}

func (o *OAuthService) handleDeviceVerificationGet(w http.ResponseWriter, r *http.Request) {
	if _, ok := SubjectFromContext(r.Context()); !ok {
		if o.browserAuth != nil {
			o.browserAuth.BeginBrowserLogin(w, r, r.URL.String())
			return
		}
		writeJSONError(w, http.StatusUnauthorized, "login_required", "browser authentication is required before device approval")
		return
	}
	userCode := strings.TrimSpace(r.URL.Query().Get("user_code"))
	if userCode == "" {
		o.renderDeviceCodeEntry(w, "")
		return
	}
	record, ok, err := o.stateStore.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "device_authorization_unavailable", "unable to load device authorization")
		return
	}
	if !ok || record.Status != deviceAuthorizationStatusPending || !time.Now().UTC().Before(record.ExpiresAt) {
		o.renderDeviceCodeEntry(w, "Device code is invalid or expired.")
		return
	}
	o.renderDeviceApproval(w, r, record, "")
}

func (o *OAuthService) handleDeviceVerificationPost(w http.ResponseWriter, r *http.Request) {
	subject, ok := SubjectFromContext(r.Context())
	if !ok || strings.TrimSpace(subject.Sub) == "" {
		writeJSONError(w, http.StatusUnauthorized, "login_required", "browser authentication is required before device approval")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "unable to parse device approval form")
		return
	}
	action := strings.TrimSpace(r.Form.Get("action"))
	userCode := strings.TrimSpace(r.Form.Get("user_code"))
	record, ok, err := o.stateStore.GetDeviceAuthorizationByUserCode(r.Context(), userCode)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "device_authorization_unavailable", "unable to load device authorization")
		return
	}
	now := time.Now().UTC()
	if !ok || record.Status != deviceAuthorizationStatusPending || !now.Before(record.ExpiresAt) {
		o.renderDeviceCodeEntry(w, "Device code is invalid or expired.")
		return
	}
	if action != "approve" && action != "deny" {
		o.renderDeviceApproval(w, r, record, "Choose approve or deny.")
		return
	}
	if !validDeviceCSRFToken(r, record) {
		writeJSONError(w, http.StatusForbidden, "invalid_csrf_token", "device approval form token is invalid")
		return
	}
	if action == "deny" {
		denied, err := o.stateStore.DenyDeviceAuthorization(r.Context(), record.ID, now)
		if err != nil || !denied {
			writeJSONError(w, http.StatusConflict, "device_authorization_not_pending", "device authorization could not be denied")
			return
		}
		o.recordAuditEvent(r.Context(), edgeAuditEvent{ActorSubjectSub: subject.Sub, ServiceID: record.ServiceID, EventType: "oauth.device.denied", EventStatus: "denied", Payload: map[string]any{"client_id": record.ClientID}})
		o.renderDeviceDone(w, "Device request denied. You can return to the device.")
		return
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), record.ClientID)
	if err != nil || !clientAllowsGrant(clientInfo, oauthGrantDeviceCode) || !clientAllowsScope(clientInfo, record.Scope) {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is no longer authorized for this device request")
		return
	}
	service, ok := o.catalog.ServiceByID(record.ServiceID)
	if !ok || record.Resource != o.publicBaseURL+service.PublicPath {
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", "device authorization resource is no longer valid")
		return
	}
	if o.grants != nil {
		allowed, err := o.grants.AllowedScopes(r.Context(), subject.Sub, record.Scope)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authorization_unavailable", "unable to validate subject service grants")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, "service_not_granted", "requested scope is not granted for this subject")
			return
		}
	}
	if err := o.stateStore.UpsertSubject(r.Context(), IdentityClaims{Sub: subject.Sub, Email: subject.Email, Name: subject.DisplayName, PreferredUsername: subject.PreferredUsername, Groups: subject.Groups}); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "subject_sync_failed", "unable to persist subject identity")
		return
	}
	approved, err := o.stateStore.ApproveDeviceAuthorization(r.Context(), record.ID, subject.Sub, now)
	if err != nil || !approved {
		writeJSONError(w, http.StatusConflict, "device_authorization_not_pending", "device authorization could not be approved")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{ActorSubjectSub: subject.Sub, ServiceID: record.ServiceID, EventType: "oauth.device.approved", EventStatus: "approved", Payload: map[string]any{"client_id": record.ClientID, "scope": record.Scope, "resource": record.Resource}})
	o.renderDeviceDone(w, "Device request approved. You can return to the device.")
}

func (o *OAuthService) renderDeviceCodeEntry(w http.ResponseWriter, message string) {
	setDeviceHTMLHeaders(w)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><body><main><h1>MCP Device Authorization</h1><p>%s</p><form method="get" action="/oauth/device"><label>User code <input name="user_code" autocomplete="one-time-code" autofocus></label><button type="submit">Continue</button></form></main></body></html>`, html.EscapeString(message))
}

func (o *OAuthService) renderDeviceApproval(w http.ResponseWriter, r *http.Request, record deviceAuthorization, message string) {
	setDeviceHTMLHeaders(w)
	serviceName := record.ServiceID
	if service, ok := o.catalog.ServiceByID(record.ServiceID); ok {
		serviceName = service.DisplayName
	}
	csrfToken := deviceCSRFToken(r, record)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><body><main><h1>Approve MCP Device?</h1><p>%s</p><dl><dt>Client</dt><dd>%s</dd><dt>Service</dt><dd>%s</dd><dt>Scope</dt><dd>%s</dd><dt>Resource</dt><dd>%s</dd><dt>User code</dt><dd>%s</dd></dl><form method="post" action="/oauth/device"><input type="hidden" name="user_code" value="%s"><input type="hidden" name="csrf_token" value="%s"><button type="submit" name="action" value="approve">Approve</button><button type="submit" name="action" value="deny">Deny</button></form></main></body></html>`, html.EscapeString(message), html.EscapeString(record.ClientID), html.EscapeString(serviceName), html.EscapeString(record.Scope), html.EscapeString(record.Resource), html.EscapeString(record.UserCodeDisplay), html.EscapeString(record.UserCodeDisplay), html.EscapeString(csrfToken))
}

func (o *OAuthService) renderDeviceDone(w http.ResponseWriter, message string) {
	setDeviceHTMLHeaders(w)
	_, _ = fmt.Fprintf(w, `<!doctype html><html><body><main><h1>MCP Device Authorization</h1><p>%s</p></main></body></html>`, html.EscapeString(message))
}

func setDeviceHTMLHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
}

func deviceCSRFToken(r *http.Request, record deviceAuthorization) string {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil {
		return ""
	}
	return hashOpaqueValue(cookie.Value + "|" + record.ID.String())
}

func validDeviceCSRFToken(r *http.Request, record deviceAuthorization) bool {
	expected := deviceCSRFToken(r, record)
	provided := strings.TrimSpace(r.Form.Get("csrf_token"))
	return expected != "" && provided != "" && subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) == 1
}

func (o *OAuthService) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "token exchange requires POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "unable to parse request parameters")
		return
	}
	if r.Form.Get("grant_type") == oauthGrantDeviceCode {
		o.handleDeviceToken(w, r)
		return
	}
	resource, err := o.validateTokenResourceIndicator(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", err.Error())
		return
	}
	refreshClientID, err := o.prevalidateRefreshClient(r)
	if err != nil {
		o.logger.Warn().Err(err).Msg("refresh token client prevalidation failed")
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if refreshClientID != "" {
		r = r.WithContext(context.WithValue(r.Context(), refreshClientIDContextKey{}, refreshClientID))
	}
	if err := o.validateClientGrantType(r, refreshClientID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", err.Error())
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), expectedResourceContextKey{}, resource))
	auditClientID := refreshClientID
	if auditClientID == "" {
		if clientID, _, err := resolveClientCredentials(r); err == nil {
			auditClientID = clientID
		}
	}

	tracker := &statusTrackingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	if err := o.server.HandleTokenRequest(tracker, r); err != nil {
		o.logger.Error().Err(err).Msg("oauth token request failed")
		return
	}
	if tracker.statusCode < http.StatusOK || tracker.statusCode >= http.StatusMultipleChoices {
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{
		EventType:   "oauth.token.issued",
		EventStatus: "issued",
		Payload: map[string]any{
			"client_id":  auditClientID,
			"grant_type": r.FormValue("grant_type"),
			"resource":   resource,
		},
	})
}

func (o *OAuthService) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := resolveClientCredentials(r)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), clientID)
	if err != nil || !verifyClientSecretForTokenRequest(clientInfo, clientSecret) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if !clientAllowsGrant(clientInfo, oauthGrantDeviceCode) {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for device_code grant")
		return
	}
	deviceCode := strings.TrimSpace(r.Form.Get("device_code"))
	if deviceCode == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}
	record, ok, err := o.stateStore.GetDeviceAuthorizationByDeviceCode(r.Context(), deviceCode)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "unable to load device authorization")
		return
	}
	if !ok || record.ClientID != clientID {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "device_code is invalid")
		return
	}
	now := time.Now().UTC()
	if !now.Before(record.ExpiresAt) || record.Status == deviceAuthorizationStatusExpired {
		_, _ = o.stateStore.MarkExpiredDeviceAuthorizations(r.Context(), now)
		writeJSONError(w, http.StatusBadRequest, "expired_token", "device_code has expired")
		return
	}
	if record.LastPollAt != nil && now.Sub(*record.LastPollAt) < record.Interval {
		_, _ = o.stateStore.SlowDownDeviceAuthorizationPoll(r.Context(), record.ID, now, 5*time.Second)
		writeJSONError(w, http.StatusBadRequest, "slow_down", "device authorization polling is too frequent")
		return
	}
	_, _ = o.stateStore.UpdateDeviceAuthorizationPoll(r.Context(), record.ID, now)
	switch record.Status {
	case deviceAuthorizationStatusPending:
		writeJSONError(w, http.StatusBadRequest, "authorization_pending", "device authorization is pending")
		return
	case deviceAuthorizationStatusDenied:
		writeJSONError(w, http.StatusBadRequest, "access_denied", "device authorization was denied")
		return
	case deviceAuthorizationStatusConsumed:
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "device_code has already been consumed")
		return
	case deviceAuthorizationStatusApproved:
	default:
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "device_code is invalid")
		return
	}
	if record.SubjectSub == nil || strings.TrimSpace(*record.SubjectSub) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "device authorization has no approving subject")
		return
	}
	if !clientAllowsScope(clientInfo, record.Scope) || !clientAllowsGrant(clientInfo, oauthGrantDeviceCode) {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is no longer authorized for this device grant")
		return
	}
	service, ok := o.catalog.ServiceByID(record.ServiceID)
	if !ok || record.Resource != o.publicBaseURL+service.PublicPath {
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", "device authorization resource is no longer valid")
		return
	}
	if o.grants != nil {
		allowed, err := o.grants.AllowedScopes(r.Context(), *record.SubjectSub, record.Scope)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authorization_unavailable", "unable to validate subject service grants")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, "service_not_granted", "requested scope is not granted for this subject")
			return
		}
	}
	accessToken, err := randomToken(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_generation_failed", "unable to issue access token")
		return
	}
	token := models.NewToken()
	token.SetClientID(clientID)
	token.SetUserID(*record.SubjectSub)
	token.SetScope(record.Scope)
	token.SetAccess(accessToken)
	token.SetAccessCreateAt(now)
	token.SetAccessExpiresIn(time.Hour)
	setTokenInfoResource(token, record.Resource)
	setTokenInfoIssuedVia(token, oauthGrantDeviceCode)
	var refreshToken string
	if clientAllowsGrant(clientInfo, oauthGrantRefreshToken) {
		refreshToken, err = randomToken(32)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "token_generation_failed", "unable to issue refresh token")
			return
		}
		token.SetRefresh(refreshToken)
		token.SetRefreshCreateAt(now)
		token.SetRefreshExpiresIn(24 * time.Hour)
	}
	consumed, err := o.stateStore.ConsumeDeviceAuthorizationAndCreateToken(r.Context(), record.ID, now, token)
	if err != nil || !consumed {
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "token_store_failed", "unable to persist device token")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "device_code could not be consumed")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{ActorSubjectSub: *record.SubjectSub, ServiceID: record.ServiceID, EventType: "oauth.device.token_issued", EventStatus: "issued", Payload: map[string]any{"client_id": clientID, "scope": record.Scope, "resource": record.Resource}})
	response := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Hour / time.Second),
		"scope":        record.Scope,
		"resource":     record.Resource,
	}
	if refreshToken != "" {
		response["refresh_token"] = refreshToken
	}
	writeJSON(w, http.StatusOK, response)
}

type statusTrackingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusTrackingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (o *OAuthService) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "token introspection requires POST")
		return
	}
	if !o.requireOperatorToken(w, r) {
		return
	}

	token, err := resolveIntrospectionToken(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	ti, err := o.manager.LoadAccessToken(r.Context(), token)
	if err != nil {
		o.recordAuditEvent(r.Context(), edgeAuditEvent{
			EventType:   "oauth.introspect",
			EventStatus: "inactive",
		})
		writeJSON(w, http.StatusOK, tokenIntrospectionResponse{Active: false})
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{
		ActorSubjectSub: ti.GetUserID(),
		EventType:       "oauth.introspect",
		EventStatus:     "active",
		Payload: map[string]any{
			"client_id": ti.GetClientID(),
			"scope":     ti.GetScope(),
		},
	})

	writeJSON(w, http.StatusOK, tokenIntrospectionResponse{
		Active:    true,
		SessionID: tokenInfoSessionID(ti),
		ClientID:  ti.GetClientID(),
		Sub:       ti.GetUserID(),
		Scope:     ti.GetScope(),
		Resource:  tokenInfoResource(ti),
		TokenType: "Bearer",
		IssuedVia: tokenInfoIssuedVia(ti),
		Iat:       ti.GetAccessCreateAt().Unix(),
		Exp:       ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix(),
	})
}

func (o *OAuthService) handleOperatorTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "operator token minting requires POST")
		return
	}
	if !o.requireOperatorToken(w, r) {
		return
	}
	defer func() { _, _ = io.Copy(io.Discard, r.Body) }()
	var req operatorTokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "request body must be JSON")
		return
	}
	subjectSub := strings.TrimSpace(req.SubjectSub)
	if subjectSub == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_subject", "subject_sub is required")
		return
	}
	scope := strings.TrimSpace(req.Scope)
	if scope == "" || !scopeStringAllowed(scope, o.catalog.Scopes()) {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not supported")
		return
	}
	serviceID, err := singleServiceFromScope(scope)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	service, ok := o.catalog.ServiceByID(serviceID)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_scope", "requested service is not registered")
		return
	}
	resource := strings.TrimRight(strings.TrimSpace(req.Resource), "/")
	if resource == "" {
		resource = o.publicBaseURL + service.PublicPath
	}
	if resource != o.publicBaseURL+service.PublicPath {
		writeJSONError(w, http.StatusBadRequest, "invalid_resource", "resource must match the requested MCP service")
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > operatorTokenReasonMaxLen {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "reason is too long")
		return
	}
	if o.grants != nil {
		allowed, err := o.grants.AllowedScopes(r.Context(), subjectSub, scope)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "authorization_unavailable", "unable to validate subject service grants")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, "service_not_granted", "requested scope is not granted for this subject")
			return
		}
	}
	if err := o.ensureOperatorTokenClient(r.Context()); err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "operator_client_unavailable", "unable to prepare operator token client")
		return
	}
	expiresIn := time.Duration(req.ExpiresInSeconds) * time.Second
	if expiresIn <= 0 {
		expiresIn = time.Hour
	}
	if expiresIn > operatorTokenMaxTTL {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "expires_in_seconds exceeds operator token maximum")
		return
	}
	accessToken, err := randomToken(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_generation_failed", "unable to issue access token")
		return
	}
	now := time.Now().UTC()
	sessionID := ids.New().String()
	token := models.NewToken()
	token.SetClientID(operatorTokenMintClientID)
	token.SetUserID(subjectSub)
	token.SetScope(scope)
	token.SetAccess(accessToken)
	token.SetAccessCreateAt(now)
	token.SetAccessExpiresIn(expiresIn)
	setTokenInfoSessionID(token, sessionID)
	setTokenInfoResource(token, resource)
	setTokenInfoIssuedVia(token, oauthSessionIssuedViaOperator)
	setTokenInfoOperatorReason(token, reason)
	if err := o.stateStore.Create(r.Context(), token); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_store_failed", "unable to persist operator token")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{ActorSubjectSub: subjectSub, ServiceID: serviceID, EventType: "oauth.operator_token.issued", EventStatus: "issued", Payload: map[string]any{"client_id": operatorTokenMintClientID, "scope": scope, "resource": resource, "session_id": sessionID}})
	writeJSON(w, http.StatusCreated, operatorTokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(expiresIn / time.Second), Scope: scope, Resource: resource, SessionID: sessionID, IssuedVia: oauthSessionIssuedViaOperator})
}

func (o *OAuthService) handleOperatorToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "operator token revocation requires DELETE")
		return
	}
	if !o.requireOperatorToken(w, r) {
		return
	}
	sessionIDRaw := strings.TrimPrefix(r.URL.Path, "/oauth/operator-tokens/")
	if strings.Contains(sessionIDRaw, "/") || strings.TrimSpace(sessionIDRaw) == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "session_id path segment is required")
		return
	}
	sessionID, err := ids.Parse(sessionIDRaw)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_session_id", "session_id must be a UUID")
		return
	}
	deleted, err := o.stateStore.DeleteOperatorOAuthSessionByID(r.Context(), sessionID, operatorTokenMintClientID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "token_revoke_failed", "unable to revoke operator token")
		return
	}
	if !deleted {
		writeJSONError(w, http.StatusNotFound, "token_not_found", "operator token session was not found")
		return
	}
	o.recordAuditEvent(r.Context(), edgeAuditEvent{EventType: "oauth.operator_token.revoked", EventStatus: "revoked", Payload: map[string]any{"session_id": sessionID.String()}})
	w.WriteHeader(http.StatusNoContent)
}

func (o *OAuthService) ensureOperatorTokenClient(ctx context.Context) error {
	if _, err := o.stateStore.GetByID(ctx, operatorTokenMintClientID); err == nil {
		return nil
	}
	return o.stateStore.CreateClient(ctx, registeredClient{
		ID:                      operatorTokenMintClientID,
		Name:                    "MCP Edge Operator Token Mint",
		GrantTypes:              []string{oauthSessionIssuedViaOperator},
		ResponseTypes:           []string{},
		TokenEndpointAuthMethod: tokenEndpointAuthMethodNone,
		Scopes:                  o.catalog.Scopes(),
		CreatedAt:               time.Now().UTC(),
	}, "operator")
}

func (o *OAuthService) recordAuditEvent(ctx context.Context, event edgeAuditEvent) {
	if o.stateStore == nil {
		return
	}
	if correlationID, ok := ctx.Value(correlationIDContextKey).(string); ok && event.CorrelationID == "" {
		event.CorrelationID = correlationID
	}
	if err := o.stateStore.RecordAuditEvent(ctx, event); err != nil {
		o.logger.Error().Err(err).Str("event_type", event.EventType).Msg("failed to record oauth audit event")
	}
}

func newOAuthServerConfig() *oauth2server.Config {
	cfg := oauth2server.NewConfig()
	cfg.AllowedResponseTypes = []oauth2.ResponseType{oauth2.Code}
	cfg.AllowedGrantTypes = []oauth2.GrantType{oauth2.AuthorizationCode, oauth2.Refreshing}
	cfg.AllowedCodeChallengeMethods = []oauth2.CodeChallengeMethod{oauth2.CodeChallengeS256}
	cfg.ForcePKCE = true
	return cfg
}

func resolveClientCredentials(r *http.Request) (string, string, error) {
	if clientID, clientSecret, ok := r.BasicAuth(); ok {
		return clientID, clientSecret, nil
	}
	return oauth2server.ClientFormHandler(r)
}

func scopeStringAllowed(scope string, allowed []string) bool {
	if strings.TrimSpace(scope) == "" {
		return true
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, entry := range allowed {
		allowedSet[entry] = struct{}{}
	}

	for _, requested := range strings.Fields(scope) {
		if _, ok := allowedSet[requested]; !ok {
			return false
		}
	}
	return true
}

func clientAllowsScope(clientInfo oauth2.ClientInfo, scope string) bool {
	if strings.TrimSpace(scope) == "" {
		return true
	}
	clientScopes, ok := clientInfo.(scopedClient)
	if !ok {
		return false
	}
	return scopeStringAllowed(scope, clientScopes.AllowedScopes())
}

func clientAllowsGrant(clientInfo oauth2.ClientInfo, grantType string) bool {
	grantType = strings.TrimSpace(grantType)
	if grantType == "" {
		return false
	}
	clientGrantTypes, ok := clientInfo.(grantTypedClient)
	if !ok {
		return grantType == "authorization_code" || grantType == "refresh_token"
	}
	return slices.Contains(clientGrantTypes.AllowedGrantTypes(), grantType)
}

func verifyClientSecretForTokenRequest(clientInfo oauth2.ClientInfo, clientSecret string) bool {
	if clientInfo == nil {
		return false
	}
	if verifier, ok := clientInfo.(oauth2.ClientPasswordVerifier); ok {
		return verifier.VerifyPassword(clientSecret)
	}
	if clientInfo.IsPublic() {
		return strings.TrimSpace(clientSecret) == ""
	}
	return clientInfo.GetSecret() != "" && clientInfo.GetSecret() == clientSecret
}

func (o *OAuthService) validateClientGrantType(r *http.Request, prevalidatedClientID string) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("unable to parse request parameters")
	}
	grantType := strings.TrimSpace(r.Form.Get("grant_type"))
	if grantType != oauthGrantAuthorizationCode && grantType != oauthGrantRefreshToken && grantType != oauthGrantDeviceCode {
		return nil
	}
	clientID := strings.TrimSpace(prevalidatedClientID)
	if clientID == "" {
		var err error
		clientID, _, err = resolveClientCredentials(r)
		if err != nil {
			return fmt.Errorf("registered OAuth client is required")
		}
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), clientID)
	if err != nil {
		return fmt.Errorf("registered OAuth client is required")
	}
	if !clientAllowsGrant(clientInfo, grantType) {
		return fmt.Errorf("client is not registered for %s grant", grantType)
	}
	return nil
}

func (o *OAuthService) validateResourceIndicator(r *http.Request, scope string) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("unable to parse request parameters")
	}
	expectedResource, err := o.resourceForSingleServiceScope(scope)
	if err != nil {
		return "", err
	}
	resources := r.Form["resource"]
	if len(resources) == 0 || len(resources) == 1 && strings.TrimSpace(resources[0]) == "" {
		setRequestResourceIndicator(r, expectedResource)
		return expectedResource, nil
	}
	if len(resources) != 1 {
		return "", fmt.Errorf("exactly one resource indicator is required")
	}
	resource := strings.TrimRight(strings.TrimSpace(resources[0]), "/")
	if resource != expectedResource {
		return "", fmt.Errorf("resource indicator must match the requested MCP service")
	}
	setRequestResourceIndicator(r, expectedResource)
	return expectedResource, nil
}

func (o *OAuthService) validateTokenResourceIndicator(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("unable to parse form body")
	}
	resources := r.Form["resource"]
	if len(resources) == 0 || len(resources) == 1 && strings.TrimSpace(resources[0]) == "" {
		if scope := strings.TrimSpace(r.Form.Get("scope")); scope != "" {
			resource, err := o.resourceForSingleServiceScope(scope)
			if err != nil {
				return "", err
			}
			setRequestResourceIndicator(r, resource)
			return resource, nil
		}
		return "", nil
	}
	if len(resources) != 1 {
		return "", fmt.Errorf("exactly one resource indicator is required")
	}
	resource := strings.TrimRight(strings.TrimSpace(resources[0]), "/")
	for _, scope := range o.catalog.Scopes() {
		serviceID := strings.TrimPrefix(scope, "mcp:")
		service, ok := o.catalog.ServiceByID(serviceID)
		if ok && resource == o.publicBaseURL+service.PublicPath {
			setRequestResourceIndicator(r, resource)
			return resource, nil
		}
	}
	return "", fmt.Errorf("resource indicator is not registered on this edge")
}

func (o *OAuthService) resourceForSingleServiceScope(scope string) (string, error) {
	serviceID, err := singleServiceFromScope(scope)
	if err != nil {
		return "", err
	}
	service, ok := o.catalog.ServiceByID(serviceID)
	if !ok {
		return "", fmt.Errorf("requested resource scope is not supported")
	}
	return o.publicBaseURL + service.PublicPath, nil
}

func setRequestResourceIndicator(r *http.Request, resource string) {
	resource = strings.TrimRight(strings.TrimSpace(resource), "/")
	if resource == "" {
		return
	}
	setRequestFormValue(r, "resource", resource)
}

func setRequestFormValue(r *http.Request, key string, value string) {
	if r.Form != nil {
		r.Form.Set(key, value)
	}
	if r.PostForm != nil {
		r.PostForm.Set(key, value)
	}
	if r.Method == http.MethodGet && r.URL != nil {
		query := r.URL.Query()
		query.Set(key, value)
		r.URL.RawQuery = query.Encode()
	}
}

func singleServiceFromScope(scope string) (string, error) {
	serviceID := ""
	for _, scopeEntry := range strings.Fields(scope) {
		if !strings.HasPrefix(scopeEntry, "mcp:") {
			continue
		}
		if serviceID != "" {
			return "", fmt.Errorf("exactly one mcp:<service> scope is required")
		}
		serviceID = strings.TrimPrefix(scopeEntry, "mcp:")
	}
	if serviceID == "" {
		return "", fmt.Errorf("exactly one mcp:<service> scope is required")
	}
	return serviceID, nil
}

func normalizeClientRegistration(req clientRegistrationRequest, allowedScopes []string) (registeredClient, error) {
	record := registeredClient{
		Name:                    strings.TrimSpace(req.ClientName),
		RedirectURIs:            normalizeStringList(req.RedirectURIs),
		GrantTypes:              normalizeStringList(req.GrantTypes),
		ResponseTypes:           normalizeStringList(req.ResponseTypes),
		TokenEndpointAuthMethod: strings.TrimSpace(req.TokenEndpointAuthMethod),
		Scopes:                  normalizeStringList(strings.Fields(req.Scope)),
	}

	if record.Name == "" {
		return registeredClient{}, fmt.Errorf("client_name is required")
	}
	if len(record.GrantTypes) == 0 {
		record.GrantTypes = []string{oauthGrantAuthorizationCode, oauthGrantRefreshToken}
	}
	if len(record.ResponseTypes) == 0 {
		if slices.Contains(record.GrantTypes, oauthGrantAuthorizationCode) {
			record.ResponseTypes = []string{"code"}
		} else {
			record.ResponseTypes = []string{}
		}
	}
	if record.TokenEndpointAuthMethod == "" {
		record.TokenEndpointAuthMethod = tokenEndpointAuthMethodNone
	}

	if !grantTypesAllowed(record.GrantTypes) {
		return registeredClient{}, fmt.Errorf("unsupported OAuth grant type")
	}
	usesAuthorizationCode := slices.Contains(record.GrantTypes, oauthGrantAuthorizationCode)
	if usesAuthorizationCode {
		if len(record.RedirectURIs) == 0 {
			return registeredClient{}, fmt.Errorf("authorization_code clients require at least one redirect URI")
		}
		if !slices.Equal(record.ResponseTypes, []string{"code"}) {
			return registeredClient{}, fmt.Errorf("authorization_code clients require response type code")
		}
	} else if len(record.ResponseTypes) != 0 {
		return registeredClient{}, fmt.Errorf("response_types must be empty unless authorization_code is registered")
	}
	for _, redirectURI := range record.RedirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			return registeredClient{}, err
		}
	}
	if !slices.Contains([]string{
		tokenEndpointAuthMethodNone,
		tokenEndpointAuthMethodClientPost,
		tokenEndpointAuthMethodClientBasic,
	}, record.TokenEndpointAuthMethod) {
		return registeredClient{}, fmt.Errorf("unsupported token endpoint auth method")
	}
	if !scopeStringAllowed(strings.Join(record.Scopes, " "), allowedScopes) {
		return registeredClient{}, fmt.Errorf("requested scopes are not supported")
	}

	return record, nil
}

func validateRedirectURI(rawURI string) error {
	parsed, err := url.Parse(rawURI)
	if err != nil || !parsed.IsAbs() || strings.TrimSpace(parsed.Scheme) == "" {
		return fmt.Errorf("redirect URI must be absolute")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("redirect URI must not include a fragment")
	}
	switch parsed.Scheme {
	case "https":
		if parsed.Hostname() == "" {
			return fmt.Errorf("https redirect URI must include a host")
		}
	case "http":
		ip := net.ParseIP(parsed.Hostname())
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("http redirect URI is only allowed for loopback clients")
		}
	default:
		return fmt.Errorf("redirect URI scheme must be https or loopback http")
	}
	return nil
}

func (o *OAuthService) registerClientMetadataDocument(ctx context.Context, clientID string) (oauth2.ClientInfo, error) {
	clientID = strings.TrimSpace(clientID)
	parsed, err := url.Parse(clientID)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("client_id metadata document must be an HTTPS URL")
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := validateCIMDURL(requestCtx, parsed); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: dialPublicHTTPSHost,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata document returned status %d", resp.StatusCode)
	}
	var metadata clientRegistrationRequest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("client metadata document must be valid JSON")
	}
	if metadata.ClientID != "" && metadata.ClientID != clientID {
		return nil, fmt.Errorf("client metadata document client_id must match the requested client_id")
	}
	record, err := normalizeClientRegistration(metadata, o.catalog.Scopes())
	if err != nil {
		return nil, err
	}
	record.ID = clientID
	record.TokenEndpointAuthMethod = tokenEndpointAuthMethodNone
	record.CreatedAt = time.Now().UTC()
	if err := o.stateStore.CreateClient(ctx, record, ""); err != nil {
		return nil, err
	}
	return o.stateStore.GetByID(ctx, clientID)
}

func dialPublicHTTPSHost(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if port != "443" {
		return nil, fmt.Errorf("client metadata document must use default HTTPS port 443")
	}
	ips, err := resolvePublicCIMDHost(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func validateCIMDURL(ctx context.Context, parsed *url.URL) error {
	if parsed == nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("client_id metadata document must be an HTTPS URL")
	}
	if parsed.Port() != "" && parsed.Port() != "443" {
		return fmt.Errorf("client metadata document must use default HTTPS port 443")
	}
	_, err := resolvePublicCIMDHost(ctx, parsed.Hostname())
	return err
}

func resolvePublicCIMDHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve client metadata document host: %w", err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("client metadata document host did not resolve")
	}
	for _, resolved := range ips {
		ip := resolved.IP
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return nil, fmt.Errorf("client metadata document host must resolve to public addresses only")
		}
	}
	return ips, nil
}

func grantTypesAllowed(grantTypes []string) bool {
	for _, grantType := range grantTypes {
		switch grantType {
		case oauthGrantAuthorizationCode, oauthGrantRefreshToken, oauthGrantDeviceCode:
			continue
		default:
			return false
		}
	}
	return true
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	var normalized []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func generateClientSecret() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func generateUserCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, value := range buf {
		buf[i] = alphabet[int(value)%len(alphabet)]
	}
	return string(buf[:4]) + "-" + string(buf[4:]), nil
}

func (o *OAuthService) requireOperatorToken(w http.ResponseWriter, r *http.Request) bool {
	providedToken, ok := parseBearerAuthorization(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-edge-operator"`)
		writeJSONError(w, http.StatusUnauthorized, "operator_auth_required", "operator bearer token is required")
		return false
	}
	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(o.operatorToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-edge-operator"`)
		writeJSONError(w, http.StatusUnauthorized, "operator_auth_invalid", "operator bearer token is invalid")
		return false
	}
	return true
}

func parseBearerAuthorization(headerValue string) (string, bool) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue == "" {
		return "", false
	}
	parts := strings.Fields(headerValue)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

func resolveIntrospectionToken(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("unable to parse form body")
	}

	token := strings.TrimSpace(r.Form.Get("token"))
	if token != "" {
		return token, nil
	}

	req := r.Clone(context.Background())
	if tokenInfo, ok := oauth2server.AccessTokenDefaultResolveHandler(req); ok {
		return tokenInfo, nil
	}

	return "", fmt.Errorf("token is required")
}

func (o *OAuthService) prevalidateRefreshClient(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", fmt.Errorf("parse token form: %w", err)
	}
	if r.Form.Get("grant_type") != "refresh_token" {
		return "", nil
	}
	clientID, clientSecret, err := resolveClientCredentials(r)
	if err != nil {
		return "", err
	}
	clientInfo, err := o.stateStore.GetByID(r.Context(), clientID)
	if err != nil {
		return "", err
	}
	if verifier, ok := clientInfo.(oauth2.ClientPasswordVerifier); ok {
		if !verifier.VerifyPassword(clientSecret) {
			return "", fmt.Errorf("refresh client secret is invalid")
		}
		return clientID, nil
	}
	if clientInfo.GetSecret() != "" && clientInfo.GetSecret() != clientSecret {
		return "", fmt.Errorf("refresh client secret is invalid")
	}
	if clientInfo.IsPublic() && strings.TrimSpace(clientSecret) != "" {
		return "", fmt.Errorf("public refresh clients must not send a client secret")
	}
	return clientID, nil
}
