package edge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/ids"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	oauth2server "github.com/go-oauth2/oauth2/v4/server"
	"github.com/rs/zerolog"
)

const (
	tokenEndpointAuthMethodNone        = "none"
	tokenEndpointAuthMethodClientPost  = "client_secret_post"
	tokenEndpointAuthMethodClientBasic = "client_secret_basic"
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

type tokenIntrospectionResponse struct {
	Active    bool   `json:"active"`
	ClientID  string `json:"client_id,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
}

type refreshClientIDContextKey struct{}

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
	manager := manage.NewDefaultManager()
	manager.MapTokenStorage(stateStore)
	manager.MapClientStorage(stateStore)
	manager.SetValidateURIHandler(func(baseURI, redirectURI string) error {
		if strings.TrimSpace(baseURI) != strings.TrimSpace(redirectURI) {
			return oauth2errors.ErrInvalidRedirectURI
		}
		return nil
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
		publicBaseURL: strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/"),
		operatorToken: operatorToken,
		catalog:       catalogCache,
		grants:        grants,
		browserAuth:   browserAuth,
		stateStore:    stateStore,
		manager:       manager,
		server:        srv,
	}, nil
}

func (o *OAuthService) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/.well-known/oauth-authorization-server", o.handleAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource", o.handleProtectedResourceMetadata)
	mux.HandleFunc("/oauth/register", o.handleClientRegistration)
	mux.HandleFunc("/oauth/authorize", o.handleAuthorize)
	mux.HandleFunc("/oauth/token", o.handleToken)
	mux.HandleFunc("/oauth/introspect", o.handleIntrospect)
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

	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                o.publicBaseURL,
		"authorization_endpoint":                o.publicBaseURL + "/oauth/authorize",
		"token_endpoint":                        o.publicBaseURL + "/oauth/token",
		"registration_endpoint":                 o.publicBaseURL + "/oauth/register",
		"introspection_endpoint":                o.publicBaseURL + "/oauth/introspect",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{tokenEndpointAuthMethodNone, tokenEndpointAuthMethodClientPost, tokenEndpointAuthMethodClientBasic},
		"scopes_supported":                      o.catalog.Scopes(),
	})
}

func (o *OAuthService) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "metadata requires GET")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                              o.publicBaseURL,
		"authorization_servers":                 []string{o.publicBaseURL},
		"scopes_supported":                      o.catalog.Scopes(),
		"bearer_methods_supported":              []string{"header"},
		"resource_documentation":                o.publicBaseURL + "/health",
		"resource_name":                         "dragonserver-mcp-edge",
		"authorization_details_types_supported": []string{},
	})
}

func (o *OAuthService) handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "client registration requires POST")
		return
	}
	if !o.requireOperatorToken(w, r) {
		return
	}

	var req clientRegistrationRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	record, err := normalizeClientRegistration(req, o.catalog.Scopes())
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

func (o *OAuthService) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "token exchange requires POST")
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
		},
	})
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
		ClientID:  ti.GetClientID(),
		Sub:       ti.GetUserID(),
		Scope:     ti.GetScope(),
		TokenType: "Bearer",
		Iat:       ti.GetAccessCreateAt().Unix(),
		Exp:       ti.GetAccessCreateAt().Add(ti.GetAccessExpiresIn()).Unix(),
	})
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
	if len(record.RedirectURIs) != 1 {
		return registeredClient{}, fmt.Errorf("exactly one redirect URI is required")
	}
	if !strings.Contains(record.RedirectURIs[0], "://") {
		return registeredClient{}, fmt.Errorf("redirect URI must be absolute")
	}

	if len(record.GrantTypes) == 0 {
		record.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(record.ResponseTypes) == 0 {
		record.ResponseTypes = []string{"code"}
	}
	if record.TokenEndpointAuthMethod == "" {
		record.TokenEndpointAuthMethod = tokenEndpointAuthMethodNone
	}

	if !slices.Equal(record.ResponseTypes, []string{"code"}) {
		return registeredClient{}, fmt.Errorf("only response type code is supported")
	}
	if !grantTypesAllowed(record.GrantTypes) {
		return registeredClient{}, fmt.Errorf("only authorization_code and refresh_token grant types are supported")
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

func grantTypesAllowed(grantTypes []string) bool {
	for _, grantType := range grantTypes {
		switch grantType {
		case "authorization_code", "refresh_token":
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
