package edge

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

const (
	browserSessionCookieName = "mcp_edge_session"
	groupMCPUsers            = "mcp-users"
	groupMCPAdmin            = "mcp-admin"
)

type IdentityClaims struct {
	Sub               string
	Email             string
	Name              string
	PreferredUsername string
	Groups            []string
}

type GrantAuthorizer interface {
	Allowed(ctx context.Context, subjectSub string, serviceID string) (bool, error)
	AllowedScopes(ctx context.Context, subjectSub string, scope string) (bool, error)
}

type AuthRuntime struct {
	logger          zerolog.Logger
	publicBaseURL   string
	cookieSecure    bool
	sessionTTL      time.Duration
	pendingLoginTTL time.Duration
	stateStore      edgeStateStore
	authenticator delegatedLoginAuthenticator
}

type delegatedLoginAuthenticator interface {
	Start(w http.ResponseWriter, r *http.Request, pending pendingLogin) error
	Complete(ctx context.Context, r *http.Request, pending pendingLogin) (IdentityClaims, error)
}

type pendingLogin struct {
	State    string
	ReturnTo string
	Nonce    string
	Expiry   time.Time
}

type browserSession struct {
	Claims IdentityClaims
	Expiry time.Time
}

type fixtureDelegatedAuthenticator struct {
	callbackURL string
	claims      IdentityClaims
}

type oidcDelegatedAuthenticator struct {
	logger       zerolog.Logger
	issuerURL    string
	clientID     string
	clientSecret string
	callbackURL  string

	mu          sync.Mutex
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthConfig *oauth2.Config
	initErr     error
}

type oidcIdentityClaims struct {
	Sub               string          `json:"sub"`
	Email             string          `json:"email"`
	Name              string          `json:"name"`
	PreferredUsername string          `json:"preferred_username"`
	Groups            []string        `json:"groups"`
	Nonce             string          `json:"nonce"`
	RawGroups         json.RawMessage `json:"-"`
}

func NewAuthRuntime(cfg Config, logger zerolog.Logger, stateStore edgeStateStore) (*AuthRuntime, error) {
	if stateStore == nil {
		return nil, fmt.Errorf("edge auth state store is required")
	}
	runtime := &AuthRuntime{
		logger:          logger,
		publicBaseURL:   strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/"),
		cookieSecure:    cfg.CookieSecure,
		sessionTTL:      12 * time.Hour,
		pendingLoginTTL: 10 * time.Minute,
		stateStore:      stateStore,
	}

	callbackURL := runtime.publicBaseURL + "/auth/callback"
	if cfg.HasOIDCConfig() {
		clientSecret, secretErr := resolveConfiguredSecret(cfg.AuthentikClientSecretPath, "")
		if secretErr != nil {
			return nil, secretErr
		}
		runtime.authenticator = &oidcDelegatedAuthenticator{
			logger:       logger,
			issuerURL:    strings.TrimSpace(cfg.AuthentikIssuerURL),
			clientID:     strings.TrimSpace(cfg.AuthentikClientID),
			clientSecret: clientSecret,
			callbackURL:  callbackURL,
		}
		return runtime, nil
	}
	if !cfg.EnableFixtureMode {
		return nil, fmt.Errorf("fixture auth mode is disabled and Authentik OIDC is not configured")
	}

	claims := IdentityClaims{
		Sub:               firstNonEmpty(cfg.FixtureAuthSubjectSub, "fixture-user"),
		Email:             firstNonEmpty(cfg.FixtureAuthSubjectEmail, "fixture-user@example.com"),
		Name:              firstNonEmpty(cfg.FixtureAuthSubjectName, "Fixture User"),
		PreferredUsername: firstNonEmpty(cfg.FixtureAuthPreferredUsername, "fixture-user"),
		Groups:            cfg.FixtureAuthGroups,
	}
	if len(claims.Groups) == 0 {
		claims.Groups = []string{groupMCPUsers, grantGroupForService("mealie")}
	}
	if err := runtime.stateStore.UpsertSubject(context.Background(), claims); err != nil {
		return nil, err
	}
	runtime.authenticator = &fixtureDelegatedAuthenticator{
		callbackURL: callbackURL,
		claims:      claims,
	}
	return runtime, nil
}

func (a *AuthRuntime) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/auth/callback", a.handleCallback)
}

func (a *AuthRuntime) InjectBrowserSubject(r *http.Request) *http.Request {
	cookie, err := r.Cookie(browserSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return r
	}

	session, ok, err := a.stateStore.GetBrowserSession(r.Context(), cookie.Value, time.Now().UTC())
	if err != nil {
		a.logger.Warn().Err(err).Str("session_id", cookie.Value).Msg("failed to load browser session")
		return r
	}
	if !ok {
		return r
	}

	return r.WithContext(WithAuthenticatedSubject(r.Context(), AuthenticatedSubject{
		Sub:               session.Claims.Sub,
		Email:             session.Claims.Email,
		DisplayName:       session.Claims.Name,
		PreferredUsername: session.Claims.PreferredUsername,
		Groups:            append([]string(nil), session.Claims.Groups...),
	}))
}

func (a *AuthRuntime) BeginBrowserLogin(w http.ResponseWriter, r *http.Request, returnTo string) {
	state, err := randomToken(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "login_state_failed", "unable to allocate login state")
		return
	}

	nonce, err := randomToken(24)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "login_state_failed", "unable to allocate login nonce")
		return
	}

	pending := pendingLogin{
		State:    state,
		ReturnTo: returnTo,
		Nonce:    nonce,
		Expiry:   time.Now().UTC().Add(a.pendingLoginTTL),
	}
	if err := a.stateStore.PutPendingLogin(r.Context(), pending); err != nil {
		a.logger.Error().Err(err).Msg("delegated login persistence failed")
		writeJSONError(w, http.StatusInternalServerError, "login_state_failed", "unable to persist login state")
		return
	}

	if err := a.authenticator.Start(w, r, pending); err != nil {
		a.logger.Error().Err(err).Msg("delegated login start failed")
		writeJSONError(w, http.StatusBadGateway, "delegated_login_unavailable", "unable to start delegated login")
	}
}

func (a *AuthRuntime) Allowed(ctx context.Context, subjectSub string, serviceID string) (bool, error) {
	return a.stateStore.Allowed(ctx, subjectSub, serviceID)
}

func (a *AuthRuntime) AllowedScopes(ctx context.Context, subjectSub string, scope string) (bool, error) {
	return a.stateStore.AllowedScopes(ctx, subjectSub, scope)
}

func (a *AuthRuntime) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if state == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_state", "login state is required")
		return
	}

	pending, ok, err := a.stateStore.GetPendingLogin(r.Context(), state, time.Now().UTC())
	if err != nil {
		a.logger.Error().Err(err).Msg("delegated login state lookup failed")
		writeJSONError(w, http.StatusServiceUnavailable, "login_state_unavailable", "unable to load delegated login state")
		return
	}
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "invalid_state", "login state is invalid or expired")
		return
	}

	claims, err := a.authenticator.Complete(r.Context(), r, pending)
	if err != nil {
		a.logger.Error().Err(err).Msg("delegated login callback failed")
		writeJSONError(w, http.StatusUnauthorized, "delegated_login_failed", "unable to complete delegated login")
		return
	}

	if err := a.stateStore.UpsertSubject(r.Context(), claims); err != nil {
		a.logger.Error().Err(err).Msg("subject upsert failed during delegated login")
		writeJSONError(w, http.StatusServiceUnavailable, "subject_sync_failed", "unable to persist subject identity")
		return
	}
	if err := a.stateStore.DeletePendingLogin(r.Context(), state); err != nil {
		a.logger.Error().Err(err).Msg("delegated login state cleanup failed")
		writeJSONError(w, http.StatusServiceUnavailable, "login_state_unavailable", "unable to finalize delegated login state")
		return
	}

	sessionID, err := randomToken(32)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "session_create_failed", "unable to create browser session")
		return
	}
	sessionExpiry := time.Now().UTC().Add(a.sessionTTL)
	if err := a.stateStore.PutBrowserSession(r.Context(), sessionID, browserSession{
		Claims: claims,
		Expiry: sessionExpiry,
	}); err != nil {
		a.logger.Error().Err(err).Msg("browser session persistence failed")
		writeJSONError(w, http.StatusServiceUnavailable, "session_create_failed", "unable to persist browser session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     browserSessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sessionExpiry,
	})

	http.Redirect(w, r, pending.ReturnTo, http.StatusFound)
}

func identityHasGrant(claims IdentityClaims, serviceID string) bool {
	groupSet := make(map[string]struct{}, len(claims.Groups))
	for _, group := range claims.Groups {
		groupSet[group] = struct{}{}
	}

	if _, ok := groupSet[groupMCPAdmin]; ok {
		return true
	}
	if _, ok := groupSet[groupMCPUsers]; !ok {
		return false
	}
	_, ok := groupSet[grantGroupForService(serviceID)]
	return ok
}

func grantGroupForService(serviceID string) string {
	return "mcp-service-" + serviceID
}

func (f *fixtureDelegatedAuthenticator) Start(w http.ResponseWriter, r *http.Request, pending pendingLogin) error {
	callbackURL := f.callbackURL + "?state=" + url.QueryEscape(pending.State) + "&fixture=1"
	http.Redirect(w, r, callbackURL, http.StatusFound)
	return nil
}

func (f *fixtureDelegatedAuthenticator) Complete(_ context.Context, r *http.Request, pending pendingLogin) (IdentityClaims, error) {
	if r.URL.Query().Get("fixture") != "1" {
		return IdentityClaims{}, fmt.Errorf("fixture callback marker missing")
	}
	return f.claims, nil
}

func (o *oidcDelegatedAuthenticator) Start(w http.ResponseWriter, r *http.Request, pending pendingLogin) error {
	if err := o.ensureProvider(r.Context()); err != nil {
		return err
	}

	authURL := o.oauthConfig.AuthCodeURL(
		pending.State,
		oauth2.AccessTypeOffline,
		oidc.Nonce(pending.Nonce),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (o *oidcDelegatedAuthenticator) Complete(ctx context.Context, r *http.Request, pending pendingLogin) (IdentityClaims, error) {
	if err := o.ensureProvider(ctx); err != nil {
		return IdentityClaims{}, err
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		return IdentityClaims{}, fmt.Errorf("authorization code is required")
	}

	token, err := o.oauthConfig.Exchange(ctx, code)
	if err != nil {
		return IdentityClaims{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return IdentityClaims{}, fmt.Errorf("id_token missing from delegated login response")
	}

	idToken, err := o.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return IdentityClaims{}, err
	}

	var claims struct {
		Sub               string   `json:"sub"`
		Email             string   `json:"email"`
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		Groups            []string `json:"groups"`
		Nonce             string   `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return IdentityClaims{}, err
	}
	if claims.Nonce != pending.Nonce {
		return IdentityClaims{}, fmt.Errorf("delegated login nonce mismatch")
	}

	return IdentityClaims{
		Sub:               claims.Sub,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
		Groups:            claims.Groups,
	}, nil
}

func (o *oidcDelegatedAuthenticator) ensureProvider(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.provider != nil {
		return nil
	}
	if o.initErr != nil {
		return o.initErr
	}

	provider, err := oidc.NewProvider(ctx, o.issuerURL)
	if err != nil {
		o.initErr = err
		return err
	}

	o.provider = provider
	o.verifier = provider.Verifier(&oidc.Config{ClientID: o.clientID})
	o.oauthConfig = &oauth2.Config{
		ClientID:     o.clientID,
		ClientSecret: o.clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  o.callbackURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "offline_access", "groups"},
	}
	return nil
}

func randomToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func resolveConfiguredSecret(secretPath string, fallbackValue string) (string, error) {
	if strings.TrimSpace(fallbackValue) != "" {
		return strings.TrimSpace(fallbackValue), nil
	}
	if strings.TrimSpace(secretPath) == "" {
		return "", nil
	}

	data, err := os.ReadFile(secretPath)
	if err != nil {
		return "", fmt.Errorf("read configured secret path %q: %w", secretPath, err)
	}
	return strings.TrimSpace(string(data)), nil
}
