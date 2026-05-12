package edge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"
	"dragonserver/mcp-platform/internal/ids"
	platformsqlite "dragonserver/mcp-platform/internal/platform/sqlite"
	"dragonserver/mcp-platform/internal/platform/sqlite/platformdb"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	oauth2store "github.com/go-oauth2/oauth2/v4/store"
	"github.com/rs/zerolog"
)

const tokenSessionIDExtensionKey = "sid"

type edgeStateStore interface {
	oauth2.ClientStore
	oauth2.TokenStore
	GrantAuthorizer

	CreateClient(context.Context, registeredClient, string) error
	PutPendingLogin(context.Context, pendingLogin) error
	GetPendingLogin(context.Context, string, time.Time) (pendingLogin, bool, error)
	DeletePendingLogin(context.Context, string) error
	PutBrowserSession(context.Context, string, browserSession) error
	GetBrowserSession(context.Context, string, time.Time) (browserSession, bool, error)
	UpsertSubject(context.Context, IdentityClaims) error
	ListEnabledServiceCatalog(context.Context) ([]catalog.ServiceCatalogEntry, error)
	RecordAuditEvent(context.Context, edgeAuditEvent) error
	Ping(context.Context) error
	Close() error
}

type edgeAuditEvent struct {
	CorrelationID   string
	ActorSubjectSub string
	ServiceID       string
	EventType       string
	EventStatus     string
	Payload         map[string]any
}

type memoryEdgeStateStore struct {
	clientStore oauth2.ClientStore
	tokenStore  oauth2.TokenStore

	mu            sync.RWMutex
	pendingLogins map[string]pendingLogin
	sessions      map[string]browserSession
	subjects      map[string]IdentityClaims
	auditEvents   []edgeAuditEvent
}

type sqliteEdgeStateStore struct {
	logger  zerolog.Logger
	db      *sql.DB
	queries *platformdb.Queries
	cipher  *opaqueCipher
}

type confidentialClient struct {
	id         string
	domain     string
	userID     string
	secret     string
	secretHash string
	scopes     []string
}

type scopedClient interface {
	AllowedScopes() []string
}

type oauthSessionRecord struct {
	SessionID                   string
	SubjectSub                  *string
	ClientID                    string
	ServiceID                   *string
	RedirectURI                 string
	Scope                       string
	CodeChallenge               *string
	CodeChallengeMethod         *string
	AuthorizationCodeHash       *string
	AuthorizationCodeCiphertext []byte
	AccessTokenHash             *string
	AccessTokenCiphertext       []byte
	RefreshTokenHash            *string
	RefreshTokenCiphertext      []byte
	CodeCreateAt                *time.Time
	CodeExpiresInSeconds        int64
	AccessCreateAt              *time.Time
	AccessExpiresInSeconds      int64
	RefreshCreateAt             *time.Time
	RefreshExpiresInSeconds     int64
	ExpiresAt                   *time.Time
}

type opaqueCipher struct {
	aead cipher.AEAD
}

func newEdgeStateStore(ctx context.Context, cfg Config, logger zerolog.Logger) (edgeStateStore, error) {
	if cfg.EnableFixtureMode {
		return newMemoryEdgeStateStore()
	}
	if strings.TrimSpace(cfg.PlatformDatabaseURL) == "" {
		return nil, fmt.Errorf("mcp-edge platform database url is required outside fixture mode")
	}
	return newSQLiteEdgeStateStore(ctx, cfg, logger)
}

func newMemoryEdgeStateStore() (*memoryEdgeStateStore, error) {
	tokenStore, err := oauth2store.NewMemoryTokenStore()
	if err != nil {
		return nil, err
	}
	return &memoryEdgeStateStore{
		clientStore:   oauth2store.NewClientStore(),
		tokenStore:    tokenStore,
		pendingLogins: make(map[string]pendingLogin),
		sessions:      make(map[string]browserSession),
		subjects:      make(map[string]IdentityClaims),
		auditEvents:   make([]edgeAuditEvent, 0),
	}, nil
}

func newSQLiteEdgeStateStore(ctx context.Context, cfg Config, logger zerolog.Logger) (*sqliteEdgeStateStore, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sessionKey, err := resolveConfiguredSecret(cfg.SessionEncryptionKeyPath, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(sessionKey) == "" {
		return nil, fmt.Errorf("mcp-edge session encryption key is required when database persistence is enabled")
	}
	cipherValue, err := newOpaqueCipher(sessionKey)
	if err != nil {
		return nil, err
	}
	db, err := platformsqlite.Open(ctx, strings.TrimSpace(cfg.PlatformDatabaseURL))
	if err != nil {
		return nil, err
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping edge sqlite database: %w", err)
	}
	return &sqliteEdgeStateStore{
		logger:  logger,
		db:      db,
		queries: platformdb.New(db),
		cipher:  cipherValue,
	}, nil
}

func (s *memoryEdgeStateStore) CreateClient(ctx context.Context, record registeredClient, _ string) error {
	client := &models.Client{
		ID:     record.ID,
		Secret: record.Secret,
		Domain: firstRedirectURI(record.RedirectURIs),
		Public: record.TokenEndpointAuthMethod == tokenEndpointAuthMethodNone,
	}
	clientInfo := confidentialClient{
		id:     client.ID,
		domain: client.Domain,
		secret: client.Secret,
		userID: client.UserID,
		scopes: slices.Clone(record.Scopes),
	}
	if client.Public {
		clientInfo.secret = ""
	}
	if storeValue, ok := s.clientStore.(*oauth2store.ClientStore); ok {
		return storeValue.Set(record.ID, clientInfo)
	}
	return fmt.Errorf("memory client store does not support registration")
}

func (s *memoryEdgeStateStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	return s.clientStore.GetByID(ctx, id)
}

func (s *memoryEdgeStateStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	return s.tokenStore.Create(ctx, info)
}

func (s *memoryEdgeStateStore) RemoveByCode(ctx context.Context, code string) error {
	return s.tokenStore.RemoveByCode(ctx, code)
}

func (s *memoryEdgeStateStore) RemoveByAccess(ctx context.Context, access string) error {
	return s.tokenStore.RemoveByAccess(ctx, access)
}

func (s *memoryEdgeStateStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	return s.tokenStore.RemoveByRefresh(ctx, refresh)
}

func (s *memoryEdgeStateStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	tokenInfo, err := s.tokenStore.GetByCode(ctx, code)
	if err != nil || tokenInfo == nil {
		return tokenInfo, err
	}
	if err := s.validateTokenInfoAuthorization(ctx, tokenInfo); err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func (s *memoryEdgeStateStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return s.tokenStore.GetByAccess(ctx, access)
}

func (s *memoryEdgeStateStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	tokenInfo, err := s.tokenStore.GetByRefresh(ctx, refresh)
	if err != nil || tokenInfo == nil {
		return tokenInfo, err
	}
	if err := validateRefreshClientBinding(ctx, tokenInfo.GetClientID()); err != nil {
		return nil, err
	}
	if err := s.validateTokenInfoAuthorization(ctx, tokenInfo); err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func (s *memoryEdgeStateStore) validateTokenInfoAuthorization(ctx context.Context, tokenInfo oauth2.TokenInfo) error {
	clientInfo, err := s.GetByID(ctx, tokenInfo.GetClientID())
	if err != nil {
		return err
	}
	if !clientAllowsScope(clientInfo, tokenInfo.GetScope()) {
		return fmt.Errorf("oauth client is not registered for requested scope")
	}
	if strings.TrimSpace(tokenInfo.GetUserID()) != "" && strings.TrimSpace(tokenInfo.GetScope()) != "" {
		allowed, err := s.AllowedScopes(ctx, tokenInfo.GetUserID(), tokenInfo.GetScope())
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf("requested scope is not granted for this subject")
		}
	}
	return nil
}

func (s *memoryEdgeStateStore) PutPendingLogin(_ context.Context, pending pendingLogin) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingLogins[pending.State] = pending
	return nil
}

func (s *memoryEdgeStateStore) GetPendingLogin(_ context.Context, state string, now time.Time) (pendingLogin, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pending, ok := s.pendingLogins[state]
	if !ok {
		return pendingLogin{}, false, nil
	}
	if pending.Expiry.Before(now) {
		return pendingLogin{}, false, nil
	}
	return pending, true, nil
}

func (s *memoryEdgeStateStore) DeletePendingLogin(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pendingLogins, state)
	return nil
}

func (s *memoryEdgeStateStore) PutBrowserSession(_ context.Context, sessionID string, session browserSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = session
	return nil
}

func (s *memoryEdgeStateStore) GetBrowserSession(_ context.Context, sessionID string, now time.Time) (browserSession, bool, error) {
	s.mu.RLock()
	session, ok := s.sessions[sessionID]
	s.mu.RUnlock()
	if !ok {
		return browserSession{}, false, nil
	}
	if session.Expiry.Before(now) {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		return browserSession{}, false, nil
	}
	return session, true, nil
}

func (s *memoryEdgeStateStore) UpsertSubject(_ context.Context, claims IdentityClaims) error {
	if strings.TrimSpace(claims.Sub) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subjects[claims.Sub] = claims
	return nil
}

func (s *memoryEdgeStateStore) Allowed(_ context.Context, subjectSub string, serviceID string) (bool, error) {
	s.mu.RLock()
	claims, ok := s.subjects[subjectSub]
	s.mu.RUnlock()
	if !ok {
		return false, nil
	}
	return identityHasGrant(claims, serviceID), nil
}

func (s *memoryEdgeStateStore) AllowedScopes(ctx context.Context, subjectSub string, scope string) (bool, error) {
	serviceIDs, valid := parseRequestedServiceScopes(scope)
	if !valid {
		return false, nil
	}
	for _, serviceID := range serviceIDs {
		allowed, err := s.Allowed(ctx, subjectSub, serviceID)
		if err != nil || !allowed {
			return allowed, err
		}
	}
	return true, nil
}

func (s *memoryEdgeStateStore) ListEnabledServiceCatalog(context.Context) ([]catalog.ServiceCatalogEntry, error) {
	return catalog.DefaultCatalogV1(), nil
}

func (s *memoryEdgeStateStore) RecordAuditEvent(_ context.Context, event edgeAuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *memoryEdgeStateStore) Ping(context.Context) error {
	return nil
}

func (s *memoryEdgeStateStore) Close() error {
	return nil
}

func (c confidentialClient) GetID() string           { return c.id }
func (c confidentialClient) GetSecret() string       { return c.secret }
func (c confidentialClient) GetDomain() string       { return c.domain }
func (c confidentialClient) IsPublic() bool          { return c.secret == "" && c.secretHash == "" }
func (c confidentialClient) GetUserID() string       { return c.userID }
func (c confidentialClient) AllowedScopes() []string { return slices.Clone(c.scopes) }

func (c confidentialClient) VerifyPassword(secret string) bool {
	if c.secretHash == "" {
		return subtle.ConstantTimeCompare([]byte(c.secret), []byte(secret)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(c.secretHash), []byte(hashOpaqueValue(secret))) == 1
}

func newOpaqueCipher(secret string) (*opaqueCipher, error) {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create aes-gcm cipher: %w", err)
	}
	return &opaqueCipher{aead: aead}, nil
}

func (c *opaqueCipher) EncryptString(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate cipher nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, []byte(value), nil), nil
}

func (c *opaqueCipher) DecryptString(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", nil
	}
	nonceSize := c.aead.NonceSize()
	if len(payload) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	plaintext, err := c.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt opaque value: %w", err)
	}
	return string(plaintext), nil
}

func hashOpaqueValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func firstRedirectURI(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func parseRequestedServiceScopes(scope string) ([]string, bool) {
	if strings.TrimSpace(scope) == "" {
		return nil, false
	}
	seen := make(map[string]struct{})
	serviceIDs := make([]string, 0, len(strings.Fields(scope)))
	for _, scopeEntry := range strings.Fields(scope) {
		if !strings.HasPrefix(scopeEntry, "mcp:") {
			return nil, false
		}
		serviceID := strings.TrimSpace(strings.TrimPrefix(scopeEntry, "mcp:"))
		if serviceID == "" {
			return nil, false
		}
		if _, ok := seen[serviceID]; ok {
			continue
		}
		seen[serviceID] = struct{}{}
		serviceIDs = append(serviceIDs, serviceID)
	}
	return serviceIDs, len(serviceIDs) > 0
}

func singleServiceIDFromScope(scope string) string {
	serviceIDs, valid := parseRequestedServiceScopes(scope)
	if !valid || len(serviceIDs) != 1 {
		return ""
	}
	return serviceIDs[0]
}

func durationToSeconds(value time.Duration) int64 {
	if value <= 0 {
		return 0
	}
	return int64(value / time.Second)
}

func durationFromSeconds(value int64) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Duration(value) * time.Second
}

func sqliteNullTime(value time.Time) sql.NullString {
	if value.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatSQLiteTime(value), Valid: true}
}

func sqliteNullTimePtr(value *time.Time) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return sqliteNullTime(*value)
}

func formatSQLiteTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseSQLiteTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC)
}

func stringPtrFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

func timePtrFromNull(value sql.NullString) *time.Time {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return nil
	}
	parsed, err := parseSQLiteTime(value.String)
	if err != nil {
		return nil
	}
	return &parsed
}

func nullableString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func marshalStringSliceJSON(values []string) ([]byte, error) {
	if len(values) == 0 {
		return []byte("[]"), nil
	}
	data, err := json.Marshal(values)
	if err != nil {
		return nil, fmt.Errorf("marshal string slice: %w", err)
	}
	return data, nil
}

func unmarshalStringSliceJSON(values []byte) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var decoded []string
	if err := json.Unmarshal(values, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshal string slice: %w", err)
	}
	return decoded, nil
}

func tokenInfoSessionID(info oauth2.TokenInfo) string {
	ext, ok := info.(oauth2.ExtendableTokenInfo)
	if !ok {
		return ""
	}
	return strings.TrimSpace(ext.GetExtension().Get(tokenSessionIDExtensionKey))
}

func setTokenInfoSessionID(info oauth2.TokenInfo, sessionID string) {
	ext, ok := info.(oauth2.ExtendableTokenInfo)
	if !ok {
		return
	}
	values := ext.GetExtension()
	if values == nil {
		values = make(url.Values)
	}
	values.Set(tokenSessionIDExtensionKey, sessionID)
	ext.SetExtension(values)
}

func buildTokenSessionExpiry(info oauth2.TokenInfo) *time.Time {
	var expiry time.Time
	add := func(start time.Time, duration time.Duration) {
		if start.IsZero() || duration <= 0 {
			return
		}
		candidate := start.Add(duration).UTC()
		if expiry.IsZero() || candidate.After(expiry) {
			expiry = candidate
		}
	}
	add(info.GetCodeCreateAt(), info.GetCodeExpiresIn())
	add(info.GetAccessCreateAt(), info.GetAccessExpiresIn())
	add(info.GetRefreshCreateAt(), info.GetRefreshExpiresIn())
	if expiry.IsZero() {
		return nil
	}
	return &expiry
}

func (s *sqliteEdgeStateStore) CreateClient(ctx context.Context, record registeredClient, createdBySubjectSub string) error {
	redirectURIsJSON, err := marshalStringSliceJSON(record.RedirectURIs)
	if err != nil {
		return err
	}
	grantTypesJSON, err := marshalStringSliceJSON(record.GrantTypes)
	if err != nil {
		return err
	}
	responseTypesJSON, err := marshalStringSliceJSON(record.ResponseTypes)
	if err != nil {
		return err
	}
	scopesJSON, err := marshalStringSliceJSON(record.Scopes)
	if err != nil {
		return err
	}
	var secretHash sql.NullString
	if strings.TrimSpace(record.Secret) != "" {
		secretHash = sql.NullString{String: hashOpaqueValue(record.Secret), Valid: true}
	}
	createdAt := record.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	if createdBySubjectSub != "" {
		if err := s.ensureSubject(ctx, IdentityClaims{Sub: createdBySubjectSub}); err != nil {
			return err
		}
	}
	if err := s.queries.CreateOAuthClient(ctx, platformdb.CreateOAuthClientParams{
		ClientID:                record.ID,
		ClientName:              record.Name,
		CreatedBySubjectSub:     createdBySubjectSub,
		RedirectUris:            string(redirectURIsJSON),
		GrantTypes:              string(grantTypesJSON),
		ResponseTypes:           string(responseTypesJSON),
		Scopes:                  string(scopesJSON),
		TokenEndpointAuthMethod: record.TokenEndpointAuthMethod,
		ClientSecretHash:        secretHash,
		CreatedAt:               formatSQLiteTime(createdAt),
	}); err != nil {
		return fmt.Errorf("insert oauth client %s: %w", record.ID, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	record, err := s.queries.GetOAuthClient(ctx, platformdb.GetOAuthClientParams{ClientID: id})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("oauth client not found")
		}
		return nil, fmt.Errorf("load oauth client %s: %w", id, err)
	}
	if record.DisabledAt.Valid {
		return nil, fmt.Errorf("oauth client is disabled")
	}
	redirectURIs, err := unmarshalStringSliceJSON([]byte(record.RedirectUris))
	if err != nil {
		return nil, fmt.Errorf("decode redirect uris for client %s: %w", id, err)
	}
	scopes, err := unmarshalStringSliceJSON([]byte(record.Scopes))
	if err != nil {
		return nil, fmt.Errorf("decode scopes for client %s: %w", id, err)
	}
	userID := ""
	if record.CreatedBySubjectSub.Valid {
		userID = record.CreatedBySubjectSub.String
	}
	if record.TokenEndpointAuthMethod == tokenEndpointAuthMethodNone || !record.ClientSecretHash.Valid || strings.TrimSpace(record.ClientSecretHash.String) == "" {
		return confidentialClient{id: id, domain: firstRedirectURI(redirectURIs), userID: userID, scopes: scopes}, nil
	}
	return confidentialClient{
		id:         id,
		domain:     firstRedirectURI(redirectURIs),
		userID:     userID,
		secretHash: record.ClientSecretHash.String,
		scopes:     scopes,
	}, nil
}

func (s *sqliteEdgeStateStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	if info == nil {
		return fmt.Errorf("token info is required")
	}
	if strings.TrimSpace(info.GetUserID()) != "" {
		if err := s.ensureSubject(ctx, IdentityClaims{Sub: info.GetUserID()}); err != nil {
			return err
		}
	}
	sessionID := tokenInfoSessionID(info)
	if sessionID == "" {
		sessionID = ids.New().String()
		setTokenInfoSessionID(info, sessionID)
	}
	parsedSessionID, err := ids.Parse(sessionID)
	if err != nil {
		return fmt.Errorf("parse oauth session id: %w", err)
	}
	serviceID := singleServiceIDFromScope(info.GetScope())
	codeHash, codeCiphertext, err := s.encryptOpaqueValue(info.GetCode())
	if err != nil {
		return err
	}
	accessHash, accessCiphertext, err := s.encryptOpaqueValue(info.GetAccess())
	if err != nil {
		return err
	}
	refreshHash, refreshCiphertext, err := s.encryptOpaqueValue(info.GetRefresh())
	if err != nil {
		return err
	}
	expiresAt := buildTokenSessionExpiry(info)
	if err := s.queries.UpsertOAuthSession(ctx, platformdb.UpsertOAuthSessionParams{
		SessionID:                   parsedSessionID.Bytes(),
		SubjectSub:                  info.GetUserID(),
		ClientID:                    info.GetClientID(),
		ServiceID:                   serviceID,
		RedirectUri:                 info.GetRedirectURI(),
		Scope:                       info.GetScope(),
		CodeChallenge:               info.GetCodeChallenge(),
		CodeChallengeMethod:         string(info.GetCodeChallengeMethod()),
		AuthorizationCodeHash:       codeHash,
		AuthorizationCodeCiphertext: codeCiphertext,
		AccessTokenHash:             accessHash,
		AccessTokenCiphertext:       accessCiphertext,
		RefreshTokenHash:            refreshHash,
		RefreshTokenCiphertext:      refreshCiphertext,
		CodeCreateAt:                sqliteNullTime(info.GetCodeCreateAt()),
		CodeExpiresInSeconds:        durationToSeconds(info.GetCodeExpiresIn()),
		AccessCreateAt:              sqliteNullTime(info.GetAccessCreateAt()),
		AccessExpiresInSeconds:      durationToSeconds(info.GetAccessExpiresIn()),
		RefreshCreateAt:             sqliteNullTime(info.GetRefreshCreateAt()),
		RefreshExpiresInSeconds:     durationToSeconds(info.GetRefreshExpiresIn()),
		ExpiresAt:                   sqliteNullTimePtr(expiresAt),
	}); err != nil {
		return fmt.Errorf("persist oauth session %s: %w", sessionID, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) RemoveByCode(ctx context.Context, code string) error {
	if strings.TrimSpace(code) == "" {
		return nil
	}
	if err := s.queries.DeleteOAuthSessionByCodeHash(ctx, platformdb.DeleteOAuthSessionByCodeHashParams{AuthorizationCodeHash: sql.NullString{String: hashOpaqueValue(code), Valid: true}}); err != nil {
		return fmt.Errorf("remove oauth session by code: %w", err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) RemoveByAccess(ctx context.Context, access string) error {
	if strings.TrimSpace(access) == "" {
		return nil
	}
	if err := s.queries.DeleteOAuthSessionByAccessHash(ctx, platformdb.DeleteOAuthSessionByAccessHashParams{AccessTokenHash: sql.NullString{String: hashOpaqueValue(access), Valid: true}}); err != nil {
		return fmt.Errorf("remove oauth session by access token: %w", err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	if strings.TrimSpace(refresh) == "" {
		return nil
	}
	if err := s.queries.DeleteOAuthSessionByRefreshHash(ctx, platformdb.DeleteOAuthSessionByRefreshHashParams{RefreshTokenHash: sql.NullString{String: hashOpaqueValue(refresh), Valid: true}}); err != nil {
		return fmt.Errorf("remove oauth session by refresh token: %w", err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	record, err := s.consumeTokenRecord(ctx, "authorization_code_hash", code)
	if err != nil || record == nil {
		return nil, err
	}
	if err := s.validateOAuthSessionAuthorization(ctx, *record); err != nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, code, "", "")
}

func (s *sqliteEdgeStateStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	record, err := s.lookupTokenRecord(ctx, "access_token_hash", access)
	if err != nil || record == nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, "", access, "")
}

func (s *sqliteEdgeStateStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	preflight, err := s.lookupTokenRecord(ctx, "refresh_token_hash", refresh)
	if err != nil || preflight == nil {
		return nil, err
	}
	if err := validateRefreshClientBinding(ctx, preflight.ClientID); err != nil {
		return nil, err
	}
	if err := s.validateOAuthSessionAuthorization(ctx, *preflight); err != nil {
		return nil, err
	}
	record, err := s.consumeTokenRecord(ctx, "refresh_token_hash", refresh)
	if err != nil || record == nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, "", "", refresh)
}

func validateRefreshClientBinding(ctx context.Context, tokenClientID string) error {
	expectedClientID, _ := ctx.Value(refreshClientIDContextKey{}).(string)
	if expectedClientID == "" || expectedClientID == tokenClientID {
		return nil
	}
	return fmt.Errorf("refresh token was not issued to this OAuth client")
}

func (s *sqliteEdgeStateStore) PutPendingLogin(ctx context.Context, pending pendingLogin) error {
	if err := s.queries.PutPendingLogin(ctx, platformdb.PutPendingLoginParams{State: pending.State, ReturnTo: pending.ReturnTo, Nonce: pending.Nonce, ExpiresAt: formatSQLiteTime(pending.Expiry)}); err != nil {
		return fmt.Errorf("persist pending login %s: %w", pending.State, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) GetPendingLogin(ctx context.Context, state string, now time.Time) (pendingLogin, bool, error) {
	row, err := s.queries.GetPendingLogin(ctx, platformdb.GetPendingLoginParams{State: state})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return pendingLogin{}, false, nil
		}
		return pendingLogin{}, false, fmt.Errorf("consume pending login %s: %w", state, err)
	}
	expiresAt, err := parseSQLiteTime(row.ExpiresAt)
	if err != nil {
		return pendingLogin{}, false, fmt.Errorf("parse pending login expiry %s: %w", state, err)
	}
	record := pendingLogin{State: row.State, ReturnTo: row.ReturnTo, Nonce: row.Nonce, Expiry: expiresAt}
	if record.Expiry.Before(now) {
		return pendingLogin{}, false, nil
	}
	return record, true, nil
}

func (s *sqliteEdgeStateStore) DeletePendingLogin(ctx context.Context, state string) error {
	if err := s.queries.DeletePendingLogin(ctx, platformdb.DeletePendingLoginParams{State: state}); err != nil {
		return fmt.Errorf("delete pending login %s: %w", state, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) PutBrowserSession(ctx context.Context, sessionID string, session browserSession) error {
	if err := s.ensureSubject(ctx, session.Claims); err != nil {
		return err
	}
	claimsJSON, err := json.Marshal(session.Claims)
	if err != nil {
		return fmt.Errorf("marshal browser session claims: %w", err)
	}
	if err := s.queries.PutBrowserSession(ctx, platformdb.PutBrowserSessionParams{SessionID: sessionID, SubjectSub: session.Claims.Sub, Claims: string(claimsJSON), ExpiresAt: formatSQLiteTime(session.Expiry)}); err != nil {
		return fmt.Errorf("persist browser session %s: %w", sessionID, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) GetBrowserSession(ctx context.Context, sessionID string, now time.Time) (browserSession, bool, error) {
	row, err := s.queries.GetBrowserSession(ctx, platformdb.GetBrowserSessionParams{SessionID: sessionID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return browserSession{}, false, nil
		}
		return browserSession{}, false, fmt.Errorf("load browser session %s: %w", sessionID, err)
	}
	expiry, err := parseSQLiteTime(row.ExpiresAt)
	if err != nil {
		return browserSession{}, false, fmt.Errorf("parse browser session expiry %s: %w", sessionID, err)
	}
	if expiry.Before(now) {
		if deleteErr := s.queries.DeleteBrowserSession(ctx, platformdb.DeleteBrowserSessionParams{SessionID: sessionID}); deleteErr != nil {
			s.logger.Warn().Err(deleteErr).Str("session_id", sessionID).Msg("failed to delete expired browser session")
		}
		return browserSession{}, false, nil
	}
	var claims IdentityClaims
	if err := json.Unmarshal([]byte(row.Claims), &claims); err != nil {
		return browserSession{}, false, fmt.Errorf("decode browser session claims %s: %w", sessionID, err)
	}
	return browserSession{
		Claims: claims,
		Expiry: expiry,
	}, true, nil
}

func (s *sqliteEdgeStateStore) UpsertSubject(ctx context.Context, claims IdentityClaims) error {
	return s.ensureSubject(ctx, claims)
}

func (s *sqliteEdgeStateStore) Allowed(ctx context.Context, subjectSub string, serviceID string) (bool, error) {
	allowed, err := s.queries.AllowedServiceGrant(ctx, platformdb.AllowedServiceGrantParams{SubjectSub: subjectSub, ServiceID: serviceID})
	if err != nil {
		return false, fmt.Errorf("check service grant %s/%s: %w", subjectSub, serviceID, err)
	}
	return allowed != 0, nil
}

func (s *sqliteEdgeStateStore) AllowedScopes(ctx context.Context, subjectSub string, scope string) (bool, error) {
	serviceIDs, valid := parseRequestedServiceScopes(scope)
	if !valid {
		return false, nil
	}
	count, err := s.queries.CountAllowedServiceGrants(ctx, platformdb.CountAllowedServiceGrantsParams{SubjectSub: subjectSub, ServiceIds: serviceIDs})
	if err != nil {
		return false, fmt.Errorf("check scope grants for %s: %w", subjectSub, err)
	}
	return int(count) == len(serviceIDs), nil
}

func (s *sqliteEdgeStateStore) ListEnabledServiceCatalog(ctx context.Context) ([]catalog.ServiceCatalogEntry, error) {
	rows, err := s.queries.ListEnabledServiceCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("list enabled service catalog: %w", err)
	}
	entries := make([]catalog.ServiceCatalogEntry, 0, len(rows))
	for _, row := range rows {
		entry := catalog.ServiceCatalogEntry{
			ServiceID:              row.ServiceID,
			DisplayName:            row.DisplayName,
			UpstreamServiceName:    row.UpstreamServiceName,
			TransportType:          catalog.TransportType(row.TransportType),
			InternalPort:           int(row.InternalPort),
			PublicPath:             row.PublicPath,
			InternalUpstreamPath:   row.InternalUpstreamPath,
			HealthPath:             row.HealthPath,
			HealthProbeExpectation: row.HealthProbeExpectation,
			ResourceProfile:        row.ResourceProfile,
			PersistencePolicy:      row.PersistencePolicy,
			AdapterRequirement:     catalog.AdapterRequirement(row.AdapterRequirement),
		}
		if err := json.Unmarshal([]byte(row.SecretContract), &entry.SecretContract); err != nil {
			return nil, fmt.Errorf("decode secret contract for %s: %w", entry.ServiceID, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *sqliteEdgeStateStore) RecordAuditEvent(ctx context.Context, event edgeAuditEvent) error {
	payload := event.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal audit event payload: %w", err)
	}

	correlationID := strings.TrimSpace(event.CorrelationID)
	if correlationID == "" {
		correlationID = "unknown"
	}
	eventType := strings.TrimSpace(event.EventType)
	if eventType == "" {
		return fmt.Errorf("audit event type is required")
	}
	eventStatus := strings.TrimSpace(event.EventStatus)
	if eventStatus == "" {
		eventStatus = "unknown"
	}

	var actorSubjectSub sql.NullString
	if value := strings.TrimSpace(event.ActorSubjectSub); value != "" {
		actorSubjectSub = sql.NullString{String: value, Valid: true}
	}
	var serviceID sql.NullString
	if value := strings.TrimSpace(event.ServiceID); value != "" {
		serviceID = sql.NullString{String: value, Valid: true}
	}

	if err := s.queries.InsertAuditEvent(ctx, platformdb.InsertAuditEventParams{EventID: ids.New().Bytes(), CorrelationID: correlationID, ActorSubjectSub: actorSubjectSub, ServiceID: serviceID, EventType: eventType, EventStatus: eventStatus, Payload: string(payloadRaw)}); err != nil {
		return fmt.Errorf("insert audit event %s: %w", eventType, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *sqliteEdgeStateStore) Close() error {
	return s.db.Close()
}

func (s *sqliteEdgeStateStore) ensureSubject(ctx context.Context, claims IdentityClaims) error {
	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return nil
	}
	subjectKey := domain.DeriveSubjectKey(sub)
	if err := s.queries.EdgeUpsertSubject(ctx, platformdb.EdgeUpsertSubjectParams{SubjectSub: sub, SubjectKey: subjectKey, PreferredUsername: claims.PreferredUsername, Email: claims.Email, DisplayName: firstNonEmpty(strings.TrimSpace(claims.Name), strings.TrimSpace(claims.PreferredUsername))}); err != nil {
		return fmt.Errorf("upsert subject %s: %w", sub, err)
	}
	return nil
}

func (s *sqliteEdgeStateStore) encryptOpaqueValue(value string) (sql.NullString, []byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return sql.NullString{}, nil, nil
	}
	ciphertext, err := s.cipher.EncryptString(value)
	if err != nil {
		return sql.NullString{}, nil, fmt.Errorf("encrypt opaque value: %w", err)
	}
	hash := hashOpaqueValue(value)
	return sql.NullString{String: hash, Valid: true}, ciphertext, nil
}

func (s *sqliteEdgeStateStore) lookupTokenRecord(ctx context.Context, hashColumn string, rawValue string) (*oauthSessionRecord, error) {
	if strings.TrimSpace(rawValue) == "" {
		return nil, nil
	}
	hash := sql.NullString{String: hashOpaqueValue(rawValue), Valid: true}
	var record oauthSessionRecord
	switch hashColumn {
	case "access_token_hash":
		row, err := s.queries.GetOAuthSessionByAccessHash(ctx, platformdb.GetOAuthSessionByAccessHashParams{AccessTokenHash: hash})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		record, err = oauthSessionRecordFromAccessRow(row)
		if err != nil {
			return nil, err
		}
	case "refresh_token_hash":
		row, err := s.queries.GetOAuthSessionByRefreshHash(ctx, platformdb.GetOAuthSessionByRefreshHashParams{RefreshTokenHash: hash})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		record, err = oauthSessionRecordFromRefreshLookupRow(row)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported oauth session lookup column %q", hashColumn)
	}
	return &record, nil
}

func (s *sqliteEdgeStateStore) consumeTokenRecord(ctx context.Context, hashColumn string, rawValue string) (*oauthSessionRecord, error) {
	if strings.TrimSpace(rawValue) == "" {
		return nil, nil
	}
	hash := sql.NullString{String: hashOpaqueValue(rawValue), Valid: true}
	var record oauthSessionRecord
	switch hashColumn {
	case "authorization_code_hash":
		row, err := s.queries.ConsumeOAuthSessionByCodeHash(ctx, platformdb.ConsumeOAuthSessionByCodeHashParams{AuthorizationCodeHash: hash})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		record, err = oauthSessionRecordFromCodeRow(row)
		if err != nil {
			return nil, err
		}
	case "refresh_token_hash":
		row, err := s.queries.ConsumeOAuthSessionByRefreshHash(ctx, platformdb.ConsumeOAuthSessionByRefreshHashParams{RefreshTokenHash: hash})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return nil, err
		}
		record, err = oauthSessionRecordFromRefreshRow(row)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported oauth session consume column %q", hashColumn)
	}
	return &record, nil
}

func oauthSessionRecordFromAccessRow(row platformdb.GetOAuthSessionByAccessHashRow) (oauthSessionRecord, error) {
	sessionID, err := ids.ParseBytes(row.SessionID)
	if err != nil {
		return oauthSessionRecord{}, fmt.Errorf("parse oauth session id: %w", err)
	}
	return oauthSessionRecord{
		SessionID:                   sessionID.String(),
		SubjectSub:                  stringPtrFromNull(row.SubjectSub),
		ClientID:                    row.ClientID,
		ServiceID:                   stringPtrFromNull(row.ServiceID),
		RedirectURI:                 row.RedirectUri,
		Scope:                       row.Scope,
		CodeChallenge:               stringPtrFromNull(row.CodeChallenge),
		CodeChallengeMethod:         stringPtrFromNull(row.CodeChallengeMethod),
		AuthorizationCodeHash:       stringPtrFromNull(row.AuthorizationCodeHash),
		AuthorizationCodeCiphertext: row.AuthorizationCodeCiphertext,
		AccessTokenHash:             stringPtrFromNull(row.AccessTokenHash),
		AccessTokenCiphertext:       row.AccessTokenCiphertext,
		RefreshTokenHash:            stringPtrFromNull(row.RefreshTokenHash),
		RefreshTokenCiphertext:      row.RefreshTokenCiphertext,
		CodeCreateAt:                timePtrFromNull(row.CodeCreateAt),
		CodeExpiresInSeconds:        row.CodeExpiresInSeconds,
		AccessCreateAt:              timePtrFromNull(row.AccessCreateAt),
		AccessExpiresInSeconds:      row.AccessExpiresInSeconds,
		RefreshCreateAt:             timePtrFromNull(row.RefreshCreateAt),
		RefreshExpiresInSeconds:     row.RefreshExpiresInSeconds,
		ExpiresAt:                   timePtrFromNull(row.ExpiresAt),
	}, nil
}

func oauthSessionRecordFromCodeRow(row platformdb.ConsumeOAuthSessionByCodeHashRow) (oauthSessionRecord, error) {
	return oauthSessionRecordFromAccessRow(platformdb.GetOAuthSessionByAccessHashRow(row))
}

func oauthSessionRecordFromRefreshRow(row platformdb.ConsumeOAuthSessionByRefreshHashRow) (oauthSessionRecord, error) {
	return oauthSessionRecordFromAccessRow(platformdb.GetOAuthSessionByAccessHashRow(row))
}

func oauthSessionRecordFromRefreshLookupRow(row platformdb.GetOAuthSessionByRefreshHashRow) (oauthSessionRecord, error) {
	return oauthSessionRecordFromAccessRow(platformdb.GetOAuthSessionByAccessHashRow(row))
}

func (s *sqliteEdgeStateStore) validateOAuthSessionAuthorization(ctx context.Context, record oauthSessionRecord) error {
	clientInfo, err := s.GetByID(ctx, record.ClientID)
	if err != nil {
		return err
	}
	if !clientAllowsScope(clientInfo, record.Scope) {
		return fmt.Errorf("oauth client is not registered for requested scope")
	}
	if record.SubjectSub != nil && strings.TrimSpace(record.Scope) != "" {
		allowed, err := s.AllowedScopes(ctx, *record.SubjectSub, record.Scope)
		if err != nil {
			return err
		}
		if !allowed {
			return fmt.Errorf("requested scope is not granted for this subject")
		}
	}
	return nil
}

func (s *sqliteEdgeStateStore) buildTokenInfo(record oauthSessionRecord, rawCode string, rawAccess string, rawRefresh string) (oauth2.TokenInfo, error) {
	token := models.NewToken()
	setTokenInfoSessionID(token, record.SessionID)
	token.SetClientID(record.ClientID)
	if record.SubjectSub != nil {
		token.SetUserID(*record.SubjectSub)
	}
	token.SetRedirectURI(record.RedirectURI)
	token.SetScope(record.Scope)
	if record.CodeChallenge != nil {
		token.SetCodeChallenge(*record.CodeChallenge)
	}
	if record.CodeChallengeMethod != nil {
		token.SetCodeChallengeMethod(oauth2.CodeChallengeMethod(*record.CodeChallengeMethod))
	}
	if record.CodeCreateAt != nil {
		token.SetCodeCreateAt(record.CodeCreateAt.UTC())
	}
	token.SetCodeExpiresIn(durationFromSeconds(record.CodeExpiresInSeconds))
	if record.AccessCreateAt != nil {
		token.SetAccessCreateAt(record.AccessCreateAt.UTC())
	}
	token.SetAccessExpiresIn(durationFromSeconds(record.AccessExpiresInSeconds))
	if record.RefreshCreateAt != nil {
		token.SetRefreshCreateAt(record.RefreshCreateAt.UTC())
	}
	token.SetRefreshExpiresIn(durationFromSeconds(record.RefreshExpiresInSeconds))

	if record.AuthorizationCodeHash != nil {
		if strings.TrimSpace(rawCode) == "" {
			value, err := s.cipher.DecryptString(record.AuthorizationCodeCiphertext)
			if err != nil {
				return nil, err
			}
			rawCode = value
		}
		token.SetCode(rawCode)
	}
	if record.AccessTokenHash != nil {
		if strings.TrimSpace(rawAccess) == "" {
			value, err := s.cipher.DecryptString(record.AccessTokenCiphertext)
			if err != nil {
				return nil, err
			}
			rawAccess = value
		}
		token.SetAccess(rawAccess)
	}
	if record.RefreshTokenHash != nil {
		if strings.TrimSpace(rawRefresh) == "" {
			value, err := s.cipher.DecryptString(record.RefreshTokenCiphertext)
			if err != nil {
				return nil, err
			}
			rawRefresh = value
		}
		token.SetRefresh(rawRefresh)
	}
	return token, nil
}
