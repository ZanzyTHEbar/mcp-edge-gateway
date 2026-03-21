package edge

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"dragonserver/mcp-platform/internal/domain"

	oauth2 "github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/models"
	oauth2store "github.com/go-oauth2/oauth2/v4/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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
	Ping(context.Context) error
	Close() error
}

type memoryEdgeStateStore struct {
	clientStore oauth2.ClientStore
	tokenStore  oauth2.TokenStore

	mu            sync.RWMutex
	pendingLogins map[string]pendingLogin
	sessions      map[string]browserSession
	subjects      map[string]IdentityClaims
}

type postgresEdgeStateStore struct {
	logger zerolog.Logger
	pool   *pgxpool.Pool
	cipher *opaqueCipher
}

type confidentialClient struct {
	id         string
	domain     string
	userID     string
	secretHash string
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
	return newPostgresEdgeStateStore(ctx, cfg, logger)
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
	}, nil
}

func newPostgresEdgeStateStore(ctx context.Context, cfg Config, logger zerolog.Logger) (*postgresEdgeStateStore, error) {
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
	pool, err := pgxpool.New(ctx, strings.TrimSpace(cfg.PlatformDatabaseURL))
	if err != nil {
		return nil, fmt.Errorf("open edge postgres pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping edge postgres pool: %w", err)
	}
	return &postgresEdgeStateStore{
		logger: logger,
		pool:   pool,
		cipher: cipherValue,
	}, nil
}

func (s *memoryEdgeStateStore) CreateClient(ctx context.Context, record registeredClient, _ string) error {
	client := &models.Client{
		ID:     record.ID,
		Secret: record.Secret,
		Domain: firstRedirectURI(record.RedirectURIs),
		Public: record.TokenEndpointAuthMethod == tokenEndpointAuthMethodNone,
	}
	if storeValue, ok := s.clientStore.(*oauth2store.ClientStore); ok {
		return storeValue.Set(record.ID, client)
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
	return s.tokenStore.GetByCode(ctx, code)
}

func (s *memoryEdgeStateStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return s.tokenStore.GetByAccess(ctx, access)
}

func (s *memoryEdgeStateStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	return s.tokenStore.GetByRefresh(ctx, refresh)
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

func (s *memoryEdgeStateStore) Ping(context.Context) error {
	return nil
}

func (s *memoryEdgeStateStore) Close() error {
	return nil
}

func (c confidentialClient) GetID() string     { return c.id }
func (c confidentialClient) GetSecret() string { return "" }
func (c confidentialClient) GetDomain() string { return c.domain }
func (c confidentialClient) IsPublic() bool    { return false }
func (c confidentialClient) GetUserID() string { return c.userID }

func (c confidentialClient) VerifyPassword(secret string) bool {
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

func nullableTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copyValue := value.UTC()
	return &copyValue
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

func (s *postgresEdgeStateStore) CreateClient(ctx context.Context, record registeredClient, createdBySubjectSub string) error {
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
	var secretHash *string
	if strings.TrimSpace(record.Secret) != "" {
		hash := hashOpaqueValue(record.Secret)
		secretHash = &hash
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
	_, err = s.pool.Exec(
		ctx,
		`
			insert into oauth_clients (
				client_id,
				client_name,
				created_by_subject_sub,
				redirect_uris,
				grant_types,
				response_types,
				scopes,
				token_endpoint_auth_method,
				client_secret_hash,
				metadata,
				created_at,
				updated_at
			) values ($1, $2, nullif($3, ''), $4::jsonb, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9, '{}'::jsonb, $10, $10)
		`,
		record.ID,
		record.Name,
		createdBySubjectSub,
		redirectURIsJSON,
		grantTypesJSON,
		responseTypesJSON,
		scopesJSON,
		record.TokenEndpointAuthMethod,
		secretHash,
		createdAt,
	)
	if err != nil {
		return fmt.Errorf("insert oauth client %s: %w", record.ID, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	var (
		redirectURIsRaw []byte
		createdBy       *string
		authMethod      string
		secretHash      *string
		disabledAt      *time.Time
	)
	err := s.pool.QueryRow(
		ctx,
		`
			select
				redirect_uris,
				created_by_subject_sub,
				token_endpoint_auth_method,
				client_secret_hash,
				disabled_at
			from oauth_clients
			where client_id = $1
		`,
		id,
	).Scan(&redirectURIsRaw, &createdBy, &authMethod, &secretHash, &disabledAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("oauth client not found")
		}
		return nil, fmt.Errorf("load oauth client %s: %w", id, err)
	}
	if disabledAt != nil {
		return nil, fmt.Errorf("oauth client is disabled")
	}
	redirectURIs, err := unmarshalStringSliceJSON(redirectURIsRaw)
	if err != nil {
		return nil, fmt.Errorf("decode redirect uris for client %s: %w", id, err)
	}
	userID := ""
	if createdBy != nil {
		userID = *createdBy
	}
	if authMethod == tokenEndpointAuthMethodNone || secretHash == nil || strings.TrimSpace(*secretHash) == "" {
		return &models.Client{
			ID:     id,
			Domain: firstRedirectURI(redirectURIs),
			Public: true,
			UserID: userID,
		}, nil
	}
	return confidentialClient{
		id:         id,
		domain:     firstRedirectURI(redirectURIs),
		userID:     userID,
		secretHash: *secretHash,
	}, nil
}

func (s *postgresEdgeStateStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
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
		sessionID = uuid.NewString()
		setTokenInfoSessionID(info, sessionID)
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
	_, err = s.pool.Exec(
		ctx,
		`
			insert into oauth_sessions (
				session_id,
				subject_sub,
				client_id,
				service_id,
				redirect_uri,
				scope,
				code_challenge,
				code_challenge_method,
				authorization_code_hash,
				authorization_code_ciphertext,
				access_token_hash,
				access_token_ciphertext,
				refresh_token_hash,
				refresh_token_ciphertext,
				code_create_at,
				code_expires_in_seconds,
				access_create_at,
				access_expires_in_seconds,
				refresh_create_at,
				refresh_expires_in_seconds,
				expires_at,
				consumed_at,
				updated_at
			) values (
				$1,
				nullif($2, ''),
				$3,
				nullif($4, ''),
				$5,
				$6,
				nullif($7, ''),
				nullif($8, ''),
				$9,
				$10,
				$11,
				$12,
				$13,
				$14,
				$15,
				$16,
				$17,
				$18,
				$19,
				$20,
				$21,
				null,
				now()
			)
			on conflict (session_id) do update set
				subject_sub = excluded.subject_sub,
				client_id = excluded.client_id,
				service_id = excluded.service_id,
				redirect_uri = excluded.redirect_uri,
				scope = excluded.scope,
				code_challenge = excluded.code_challenge,
				code_challenge_method = excluded.code_challenge_method,
				authorization_code_hash = excluded.authorization_code_hash,
				authorization_code_ciphertext = excluded.authorization_code_ciphertext,
				access_token_hash = excluded.access_token_hash,
				access_token_ciphertext = excluded.access_token_ciphertext,
				refresh_token_hash = excluded.refresh_token_hash,
				refresh_token_ciphertext = excluded.refresh_token_ciphertext,
				code_create_at = excluded.code_create_at,
				code_expires_in_seconds = excluded.code_expires_in_seconds,
				access_create_at = excluded.access_create_at,
				access_expires_in_seconds = excluded.access_expires_in_seconds,
				refresh_create_at = excluded.refresh_create_at,
				refresh_expires_in_seconds = excluded.refresh_expires_in_seconds,
				expires_at = excluded.expires_at,
				consumed_at = null,
				updated_at = now()
		`,
		sessionID,
		info.GetUserID(),
		info.GetClientID(),
		serviceID,
		info.GetRedirectURI(),
		info.GetScope(),
		info.GetCodeChallenge(),
		string(info.GetCodeChallengeMethod()),
		codeHash,
		codeCiphertext,
		accessHash,
		accessCiphertext,
		refreshHash,
		refreshCiphertext,
		nullableTime(info.GetCodeCreateAt()),
		durationToSeconds(info.GetCodeExpiresIn()),
		nullableTime(info.GetAccessCreateAt()),
		durationToSeconds(info.GetAccessExpiresIn()),
		nullableTime(info.GetRefreshCreateAt()),
		durationToSeconds(info.GetRefreshExpiresIn()),
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("persist oauth session %s: %w", sessionID, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) RemoveByCode(ctx context.Context, code string) error {
	if strings.TrimSpace(code) == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `delete from oauth_sessions where authorization_code_hash = $1`, hashOpaqueValue(code))
	if err != nil {
		return fmt.Errorf("remove oauth session by code: %w", err)
	}
	return nil
}

func (s *postgresEdgeStateStore) RemoveByAccess(ctx context.Context, access string) error {
	if strings.TrimSpace(access) == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `delete from oauth_sessions where access_token_hash = $1`, hashOpaqueValue(access))
	if err != nil {
		return fmt.Errorf("remove oauth session by access token: %w", err)
	}
	return nil
}

func (s *postgresEdgeStateStore) RemoveByRefresh(ctx context.Context, refresh string) error {
	if strings.TrimSpace(refresh) == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `delete from oauth_sessions where refresh_token_hash = $1`, hashOpaqueValue(refresh))
	if err != nil {
		return fmt.Errorf("remove oauth session by refresh token: %w", err)
	}
	return nil
}

func (s *postgresEdgeStateStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	record, err := s.consumeTokenRecord(ctx, "authorization_code_hash", code)
	if err != nil || record == nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, code, "", "")
}

func (s *postgresEdgeStateStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	record, err := s.lookupTokenRecord(ctx, "access_token_hash", access)
	if err != nil || record == nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, "", access, "")
}

func (s *postgresEdgeStateStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	record, err := s.consumeTokenRecord(ctx, "refresh_token_hash", refresh)
	if err != nil || record == nil {
		return nil, err
	}
	return s.buildTokenInfo(*record, "", "", refresh)
}

func (s *postgresEdgeStateStore) PutPendingLogin(ctx context.Context, pending pendingLogin) error {
	_, err := s.pool.Exec(
		ctx,
		`
			insert into edge_pending_logins (
				state,
				return_to,
				nonce,
				expires_at,
				updated_at
			) values ($1, $2, $3, $4, now())
			on conflict (state) do update set
				return_to = excluded.return_to,
				nonce = excluded.nonce,
				expires_at = excluded.expires_at,
				updated_at = now()
		`,
		pending.State,
		pending.ReturnTo,
		pending.Nonce,
		pending.Expiry,
	)
	if err != nil {
		return fmt.Errorf("persist pending login %s: %w", pending.State, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) GetPendingLogin(ctx context.Context, state string, now time.Time) (pendingLogin, bool, error) {
	var record pendingLogin
	err := s.pool.QueryRow(
		ctx,
		`
			select state, return_to, nonce, expires_at
			from edge_pending_logins
			where state = $1
		`,
		state,
	).Scan(&record.State, &record.ReturnTo, &record.Nonce, &record.Expiry)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return pendingLogin{}, false, nil
		}
		return pendingLogin{}, false, fmt.Errorf("consume pending login %s: %w", state, err)
	}
	if record.Expiry.Before(now) {
		return pendingLogin{}, false, nil
	}
	return record, true, nil
}

func (s *postgresEdgeStateStore) DeletePendingLogin(ctx context.Context, state string) error {
	if _, err := s.pool.Exec(ctx, `delete from edge_pending_logins where state = $1`, state); err != nil {
		return fmt.Errorf("delete pending login %s: %w", state, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) PutBrowserSession(ctx context.Context, sessionID string, session browserSession) error {
	if err := s.ensureSubject(ctx, session.Claims); err != nil {
		return err
	}
	claimsJSON, err := json.Marshal(session.Claims)
	if err != nil {
		return fmt.Errorf("marshal browser session claims: %w", err)
	}
	_, err = s.pool.Exec(
		ctx,
		`
			insert into edge_browser_sessions (
				session_id,
				subject_sub,
				claims,
				expires_at,
				updated_at
			) values ($1, nullif($2, ''), $3::jsonb, $4, now())
			on conflict (session_id) do update set
				subject_sub = excluded.subject_sub,
				claims = excluded.claims,
				expires_at = excluded.expires_at,
				updated_at = now()
		`,
		sessionID,
		session.Claims.Sub,
		claimsJSON,
		session.Expiry,
	)
	if err != nil {
		return fmt.Errorf("persist browser session %s: %w", sessionID, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) GetBrowserSession(ctx context.Context, sessionID string, now time.Time) (browserSession, bool, error) {
	var (
		claimsRaw []byte
		expiry    time.Time
	)
	err := s.pool.QueryRow(
		ctx,
		`
			select claims, expires_at
			from edge_browser_sessions
			where session_id = $1
		`,
		sessionID,
	).Scan(&claimsRaw, &expiry)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return browserSession{}, false, nil
		}
		return browserSession{}, false, fmt.Errorf("load browser session %s: %w", sessionID, err)
	}
	if expiry.Before(now) {
		if _, deleteErr := s.pool.Exec(ctx, `delete from edge_browser_sessions where session_id = $1`, sessionID); deleteErr != nil {
			s.logger.Warn().Err(deleteErr).Str("session_id", sessionID).Msg("failed to delete expired browser session")
		}
		return browserSession{}, false, nil
	}
	var claims IdentityClaims
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		return browserSession{}, false, fmt.Errorf("decode browser session claims %s: %w", sessionID, err)
	}
	return browserSession{
		Claims: claims,
		Expiry: expiry,
	}, true, nil
}

func (s *postgresEdgeStateStore) UpsertSubject(ctx context.Context, claims IdentityClaims) error {
	return s.ensureSubject(ctx, claims)
}

func (s *postgresEdgeStateStore) Allowed(ctx context.Context, subjectSub string, serviceID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(
		ctx,
		`
			select exists (
				select 1
				from service_grants
				join service_catalog on service_catalog.service_id = service_grants.service_id
				where service_grants.subject_sub = $1
					and service_grants.service_id = $2
					and service_catalog.enabled = true
			)
		`,
		subjectSub,
		serviceID,
	).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check service grant %s/%s: %w", subjectSub, serviceID, err)
	}
	return allowed, nil
}

func (s *postgresEdgeStateStore) AllowedScopes(ctx context.Context, subjectSub string, scope string) (bool, error) {
	serviceIDs, valid := parseRequestedServiceScopes(scope)
	if !valid {
		return false, nil
	}
	var count int
	err := s.pool.QueryRow(
		ctx,
		`
			select count(distinct service_grants.service_id)
			from service_grants
			join service_catalog on service_catalog.service_id = service_grants.service_id
			where service_grants.subject_sub = $1
				and service_catalog.enabled = true
				and service_grants.service_id = any($2)
		`,
		subjectSub,
		serviceIDs,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("check scope grants for %s: %w", subjectSub, err)
	}
	return count == len(serviceIDs), nil
}

func (s *postgresEdgeStateStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *postgresEdgeStateStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *postgresEdgeStateStore) ensureSubject(ctx context.Context, claims IdentityClaims) error {
	sub := strings.TrimSpace(claims.Sub)
	if sub == "" {
		return nil
	}
	subjectKey := domain.DeriveSubjectKey(sub)
	_, err := s.pool.Exec(
		ctx,
		`
			insert into subjects (
				subject_sub,
				subject_key,
				preferred_username,
				email,
				display_name,
				last_synced_at,
				created_at,
				updated_at
			) values ($1, $2, nullif($3, ''), nullif($4, ''), nullif($5, ''), now(), now(), now())
			on conflict (subject_sub) do update set
				subject_key = excluded.subject_key,
				preferred_username = coalesce(excluded.preferred_username, subjects.preferred_username),
				email = coalesce(excluded.email, subjects.email),
				display_name = coalesce(excluded.display_name, subjects.display_name),
				last_synced_at = now(),
				updated_at = now()
		`,
		sub,
		subjectKey,
		claims.PreferredUsername,
		claims.Email,
		firstNonEmpty(strings.TrimSpace(claims.Name), strings.TrimSpace(claims.PreferredUsername)),
	)
	if err != nil {
		return fmt.Errorf("upsert subject %s: %w", sub, err)
	}
	return nil
}

func (s *postgresEdgeStateStore) encryptOpaqueValue(value string) (*string, []byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil, nil
	}
	ciphertext, err := s.cipher.EncryptString(value)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt opaque value: %w", err)
	}
	hash := hashOpaqueValue(value)
	return &hash, ciphertext, nil
}

func (s *postgresEdgeStateStore) lookupTokenRecord(ctx context.Context, hashColumn string, rawValue string) (*oauthSessionRecord, error) {
	if strings.TrimSpace(rawValue) == "" {
		return nil, nil
	}
	switch hashColumn {
	case "authorization_code_hash", "access_token_hash", "refresh_token_hash":
	default:
		return nil, fmt.Errorf("unsupported oauth session lookup column %q", hashColumn)
	}
	row := s.pool.QueryRow(
		ctx,
		fmt.Sprintf(
			`
				select
					session_id::text,
					subject_sub,
					client_id,
					service_id,
					redirect_uri,
					scope,
					code_challenge,
					code_challenge_method,
					authorization_code_hash,
					authorization_code_ciphertext,
					access_token_hash,
					access_token_ciphertext,
					refresh_token_hash,
					refresh_token_ciphertext,
					code_create_at,
					code_expires_in_seconds,
					access_create_at,
					access_expires_in_seconds,
					refresh_create_at,
					refresh_expires_in_seconds,
					expires_at
				from oauth_sessions
				where %s = $1
			`,
			hashColumn,
		),
		hashOpaqueValue(rawValue),
	)
	record, err := scanOAuthSessionRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
}

func (s *postgresEdgeStateStore) consumeTokenRecord(ctx context.Context, hashColumn string, rawValue string) (*oauthSessionRecord, error) {
	if strings.TrimSpace(rawValue) == "" {
		return nil, nil
	}
	switch hashColumn {
	case "authorization_code_hash", "refresh_token_hash":
	default:
		return nil, fmt.Errorf("unsupported oauth session consume column %q", hashColumn)
	}
	row := s.pool.QueryRow(
		ctx,
		fmt.Sprintf(
			`
				update oauth_sessions
				set consumed_at = now(), updated_at = now()
				where %s = $1
					and consumed_at is null
				returning
					session_id::text,
					subject_sub,
					client_id,
					service_id,
					redirect_uri,
					scope,
					code_challenge,
					code_challenge_method,
					authorization_code_hash,
					authorization_code_ciphertext,
					access_token_hash,
					access_token_ciphertext,
					refresh_token_hash,
					refresh_token_ciphertext,
					code_create_at,
					code_expires_in_seconds,
					access_create_at,
					access_expires_in_seconds,
					refresh_create_at,
					refresh_expires_in_seconds,
					expires_at
			`,
			hashColumn,
		),
		hashOpaqueValue(rawValue),
	)
	record, err := scanOAuthSessionRecord(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return record, nil
}

func scanOAuthSessionRecord(row pgx.Row) (*oauthSessionRecord, error) {
	record := &oauthSessionRecord{}
	if err := row.Scan(
		&record.SessionID,
		&record.SubjectSub,
		&record.ClientID,
		&record.ServiceID,
		&record.RedirectURI,
		&record.Scope,
		&record.CodeChallenge,
		&record.CodeChallengeMethod,
		&record.AuthorizationCodeHash,
		&record.AuthorizationCodeCiphertext,
		&record.AccessTokenHash,
		&record.AccessTokenCiphertext,
		&record.RefreshTokenHash,
		&record.RefreshTokenCiphertext,
		&record.CodeCreateAt,
		&record.CodeExpiresInSeconds,
		&record.AccessCreateAt,
		&record.AccessExpiresInSeconds,
		&record.RefreshCreateAt,
		&record.RefreshExpiresInSeconds,
		&record.ExpiresAt,
	); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *postgresEdgeStateStore) buildTokenInfo(record oauthSessionRecord, rawCode string, rawAccess string, rawRefresh string) (oauth2.TokenInfo, error) {
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
