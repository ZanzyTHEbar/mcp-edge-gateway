package edge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/controlplane"
	"dragonserver/mcp-platform/internal/platform/sqlite/platformdb"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestSQLiteEdgeStateStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()
	databaseURL := "file:" + filepath.Join(t.TempDir(), "mcp-platform.db")

	cpStore, err := controlplane.NewStore(ctx, databaseURL, logger)
	require.NoError(t, err)
	require.NoError(t, cpStore.RunMigrations(ctx))
	require.NoError(t, cpStore.SeedServiceCatalog(ctx))

	secretPath := filepath.Join(t.TempDir(), "session-key")
	require.NoError(t, os.WriteFile(secretPath, []byte("test-session-encryption-key"), 0o600))

	storeValue, err := newSQLiteEdgeStateStore(ctx, Config{PlatformDatabaseURL: databaseURL, SessionEncryptionKeyPath: secretPath}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storeValue.Close() })
	t.Cleanup(cpStore.Close)

	entries, err := storeValue.ListEnabledServiceCatalog(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	now := time.Now().UTC().Round(0)
	claims := IdentityClaims{Sub: "sqlite-fixture-user", Email: "fixture@example.com", Name: "Fixture User", PreferredUsername: "fixture-user", Groups: []string{"mcp-users", "mcp-service-mealie"}}
	require.NoError(t, storeValue.UpsertSubject(ctx, claims))
	require.NoError(t, cpStore.ReplaceSubjectGrants(ctx, claims.Sub, []controlplane.ServiceGrant{{SubjectSub: claims.Sub, ServiceID: "mealie", SourceGroup: "mcp-service-mealie", GrantedAt: now, LastSyncedAt: now}}))

	allowed, err := storeValue.Allowed(ctx, claims.Sub, "mealie")
	require.NoError(t, err)
	require.True(t, allowed)
	allowed, err = storeValue.AllowedScopes(ctx, claims.Sub, "mcp:mealie")
	require.NoError(t, err)
	require.True(t, allowed)

	pending := pendingLogin{State: "state-1", ReturnTo: "/oauth/authorize", Nonce: "nonce-1", Expiry: now.Add(time.Minute)}
	require.NoError(t, storeValue.PutPendingLogin(ctx, pending))
	gotPending, ok, err := storeValue.GetPendingLogin(ctx, pending.State, now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, pending, gotPending)
	require.NoError(t, storeValue.DeletePendingLogin(ctx, pending.State))

	session := browserSession{Claims: claims, Expiry: now.Add(time.Hour)}
	require.NoError(t, storeValue.PutBrowserSession(ctx, "session-1", session))
	gotSession, ok, err := storeValue.GetBrowserSession(ctx, "session-1", now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, session, gotSession)

	client := registeredClient{ID: "client-1", Name: "Example Client", RedirectURIs: []string{"https://example.com/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: tokenEndpointAuthMethodClientBasic, Secret: "super-secret", Scopes: []string{"mcp:mealie"}}
	require.NoError(t, storeValue.CreateClient(ctx, client, claims.Sub))
	clientInfo, err := storeValue.GetByID(ctx, client.ID)
	require.NoError(t, err)
	require.Empty(t, clientInfo.GetSecret())
	confidential, ok := clientInfo.(confidentialClient)
	require.True(t, ok)
	require.True(t, confidential.VerifyPassword(client.Secret))
	require.False(t, confidential.VerifyPassword("wrong-secret"))
	require.True(t, clientAllowsScope(clientInfo, "mcp:mealie"))
	require.False(t, clientAllowsScope(clientInfo, "mcp:actualbudget"))

	token := models.NewToken()
	token.SetClientID(client.ID)
	token.SetUserID(claims.Sub)
	token.SetScope("mcp:mealie")
	token.SetAccess("access-token")
	token.SetAccessCreateAt(now)
	token.SetAccessExpiresIn(time.Hour)
	token.SetRefresh("refresh-token")
	token.SetRefreshCreateAt(now)
	token.SetRefreshExpiresIn(2 * time.Hour)
	require.NoError(t, storeValue.Create(ctx, token))

	accessToken, err := storeValue.GetByAccess(ctx, "access-token")
	require.NoError(t, err)
	require.Equal(t, "access-token", accessToken.GetAccess())
	refreshToken, err := storeValue.GetByRefresh(ctx, "refresh-token")
	require.NoError(t, err)
	require.Equal(t, "access-token", refreshToken.GetAccess())
	require.Equal(t, "refresh-token", refreshToken.GetRefresh())

	deniedToken := models.NewToken()
	deniedToken.SetClientID(client.ID)
	deniedToken.SetUserID(claims.Sub)
	deniedToken.SetScope("mcp:actualbudget")
	deniedToken.SetAccess("denied-access-token")
	deniedToken.SetAccessCreateAt(now)
	deniedToken.SetAccessExpiresIn(time.Hour)
	deniedToken.SetRefresh("denied-refresh-token")
	deniedToken.SetRefreshCreateAt(now)
	deniedToken.SetRefreshExpiresIn(2 * time.Hour)
	require.NoError(t, storeValue.Create(ctx, deniedToken))
	_, err = storeValue.GetByRefresh(ctx, "denied-refresh-token")
	require.ErrorContains(t, err, "oauth client is not registered for requested scope")

	otherClient := registeredClient{ID: "client-other", Name: "Other", RedirectURIs: []string{"https://example.com/other"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: tokenEndpointAuthMethodNone, Scopes: []string{"mcp:mealie"}}
	require.NoError(t, storeValue.CreateClient(ctx, otherClient, claims.Sub))
	crossClientToken := models.NewToken()
	crossClientToken.SetClientID(client.ID)
	crossClientToken.SetUserID(claims.Sub)
	crossClientToken.SetScope("mcp:mealie")
	crossClientToken.SetAccess("cross-client-access-token")
	crossClientToken.SetAccessCreateAt(now)
	crossClientToken.SetAccessExpiresIn(time.Hour)
	crossClientToken.SetRefresh("cross-client-refresh-token")
	crossClientToken.SetRefreshCreateAt(now)
	crossClientToken.SetRefreshExpiresIn(2 * time.Hour)
	require.NoError(t, storeValue.Create(ctx, crossClientToken))
	wrongClientCtx := context.WithValue(ctx, refreshClientIDContextKey{}, otherClient.ID)
	_, err = storeValue.GetByRefresh(wrongClientCtx, "cross-client-refresh-token")
	require.ErrorContains(t, err, "refresh token was not issued to this OAuth client")

	revokedClient := registeredClient{ID: "client-2", Name: "Example Client 2", RedirectURIs: []string{"https://example.com/other-callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: tokenEndpointAuthMethodNone, Scopes: []string{"mcp:mealie"}}
	require.NoError(t, storeValue.CreateClient(ctx, revokedClient, claims.Sub))
	revokedToken := models.NewToken()
	revokedToken.SetClientID(revokedClient.ID)
	revokedToken.SetUserID(claims.Sub)
	revokedToken.SetScope("mcp:mealie")
	revokedToken.SetAccess("revoked-access-token")
	revokedToken.SetAccessCreateAt(now)
	revokedToken.SetAccessExpiresIn(time.Hour)
	revokedToken.SetRefresh("revoked-refresh-token")
	revokedToken.SetRefreshCreateAt(now)
	revokedToken.SetRefreshExpiresIn(2 * time.Hour)
	require.NoError(t, storeValue.Create(ctx, revokedToken))
	require.NoError(t, cpStore.ReplaceSubjectGrants(ctx, claims.Sub, nil))
	_, err = storeValue.GetByRefresh(ctx, "revoked-refresh-token")
	require.ErrorContains(t, err, "requested scope is not granted")

	_, err = storeValue.db.ExecContext(ctx, `
INSERT INTO oauth_sessions (session_id, subject_sub, client_id, service_id, redirect_uri, scope, access_token_hash, access_create_at, access_expires_in_seconds)
VALUES (?, ?, ?, 'mealie', 'https://example.com/callback', 'mcp:mealie', ?, ?, 3600);`, make([]byte, 16), claims.Sub, client.ID, hashOpaqueValue("corrupt-access-token"), formatSQLiteTime(now))
	require.NoError(t, err)
	_, err = storeValue.GetByAccess(ctx, "corrupt-access-token")
	require.ErrorContains(t, err, "parse oauth session id")

	require.NoError(t, storeValue.RecordAuditEvent(ctx, edgeAuditEvent{CorrelationID: "correlation-1", ActorSubjectSub: claims.Sub, ServiceID: "mealie", EventType: "test.audit", EventStatus: "ok", Payload: map[string]any{"source": "integration-test"}}))
	auditCount, err := storeValue.queries.CountAuditEventsByType(ctx, platformdb.CountAuditEventsByTypeParams{EventType: "test.audit"})
	require.NoError(t, err)
	require.Equal(t, int64(1), auditCount)
}
