package edge

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/controlplane"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPostgresEdgeStateStoreRoundTrip(t *testing.T) {
	databaseURL := os.Getenv("MCP_PLATFORM_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set MCP_PLATFORM_TEST_DATABASE_URL to run Postgres edge state-store integration tests")
	}
	if os.Getenv("MCP_PLATFORM_TEST_DATABASE_URL_ALLOW_TRUNCATE") != "1" || !postgresDatabaseNameLooksDisposable(databaseURL) {
		t.Skip("set MCP_PLATFORM_TEST_DATABASE_URL_ALLOW_TRUNCATE=1 and use a database name containing 'test' to run destructive Postgres integration tests")
	}

	ctx := context.Background()
	logger := zerolog.Nop()

	cpStore, err := controlplane.NewStore(ctx, databaseURL, logger)
	require.NoError(t, err)
	require.NoError(t, cpStore.RunMigrations(ctx))
	require.NoError(t, cpStore.SeedServiceCatalog(ctx))
	cpStore.Close()

	secretPath := filepath.Join(t.TempDir(), "session-key")
	require.NoError(t, os.WriteFile(secretPath, []byte("test-session-encryption-key"), 0o600))

	storeValue, err := newPostgresEdgeStateStore(ctx, Config{
		PlatformDatabaseURL:      databaseURL,
		SessionEncryptionKeyPath: secretPath,
	}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storeValue.Close() })

	cleanupPostgresEdgeStateStore(t, ctx, storeValue)

	entries, err := storeValue.ListEnabledServiceCatalog(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	now := time.Now().UTC()
	claims := IdentityClaims{
		Sub:               "postgres-fixture-user",
		Email:             "fixture@example.com",
		Name:              "Fixture User",
		PreferredUsername: "fixture-user",
		Groups:            []string{"mcp-users", "mcp-service-mealie"},
	}
	require.NoError(t, storeValue.UpsertSubject(ctx, claims))
	_, err = storeValue.pool.Exec(ctx, `
		insert into service_grants (subject_sub, service_id, source_group, last_synced_at)
		values ($1, $2, $3, now())
	`, claims.Sub, "mealie", "mcp-service-mealie")
	require.NoError(t, err)

	allowed, err := storeValue.Allowed(ctx, claims.Sub, "mealie")
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = storeValue.AllowedScopes(ctx, claims.Sub, "mcp:mealie")
	require.NoError(t, err)
	require.True(t, allowed)

	pending := pendingLogin{
		State:    "state-1",
		ReturnTo: "/oauth/authorize",
		Nonce:    "nonce-1",
		Expiry:   now.Add(time.Minute),
	}
	require.NoError(t, storeValue.PutPendingLogin(ctx, pending))

	gotPending, ok, err := storeValue.GetPendingLogin(ctx, pending.State, now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, pending, gotPending)
	require.NoError(t, storeValue.DeletePendingLogin(ctx, pending.State))

	session := browserSession{
		Claims: claims,
		Expiry: now.Add(time.Hour),
	}
	require.NoError(t, storeValue.PutBrowserSession(ctx, "session-1", session))

	gotSession, ok, err := storeValue.GetBrowserSession(ctx, "session-1", now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, session, gotSession)

	client := registeredClient{
		ID:                      "client-1",
		Name:                    "Open WebUI",
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: tokenEndpointAuthMethodClientBasic,
		Secret:                  "super-secret",
	}
	require.NoError(t, storeValue.CreateClient(ctx, client, claims.Sub))

	clientInfo, err := storeValue.GetByID(ctx, client.ID)
	require.NoError(t, err)
	require.Empty(t, clientInfo.GetSecret())
	confidential, ok := clientInfo.(confidentialClient)
	require.True(t, ok)
	require.True(t, confidential.VerifyPassword(client.Secret))
	require.False(t, confidential.VerifyPassword("wrong-secret"))

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

	require.NoError(t, storeValue.RecordAuditEvent(ctx, edgeAuditEvent{
		CorrelationID:   "correlation-1",
		ActorSubjectSub: claims.Sub,
		ServiceID:       "mealie",
		EventType:       "test.audit",
		EventStatus:     "ok",
		Payload: map[string]any{
			"source": "integration-test",
		},
	}))

	var auditCount int
	require.NoError(t, storeValue.pool.QueryRow(ctx, `select count(*) from audit_events where event_type = 'test.audit'`).Scan(&auditCount))
	require.Equal(t, 1, auditCount)
}

func postgresDatabaseNameLooksDisposable(databaseURL string) bool {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return false
	}
	name := strings.Trim(strings.ToLower(parsed.Path), "/")
	return strings.Contains(name, "test")
}

func cleanupPostgresEdgeStateStore(t *testing.T, ctx context.Context, storeValue *postgresEdgeStateStore) {
	t.Helper()
	_, err := storeValue.pool.Exec(ctx, `
		truncate table
			audit_events,
			oauth_sessions,
			oauth_clients,
			edge_pending_logins,
			edge_browser_sessions,
			tenant_instances,
			service_grants,
			subjects
		cascade
	`)
	require.NoError(t, err)
}
