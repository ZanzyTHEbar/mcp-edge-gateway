package edge

import (
	"context"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/ids"

	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/stretchr/testify/require"
)

func TestParseRequestedServiceScopes(t *testing.T) {
	t.Parallel()

	serviceIDs, valid := parseRequestedServiceScopes("mcp:mealie mcp:actualbudget mcp:mealie")
	require.True(t, valid)
	require.Equal(t, []string{"mealie", "actualbudget"}, serviceIDs)

	_, valid = parseRequestedServiceScopes("")
	require.False(t, valid)

	_, valid = parseRequestedServiceScopes("openid")
	require.False(t, valid)
}

func TestOpaqueCipherRoundTrip(t *testing.T) {
	t.Parallel()

	cipherValue, err := newOpaqueCipher("test-session-secret")
	require.NoError(t, err)

	ciphertext, err := cipherValue.EncryptString("sensitive-token")
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	plaintext, err := cipherValue.DecryptString(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "sensitive-token", plaintext)
}

func TestFormatSQLiteTimeUsesFixedWidthUTC(t *testing.T) {
	t.Parallel()

	first := formatSQLiteTime(time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC))
	second := formatSQLiteTime(time.Date(2026, 1, 1, 0, 0, 10, 100_000_000, time.UTC))

	require.Equal(t, "2026-01-01T00:00:10.000000000Z", first)
	require.Equal(t, "2026-01-01T00:00:10.100000000Z", second)
	require.Less(t, first, second)
}

func TestMemoryEdgeStateStoreRoundTrip(t *testing.T) {
	t.Parallel()

	storeValue, err := newMemoryEdgeStateStore()
	require.NoError(t, err)

	now := time.Now().UTC()
	claims := IdentityClaims{
		Sub:               "fixture-user",
		Email:             "fixture@example.com",
		Name:              "Fixture User",
		PreferredUsername: "fixture-user",
		Groups:            []string{"mcp-users", "mcp-service-mealie"},
	}
	require.NoError(t, storeValue.UpsertSubject(context.Background(), claims))

	allowed, err := storeValue.Allowed(context.Background(), claims.Sub, "mealie")
	require.NoError(t, err)
	require.True(t, allowed)

	allowed, err = storeValue.AllowedScopes(context.Background(), claims.Sub, "mcp:mealie")
	require.NoError(t, err)
	require.True(t, allowed)

	pending := pendingLogin{
		State:    "state-1",
		ReturnTo: "/oauth/authorize",
		Nonce:    "nonce-1",
		Expiry:   now.Add(time.Minute),
	}
	require.NoError(t, storeValue.PutPendingLogin(context.Background(), pending))

	gotPending, ok, err := storeValue.GetPendingLogin(context.Background(), pending.State, now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, pending, gotPending)
	require.NoError(t, storeValue.DeletePendingLogin(context.Background(), pending.State))

	session := browserSession{
		Claims: claims,
		Expiry: now.Add(time.Hour),
	}
	require.NoError(t, storeValue.PutBrowserSession(context.Background(), "session-1", session))

	gotSession, ok, err := storeValue.GetBrowserSession(context.Background(), "session-1", now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, session, gotSession)

	client := registeredClient{
		ID:                      "client-1",
		Name:                    "Example Client",
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: tokenEndpointAuthMethodClientBasic,
		Secret:                  "super-secret",
		Scopes:                  []string{"mcp:mealie"},
	}
	require.NoError(t, storeValue.CreateClient(context.Background(), client, claims.Sub))

	clientInfo, err := storeValue.GetByID(context.Background(), client.ID)
	require.NoError(t, err)
	require.Equal(t, client.Secret, clientInfo.GetSecret())
	require.True(t, clientAllowsGrant(clientInfo, "authorization_code"))
	require.False(t, clientAllowsGrant(clientInfo, "urn:ietf:params:oauth:grant-type:device_code"))

	deviceID := ids.New()
	require.ErrorContains(t, storeValue.CreateDeviceAuthorization(context.Background(), deviceAuthorization{}), "device authorization id is required")
	deviceRecord := deviceAuthorization{
		ID:              deviceID,
		ClientID:        client.ID,
		ServiceID:       "mealie",
		Resource:        "https://mcp.example.com/mealie/mcp",
		Scope:           "mcp:mealie",
		DeviceCodeHash:  hashOpaqueValue("device-code"),
		UserCodeHash:    hashOpaqueValue(normalizeUserCode("ABCD-EFGH")),
		UserCodeDisplay: "ABCD-EFGH",
		ExpiresAt:       now.Add(10 * time.Minute),
		CreatedAt:       now,
	}
	require.NoError(t, storeValue.CreateDeviceAuthorization(context.Background(), deviceRecord))
	loadedDevice, ok, err := storeValue.GetDeviceAuthorizationByDeviceCode(context.Background(), "device-code")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, deviceAuthorizationStatusPending, loadedDevice.Status)
	require.Equal(t, 5*time.Second, loadedDevice.Interval)
	loadedDevice, ok, err = storeValue.GetDeviceAuthorizationByUserCode(context.Background(), "abcd efgh")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, deviceID, loadedDevice.ID)
	updated, err := storeValue.ApproveDeviceAuthorization(context.Background(), deviceID, "", now.Add(time.Second))
	require.ErrorContains(t, err, "requires subject")
	require.False(t, updated)
	updated, err = storeValue.UpdateDeviceAuthorizationPoll(context.Background(), deviceID, now.Add(time.Second))
	require.NoError(t, err)
	require.True(t, updated)
	updated, err = storeValue.ApproveDeviceAuthorization(context.Background(), deviceID, claims.Sub, now.Add(2*time.Second))
	require.NoError(t, err)
	require.True(t, updated)
	loadedDevice, ok, err = storeValue.GetDeviceAuthorizationByDeviceCode(context.Background(), "device-code")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, int64(1), loadedDevice.PollCount)
	require.NotNil(t, loadedDevice.ApprovedAt)
	updated, err = storeValue.ConsumeDeviceAuthorization(context.Background(), deviceID, now.Add(3*time.Second))
	require.NoError(t, err)
	require.True(t, updated)

	expiredID := ids.New()
	require.NoError(t, storeValue.CreateDeviceAuthorization(context.Background(), deviceAuthorization{
		ID:              expiredID,
		ClientID:        client.ID,
		ServiceID:       "mealie",
		Resource:        "https://mcp.example.com/mealie/mcp",
		Scope:           "mcp:mealie",
		DeviceCodeHash:  hashOpaqueValue("expired-device-code"),
		UserCodeHash:    hashOpaqueValue(normalizeUserCode("ZZZZ-9999")),
		UserCodeDisplay: "ZZZZ-9999",
		Interval:        5 * time.Second,
		ExpiresAt:       now.Add(-time.Second),
		CreatedAt:       now.Add(-10 * time.Minute),
	}))
	expiredCount, err := storeValue.MarkExpiredDeviceAuthorizations(context.Background(), now)
	require.NoError(t, err)
	require.Equal(t, int64(1), expiredCount)
	updated, err = storeValue.ApproveDeviceAuthorization(context.Background(), expiredID, claims.Sub, now)
	require.NoError(t, err)
	require.False(t, updated)
	prunedCount, err := storeValue.PruneExpiredDeviceAuthorizations(context.Background(), now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, int64(1), prunedCount)

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
	require.NoError(t, storeValue.Create(context.Background(), token))

	accessToken, err := storeValue.GetByAccess(context.Background(), "access-token")
	require.NoError(t, err)
	require.Equal(t, "access-token", accessToken.GetAccess())

	refreshToken, err := storeValue.GetByRefresh(context.Background(), "refresh-token")
	require.NoError(t, err)
	require.Equal(t, "access-token", refreshToken.GetAccess())
	require.Equal(t, "refresh-token", refreshToken.GetRefresh())
}
