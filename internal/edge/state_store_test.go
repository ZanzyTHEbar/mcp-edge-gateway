package edge

import (
	"context"
	"testing"
	"time"

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
		Name:                    "Open WebUI",
		RedirectURIs:            []string{"https://example.com/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: tokenEndpointAuthMethodClientBasic,
		Secret:                  "super-secret",
	}
	require.NoError(t, storeValue.CreateClient(context.Background(), client, claims.Sub))

	clientInfo, err := storeValue.GetByID(context.Background(), client.ID)
	require.NoError(t, err)
	require.Equal(t, client.Secret, clientInfo.GetSecret())

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
