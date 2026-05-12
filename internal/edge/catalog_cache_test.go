package edge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/catalog"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestCatalogSnapshotMatchesExactAndNestedPublicPaths(t *testing.T) {
	t.Parallel()

	snapshot, err := newCatalogSnapshot([]catalog.ServiceCatalogEntry{
		{ServiceID: "memory", PublicPath: "/memory/mcp"},
		{ServiceID: "mealie", PublicPath: "/mealie/mcp"},
	}, time.Now().UTC())
	require.NoError(t, err)

	service, ok := snapshot.MatchPublicPath("/memory/mcp")
	require.True(t, ok)
	require.Equal(t, "memory", service.ServiceID)

	service, ok = snapshot.MatchPublicPath("/memory/mcp/tools/list")
	require.True(t, ok)
	require.Equal(t, "memory", service.ServiceID)

	_, ok = snapshot.MatchPublicPath("/memory/mcp2")
	require.False(t, ok)
}

func TestCatalogCacheRefreshKeepsLastGoodSnapshotOnError(t *testing.T) {
	t.Parallel()

	store := newMutableCatalogStore(t)
	cache := NewCatalogCache(store, zerolog.Nop())
	require.NoError(t, cache.Refresh(context.Background()))
	require.Equal(t, 3, cache.Len())

	store.err = errors.New("database unavailable")
	require.Error(t, cache.Refresh(context.Background()))
	require.Equal(t, 3, cache.Len())
	require.Equal(t, "database unavailable", cache.LastError())
}

func TestCatalogSnapshotRejectsReservedPublicPath(t *testing.T) {
	t.Parallel()

	_, err := newCatalogSnapshot([]catalog.ServiceCatalogEntry{{ServiceID: "bad", PublicPath: "/oauth/register"}}, time.Now().UTC())
	require.ErrorContains(t, err, "conflicts with a reserved edge route")
}

func TestServerHandlerUsesRefreshedCatalogWithoutRebuild(t *testing.T) {
	t.Parallel()

	store := newMutableCatalogStore(t)
	server, err := NewServerWithStateStore(context.Background(), testEdgeConfig(), zerolog.Nop(), staticResolver{}, store)
	require.NoError(t, err)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/newservice/mcp", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)

	newService := catalog.DefaultCatalogV1()[0]
	newService.ServiceID = "newservice"
	newService.PublicPath = "/newservice/mcp"
	store.entries = append(store.entries, newService)
	require.NoError(t, server.catalogCache.Refresh(context.Background()))

	req = httptest.NewRequest(http.MethodGet, "/newservice/mcp", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusUnauthorized, res.Code)
	require.Contains(t, res.Body.String(), "invalid_token")

	store.entries = catalog.DefaultCatalogV1()
	require.NoError(t, server.catalogCache.Refresh(context.Background()))
	req = httptest.NewRequest(http.MethodGet, "/newservice/mcp", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func TestOAuthScopesReflectRefreshedCatalog(t *testing.T) {
	t.Parallel()

	store := newMutableCatalogStore(t)
	server, err := NewServerWithStateStore(context.Background(), testEdgeConfig(), zerolog.Nop(), staticResolver{}, store)
	require.NoError(t, err)
	handler := server.Handler()

	store.entries = filterCatalogService(store.entries, "mealie")
	require.NoError(t, server.catalogCache.Refresh(context.Background()))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.NotContains(t, res.Body.String(), "mcp:mealie")

	registrationBody := `{"client_name":"bad-scope","redirect_uris":["https://client.example.com/callback"],"scope":"mcp:mealie"}`
	req = httptest.NewRequest(http.MethodPost, "/oauth/register", strings.NewReader(registrationBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer fixture-operator-token")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusBadRequest, res.Code)
	require.Contains(t, res.Body.String(), "requested scopes are not supported")
}

func TestReservedRoutesWinOverDynamicFallback(t *testing.T) {
	t.Parallel()

	store := newMutableCatalogStore(t)
	server, err := NewServerWithStateStore(context.Background(), testEdgeConfig(), zerolog.Nop(), staticResolver{}, store)
	require.NoError(t, err)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), "live")
}

type mutableCatalogStore struct {
	*memoryEdgeStateStore
	entries []catalog.ServiceCatalogEntry
	err     error
}

func newMutableCatalogStore(t *testing.T) *mutableCatalogStore {
	t.Helper()
	memoryStore, err := newMemoryEdgeStateStore()
	require.NoError(t, err)
	return &mutableCatalogStore{memoryEdgeStateStore: memoryStore, entries: catalog.DefaultCatalogV1()}
}

func (s *mutableCatalogStore) ListEnabledServiceCatalog(context.Context) ([]catalog.ServiceCatalogEntry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return append([]catalog.ServiceCatalogEntry(nil), s.entries...), nil
}

func testEdgeConfig() Config {
	return Config{
		PlatformEnv:           "test",
		PublicBaseURL:         "https://mcp.example.com",
		CookieSecure:          false,
		EnableFixtureMode:     true,
		FixtureAuthSubjectSub: "fixture-user",
		FixtureAuthGroups:     []string{"mcp-users", "mcp-service-mealie"},
		FixtureOperatorToken:  "fixture-operator-token",
	}
}

func filterCatalogService(entries []catalog.ServiceCatalogEntry, serviceID string) []catalog.ServiceCatalogEntry {
	filtered := make([]catalog.ServiceCatalogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.ServiceID != serviceID {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
