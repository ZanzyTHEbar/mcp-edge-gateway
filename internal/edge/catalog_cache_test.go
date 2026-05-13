package edge

import (
	"context"
	"encoding/json"
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

func TestCatalogSnapshotRejectsInvalidServiceID(t *testing.T) {
	t.Parallel()

	_, err := newCatalogSnapshot([]catalog.ServiceCatalogEntry{{ServiceID: "bad service/id", PublicPath: "/bad/mcp"}}, time.Now().UTC())
	require.ErrorContains(t, err, "invalid service_id")
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
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `scope="mcp:newservice"`)
	require.Contains(t, res.Header().Get("WWW-Authenticate"), `resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/newservice"`)

	store.entries = catalog.DefaultCatalogV1()
	require.NoError(t, server.catalogCache.Refresh(context.Background()))
	req = httptest.NewRequest(http.MethodGet, "/newservice/mcp", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusNotFound, res.Code)
}

func TestRootDiscoveryReturnsCatalogAndMetadataLinks(t *testing.T) {
	t.Parallel()

	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(res.Body.Bytes(), &payload))
	require.Equal(t, "mcp-edge", payload["name"])
	require.Equal(t, "https://mcp.example.com", payload["public_base_url"])
	require.Equal(t, "ok", payload["catalog_status"])

	services, ok := payload["services"].([]any)
	require.True(t, ok)
	require.Len(t, services, 3)
	require.Contains(t, res.Body.String(), `"id":"mealie"`)
	require.Contains(t, res.Body.String(), `"path":"/mealie/mcp"`)
	require.Contains(t, res.Body.String(), `"scope":"mcp:mealie"`)

	oauth, ok := payload["oauth"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "https://mcp.example.com/.well-known/oauth-authorization-server", oauth["authorization_server_metadata"])
	require.Equal(t, "https://mcp.example.com/oauth/register", oauth["registration_endpoint"])
}

func TestRootDiscoveryDoesNotExposeCatalogRefreshErrors(t *testing.T) {
	t.Parallel()

	store := newMutableCatalogStore(t)
	server, err := NewServerWithStateStore(context.Background(), testEdgeConfig(), zerolog.Nop(), staticResolver{}, store)
	require.NoError(t, err)

	store.err = errors.New("sqlite failed at /data/private/mcp-platform.db")
	require.Error(t, server.catalogCache.Refresh(context.Background()))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), `"catalog_status":"degraded"`)
	require.NotContains(t, res.Body.String(), "sqlite failed")
	require.NotContains(t, res.Body.String(), "/data/private")
}

func TestRootDiscoverySupportsHEAD(t *testing.T) {
	t.Parallel()

	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Equal(t, "application/json", res.Header().Get("Content-Type"))
}

func TestRootDiscoveryTrimsPublicBaseURL(t *testing.T) {
	t.Parallel()

	cfg := testEdgeConfig()
	cfg.PublicBaseURL = "https://mcp.example.com/"
	server, err := NewServer(cfg, zerolog.Nop(), staticResolver{})
	require.NoError(t, err)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusOK, res.Code)
	require.Contains(t, res.Body.String(), `"registration_endpoint":"https://mcp.example.com/oauth/register"`)
	require.NotContains(t, res.Body.String(), "https://mcp.example.com//")
}

func TestRootDiscoveryRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()

	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusMethodNotAllowed, res.Code)
	require.Equal(t, "GET, HEAD", res.Header().Get("Allow"))
	require.Contains(t, res.Body.String(), "method_not_allowed")
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

func TestCORSPreflightAllowsMCPTransportHeaders(t *testing.T) {
	t.Parallel()

	server := newTestEdgeServer(t, nil)
	handler := server.Handler()

	req := httptest.NewRequest(http.MethodOptions, "/mealie/mcp", nil)
	req.Header.Set("Origin", "https://client.example.com")
	req.Header.Set("Access-Control-Request-Headers", "authorization, mcp-protocol-version, mcp-session-id")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)

	require.Equal(t, http.StatusNoContent, res.Code)
	require.Equal(t, "*", res.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, res.Header().Get("Access-Control-Allow-Headers"), "MCP-Protocol-Version")
	require.Contains(t, res.Header().Get("Access-Control-Allow-Headers"), "MCP-Session-Id")
	require.Contains(t, res.Header().Get("Access-Control-Allow-Headers"), "Last-Event-ID")
}

func TestCORSPreflightDoesNotAllowUnconfiguredOrigin(t *testing.T) {
	t.Parallel()

	cfg := testEdgeConfig()
	cfg.CORSAllowedOrigins = []string{"https://trusted.example.com"}
	server, err := NewServer(cfg, zerolog.Nop(), staticResolver{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodOptions, "/mealie/mcp", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)

	require.Equal(t, http.StatusNoContent, res.Code)
	require.Empty(t, res.Header().Get("Access-Control-Allow-Origin"))
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
		CORSAllowedOrigins:    []string{"*"},
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
