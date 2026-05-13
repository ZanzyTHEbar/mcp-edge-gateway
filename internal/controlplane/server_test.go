package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type rewriteHostTransport struct {
	target *url.URL
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = t.target.Scheme
	clone.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func installStaticUpstreamTestNetwork(t *testing.T, upstreamURL string) string {
	t.Helper()
	target, err := url.Parse(upstreamURL)
	require.NoError(t, err)

	previousLookup := lookupStaticUpstreamIP
	previousClient := newStaticUpstreamHealthClient
	lookupStaticUpstreamIP = func(host string) ([]net.IP, error) {
		if host == "mcp-lan.test" {
			return []net.IP{net.ParseIP("192.168.1.10")}, nil
		}
		return previousLookup(host)
	}
	newStaticUpstreamHealthClient = func() *http.Client {
		return &http.Client{
			Timeout:   5 * time.Second,
			Transport: rewriteHostTransport{target: target},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	t.Cleanup(func() {
		lookupStaticUpstreamIP = previousLookup
		newStaticUpstreamHealthClient = previousClient
	})

	return target.Scheme + "://mcp-lan.test:" + target.Port()
}

func catalogEntryForTest(serviceID string, publicPath string) catalog.ServiceCatalogEntry {
	return catalog.ServiceCatalogEntry{
		ServiceID:              serviceID,
		DisplayName:            "Test MCP",
		UpstreamServiceName:    serviceID + "-mcp",
		TransportType:          catalog.TransportTypeStreamableHTTP,
		InternalPort:           7070,
		PublicPath:             publicPath,
		InternalUpstreamPath:   "/mcp",
		HealthPath:             "/health",
		HealthProbeExpectation: "GET returns OK",
		ResourceProfile:        "small",
		PersistencePolicy:      "stateless",
		AdapterRequirement:     catalog.AdapterRequirementNone,
	}
}

func TestHealthStateClearsDatabaseErrorAfterRecovery(t *testing.T) {
	t.Parallel()

	state := &healthState{}
	state.setDatabaseStatus(errors.New("ping database: boom"))

	snapshot := state.snapshot()
	require.False(t, snapshot.Ready)
	require.Equal(t, "ping database: boom", snapshot.LastError)

	state.setDatabaseStatus(nil)
	snapshot = state.snapshot()
	require.True(t, snapshot.Ready)
	require.Empty(t, snapshot.LastError)
}

func TestHealthStatePrefersReconcileError(t *testing.T) {
	t.Parallel()

	state := &healthState{}
	state.setDatabaseStatus(nil)
	state.setReconcileResult(ReconcileSummary{}, errors.New("reconcile failed"))

	snapshot := state.snapshot()
	require.False(t, snapshot.Ready)
	require.Equal(t, "reconcile failed", snapshot.LastError)

	state.setReconcileResult(ReconcileSummary{LastRunAt: time.Now().UTC()}, nil)
	snapshot = state.snapshot()
	require.True(t, snapshot.Ready)
	require.Empty(t, snapshot.LastError)
}

func TestRunStartupSequenceContinuesOnInitialReconcileFailure(t *testing.T) {
	t.Parallel()

	var callOrder []string
	err := runStartupSequence(
		context.Background(),
		zerolog.Nop(),
		func(context.Context) error {
			callOrder = append(callOrder, "seed")
			return nil
		},
		func(context.Context) error {
			callOrder = append(callOrder, "probe")
			return nil
		},
		func(context.Context) (ReconcileSummary, error) {
			callOrder = append(callOrder, "reconcile")
			return ReconcileSummary{}, errors.New("initial reconcile failed")
		},
	)

	require.NoError(t, err)
	require.Equal(t, []string{"seed", "probe", "reconcile"}, callOrder)
}

func TestRunStartupSequenceStopsBeforeReconcileWhenHealthProbeFails(t *testing.T) {
	t.Parallel()

	reconcileCalled := false
	err := runStartupSequence(
		context.Background(),
		zerolog.Nop(),
		func(context.Context) error { return nil },
		func(context.Context) error { return errors.New("probe failed") },
		func(context.Context) (ReconcileSummary, error) {
			reconcileCalled = true
			return ReconcileSummary{}, nil
		},
	)

	require.ErrorContains(t, err, "probe failed")
	require.False(t, reconcileCalled)
}

func TestRunLeaseRenewalLoopCancelsRuntimeOnLeaseLoss(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runtimeCanceled := make(chan struct{})
	runtimeCancel := func() {
		cancel()
		close(runtimeCanceled)
	}

	app := &App{logger: zerolog.Nop()}
	go app.runLeaseRenewalLoopWithInterval(ctx, runtimeCancel, time.Millisecond)

	select {
	case <-runtimeCanceled:
	case <-time.After(time.Second):
		t.Fatal("lease renewal loop did not cancel runtime after leadership loss")
	}
}

func TestRequireLeadershipReturnsContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	app := &App{logger: zerolog.Nop()}
	require.ErrorIs(t, app.requireLeadership(ctx), context.Canceled)
}

func TestHandleReadinessReportsConfigErrors(t *testing.T) {
	t.Parallel()

	t.Run("missing dependencies", func(t *testing.T) {
		t.Parallel()

		app := &App{
			cfg:    Config{},
			health: &healthState{},
		}
		app.health.setDatabaseStatus(nil)
		app.health.setReconcileResult(ReconcileSummary{LastRunAt: time.Now().UTC()}, nil)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		app.handleReadiness(recorder, request)

		require.Equal(t, http.StatusServiceUnavailable, recorder.Code)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
		require.Equal(t, "not_ready", payload["status"])
		require.Empty(t, payload["last_error"])
		require.Equal(t, false, payload["leader"])
		require.Equal(t, false, payload["dependencies_configured"])
		require.Equal(t, false, payload["tenant_runtime_configured"])
	})

	t.Run("missing tenant runtime", func(t *testing.T) {
		t.Parallel()

		app := &App{
			cfg: Config{
				AuthentikIssuerURL:               "https://auth.example.com/application/o/mcp/",
				AuthentikClientID:                "client-id",
				AuthentikClientSecretPath:        "/run/secrets/authentik-client-secret",
				CoolifyAPIBaseURL:                "https://coolify.example.com/api/v1",
				CoolifyAPITokenPath:              "/run/secrets/coolify-api-token",
				InfisicalAPIBaseURL:              "https://infisical.example.com/api",
				InfisicalProjectSlug:             "example-project",
				InfisicalEnvSlug:                 "prod",
				InfisicalMachineClientID:         "machine-id",
				InfisicalMachineClientSecretPath: "/run/secrets/infisical-machine-secret",
			},
			health: &healthState{},
		}
		app.health.setDatabaseStatus(nil)
		app.health.setReconcileResult(ReconcileSummary{LastRunAt: time.Now().UTC()}, nil)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
		app.handleReadiness(recorder, request)

		require.Equal(t, http.StatusServiceUnavailable, recorder.Code)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
		require.Equal(t, "not_ready", payload["status"])
		require.Empty(t, payload["last_error"])
		require.Equal(t, false, payload["leader"])
		require.Equal(t, true, payload["dependencies_configured"])
		require.Equal(t, false, payload["tenant_runtime_configured"])
	})
}

func TestCatalogAdminRegistersDynamicService(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}

	body := `{
  "display_name": "Custom MCP",
  "upstream_service_name": "custom-mcp",
  "transport_type": "streamable-http",
  "internal_port": 7070,
  "public_path": "/custom/mcp",
  "internal_upstream_path": "/mcp",
  "health_path": "/health",
  "health_probe_expectation": "GET returns OK",
  "resource_profile": "small",
  "persistence_policy": "stateless",
  "adapter_requirement": "none",
  "secret_contract": [{"Key":"api-token","Required":true}]
}`
	request := httptest.NewRequest(http.MethodPut, "/v1/services/custom", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)

	var enabled int
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT enabled FROM service_catalog WHERE service_id = 'custom'`).Scan(&enabled))
	require.Equal(t, 1, enabled)

	require.NoError(t, store.SeedServiceCatalog(ctx))
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT enabled FROM service_catalog WHERE service_id = 'custom'`).Scan(&enabled))
	require.Equal(t, 1, enabled)
}

func TestCatalogAdminRequiresBearerToken(t *testing.T) {
	t.Parallel()

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, health: &healthState{}}

	request := httptest.NewRequest(http.MethodGet, "/v1/services", nil)
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestCatalogAdminRejectsReservedPublicPath(t *testing.T) {
	t.Parallel()

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, health: &healthState{}}

	body := `{
  "display_name": "Bad MCP",
  "upstream_service_name": "bad-mcp",
  "transport_type": "streamable-http",
  "internal_port": 7070,
  "public_path": "/oauth/bad",
  "internal_upstream_path": "/mcp",
  "health_path": "/health",
  "health_probe_expectation": "GET returns OK",
  "resource_profile": "small",
  "persistence_policy": "stateless",
  "adapter_requirement": "none"
}`
	request := httptest.NewRequest(http.MethodPut, "/v1/services/bad", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestCatalogAdminRejectsSuspiciousPublicPath(t *testing.T) {
	t.Parallel()

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, health: &healthState{}}

	body := `{
  "display_name": "Bad MCP",
  "upstream_service_name": "bad-mcp",
  "transport_type": "streamable-http",
  "internal_port": 7070,
  "public_path": "/custom/mcp?x",
  "internal_upstream_path": "/mcp",
  "health_path": "/health",
  "health_probe_expectation": "GET returns OK",
  "resource_profile": "small",
  "persistence_policy": "stateless",
  "adapter_requirement": "none"
}`
	request := httptest.NewRequest(http.MethodPut, "/v1/services/bad", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestCatalogAdminReportsSourceAndEnabled(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}

	request := httptest.NewRequest(http.MethodGet, "/v1/services/mealie", nil)
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"source":"builtin"`)
	require.Contains(t, recorder.Body.String(), `"enabled":true`)
}

func TestCatalogAdminRejectsBuiltinMutation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}
	handler := app.Handler()

	body := `{
  "display_name": "Bad Mealie",
  "upstream_service_name": "bad-mealie",
  "transport_type": "streamable-http",
  "internal_port": 7070,
  "public_path": "/bad-mealie/mcp",
  "internal_upstream_path": "/mcp",
  "health_path": "/health",
  "health_probe_expectation": "GET returns OK",
  "resource_profile": "small",
  "persistence_policy": "stateless",
  "adapter_requirement": "none"
}`
	putRequest := httptest.NewRequest(http.MethodPut, "/v1/services/mealie", strings.NewReader(body))
	putRequest.Header.Set("Authorization", "Bearer test-admin-token")
	putRecorder := httptest.NewRecorder()
	handler.ServeHTTP(putRecorder, putRequest)
	require.Equal(t, http.StatusConflict, putRecorder.Code)
	require.Contains(t, putRecorder.Body.String(), `"error":"builtin_service_locked"`)

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/services/mealie", nil)
	deleteRequest.Header.Set("Authorization", "Bearer test-admin-token")
	deleteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteRecorder, deleteRequest)
	require.Equal(t, http.StatusConflict, deleteRecorder.Code)
	require.Contains(t, deleteRecorder.Body.String(), `"error":"builtin_service_locked"`)
}

func TestCatalogAdminRejectsOverlappingPublicPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))
	require.NoError(t, store.UpsertAdminServiceCatalogEntry(ctx, catalogEntryForTest("custom", "/custom/mcp")))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}

	body := `{
  "display_name": "Nested MCP",
  "upstream_service_name": "nested-mcp",
  "transport_type": "streamable-http",
  "internal_port": 7070,
  "public_path": "/custom/mcp/admin",
  "internal_upstream_path": "/mcp",
  "health_path": "/health",
  "health_probe_expectation": "GET returns OK",
  "resource_profile": "small",
  "persistence_policy": "stateless",
  "adapter_requirement": "none"
}`
	request := httptest.NewRequest(http.MethodPut, "/v1/services/nested", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusConflict, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"error":"public_path_conflict"`)
}

func TestGrantAdminUpsertsListsAndDeletesManualGrant(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}
	handler := app.Handler()

	putRequest := httptest.NewRequest(http.MethodPut, "/v1/subjects/manual-sub/grants/mealie", nil)
	putRequest.Header.Set("Authorization", "Bearer test-admin-token")
	putRecorder := httptest.NewRecorder()
	handler.ServeHTTP(putRecorder, putRequest)
	require.Equal(t, http.StatusOK, putRecorder.Code)

	getRequest := httptest.NewRequest(http.MethodGet, "/v1/subjects/manual-sub/grants", nil)
	getRequest.Header.Set("Authorization", "Bearer test-admin-token")
	getRecorder := httptest.NewRecorder()
	handler.ServeHTTP(getRecorder, getRequest)
	require.Equal(t, http.StatusOK, getRecorder.Code)
	require.Contains(t, getRecorder.Body.String(), `"service_id":"mealie"`)
	require.Contains(t, getRecorder.Body.String(), `"source_group":"manual"`)

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/subjects/manual-sub/grants/mealie", nil)
	deleteRequest.Header.Set("Authorization", "Bearer test-admin-token")
	deleteRecorder := httptest.NewRecorder()
	handler.ServeHTTP(deleteRecorder, deleteRequest)
	require.Equal(t, http.StatusNoContent, deleteRecorder.Code)

	grants, err := store.ListSubjectServiceGrants(ctx, "manual-sub")
	require.NoError(t, err)
	require.Empty(t, grants)
}

func TestGrantAdminReturnsNotFoundForUnknownService(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}

	request := httptest.NewRequest(http.MethodPut, "/v1/subjects/manual-sub/grants/unknown", nil)
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestStaticUpstreamAdminBindsGrantedSubject(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/mcp", r.URL.Path)
		_, _ = w.Write([]byte(`{"transport":"streamable"}`))
	}))
	defer upstream.Close()
	upstreamURL := installStaticUpstreamTestNetwork(t, upstream.URL)

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}
	handler := app.Handler()

	grantRequest := httptest.NewRequest(http.MethodPut, "/v1/subjects/manual-sub/grants/mealie", nil)
	grantRequest.Header.Set("Authorization", "Bearer test-admin-token")
	grantRecorder := httptest.NewRecorder()
	handler.ServeHTTP(grantRecorder, grantRequest)
	require.Equal(t, http.StatusOK, grantRecorder.Code)

	body := `{"upstream_url":"` + upstreamURL + `/mcp"}`
	bindRequest := httptest.NewRequest(http.MethodPut, "/v1/subjects/manual-sub/services/mealie/upstream", strings.NewReader(body))
	bindRequest.Header.Set("Authorization", "Bearer test-admin-token")
	bindRecorder := httptest.NewRecorder()
	handler.ServeHTTP(bindRecorder, bindRequest)
	require.Equal(t, http.StatusOK, bindRecorder.Code)
	require.Contains(t, bindRecorder.Body.String(), `"upstream_url":"`+upstreamURL+`/mcp"`)

	tenants, err := store.ListTenantInstances(ctx)
	require.NoError(t, err)
	require.Len(t, tenants, 1)
	require.Equal(t, "manual-sub", tenants[0].SubjectSub)
	require.Equal(t, "mealie", tenants[0].ServiceID)
	require.Equal(t, upstreamURL+"/mcp", tenants[0].UpstreamURL)
	require.Equal(t, domain.TenantRuntimeStateReady, tenants[0].RuntimeState)
	require.NotNil(t, tenants[0].LastHealthyAt)
}

func TestStaticUpstreamAdminRequiresGrant(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"transport":"streamable"}`))
	}))
	defer upstream.Close()
	upstreamURL := installStaticUpstreamTestNetwork(t, upstream.URL)

	tokenPath := filepath.Join(t.TempDir(), "admin-token")
	require.NoError(t, os.WriteFile(tokenPath, []byte("test-admin-token"), 0o600))
	app := &App{cfg: Config{AdminTokenPath: tokenPath}, store: store, health: &healthState{}}

	body := `{"upstream_url":"` + upstreamURL + `/mcp"}`
	request := httptest.NewRequest(http.MethodPut, "/v1/subjects/manual-sub/services/mealie/upstream", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	recorder := httptest.NewRecorder()
	app.Handler().ServeHTTP(recorder, request)

	require.Equal(t, http.StatusConflict, recorder.Code)
	require.Contains(t, recorder.Body.String(), "service_not_granted")
}

func TestNormalizeStaticUpstreamURLRejectsHostnameResolvingToLoopback(t *testing.T) {
	previousLookup := lookupStaticUpstreamIP
	lookupStaticUpstreamIP = func(host string) ([]net.IP, error) {
		require.Equal(t, "loopback.test", host)
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	t.Cleanup(func() { lookupStaticUpstreamIP = previousLookup })

	_, err := normalizeStaticUpstreamURL("http://loopback.test:8080")
	require.ErrorContains(t, err, "resolved ip address is not allowed")
}

func TestHandleReadinessRequiresLeadership(t *testing.T) {
	t.Parallel()

	app := &App{
		cfg:    validTenantRuntimeControlPlaneConfig(),
		health: &healthState{},
	}
	app.health.setDatabaseStatus(nil)
	app.health.setReconcileResult(ReconcileSummary{LastRunAt: time.Now().UTC()}, nil)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	app.handleReadiness(recorder, request)

	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &payload))
	require.Equal(t, "not_ready", payload["status"])
	require.Equal(t, false, payload["leader"])
	require.Equal(t, true, payload["dependencies_configured"])
	require.Equal(t, true, payload["tenant_runtime_configured"])
}
