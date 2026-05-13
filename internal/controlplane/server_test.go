package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

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
