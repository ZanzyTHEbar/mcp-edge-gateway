package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
				InfisicalProjectSlug:             "dragonserver",
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
