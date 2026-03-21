package controlplane

import (
	"context"
	"errors"
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
			callOrder = append(callOrder, "migrate")
			return nil
		},
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
	require.Equal(t, []string{"migrate", "seed", "probe", "reconcile"}, callOrder)
}

func TestRunStartupSequenceStopsBeforeReconcileWhenHealthProbeFails(t *testing.T) {
	t.Parallel()

	reconcileCalled := false
	err := runStartupSequence(
		context.Background(),
		zerolog.Nop(),
		func(context.Context) error { return nil },
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
