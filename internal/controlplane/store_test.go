package controlplane

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestControlPlaneLockUsesDatabaseBackedLease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	databaseURL := "file:" + filepath.Join(t.TempDir(), "mcp-platform.db")
	logger := zerolog.New(io.Discard)

	storeA, err := NewStore(ctx, databaseURL, logger)
	require.NoError(t, err)
	defer storeA.Close()
	require.NoError(t, storeA.RunMigrations(ctx))

	storeB, err := NewStore(ctx, databaseURL, logger)
	require.NoError(t, err)
	defer storeB.Close()

	lockA, err := storeA.AcquireControlPlaneLock(ctx)
	require.NoError(t, err)
	require.True(t, lockA.Held(ctx))

	lockB, err := storeB.AcquireControlPlaneLock(ctx)
	require.Error(t, err)
	require.Nil(t, lockB)

	require.NoError(t, lockA.Release(ctx))
	require.False(t, lockA.Held(ctx))

	lockB, err = storeB.AcquireControlPlaneLock(ctx)
	require.NoError(t, err)
	require.True(t, lockB.Held(ctx))
	require.NoError(t, lockB.Release(ctx))
}

func TestNewAppRunsMigrationsBeforeAcquiringControlPlaneLock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	app, err := NewApp(ctx, Config{
		DatabaseURL:         "file:" + filepath.Join(t.TempDir(), "mcp-platform.db"),
		HTTPBindAddr:        "127.0.0.1:0",
		ReconcileInterval:   30 * time.Second,
		HealthcheckInterval: 30 * time.Second,
	}, zerolog.New(io.Discard))
	require.NoError(t, err)
	defer app.Close()
	require.True(t, app.lock.Held(ctx))
}
