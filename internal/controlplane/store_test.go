package controlplane

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/domain"
	"dragonserver/mcp-platform/internal/ids"

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

func TestUpdateTenantRuntimeStatusCanClearRuntimeReferences(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	tenantID := ids.New()
	_, err = store.db.ExecContext(ctx, `
INSERT INTO subjects (subject_sub, subject_key, preferred_username, email, display_name, last_synced_at)
VALUES ('user-sub', 'subject-key', 'user', 'user@example.com', 'User', CURRENT_TIMESTAMP);`)
	require.NoError(t, err)
	_, err = store.db.ExecContext(ctx, `
INSERT INTO tenant_instances (
    tenant_id,
    subject_sub,
    service_id,
    subject_key,
    tenant_instance_name,
    internal_dns_name,
    desired_state,
    runtime_state,
    coolify_resource_id,
    coolify_application_id,
    upstream_url,
    last_healthy_at
)
VALUES (?, 'user-sub', 'mealie', 'subject-key', 'u-subject-key-mealie', 'u-subject-key-mealie', 'enabled', 'ready', 'service-uuid', 'app-uuid', 'http://mealie:9000', CURRENT_TIMESTAMP);`, tenantID.Bytes())
	require.NoError(t, err)

	require.NoError(t, store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:               tenantID,
		RuntimeState:           domain.TenantRuntimeStateDegraded,
		ClearRuntimeReferences: true,
		LastError:              "service disappeared",
	}))

	tenants, err := store.ListTenantInstances(ctx)
	require.NoError(t, err)
	require.Len(t, tenants, 1)
	require.Empty(t, tenants[0].CoolifyResourceID)
	require.Empty(t, tenants[0].CoolifyApplicationID)
	require.Empty(t, tenants[0].UpstreamURL)
	require.Nil(t, tenants[0].LastHealthyAt)
	require.Equal(t, domain.TenantRuntimeStateDegraded, tenants[0].RuntimeState)
}
