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

func TestUpsertStaticTenantUpstreamUsesPersistedSubjectKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	subject := domain.Subject{Sub: "user-sub", SubjectKey: "persisted-key", PreferredUsername: "user"}
	require.NoError(t, store.UpsertSubject(ctx, subject))
	require.NoError(t, store.UpsertManualServiceGrant(ctx, domain.Subject{Sub: subject.Sub}, "mealie"))

	require.NoError(t, store.UpsertStaticTenantUpstream(ctx, domain.Subject{Sub: subject.Sub, SubjectKey: "operator-provided-wrong-key"}, "mealie", "https://mcp.lan", time.Now().UTC()))

	tenants, err := store.ListTenantInstances(ctx)
	require.NoError(t, err)
	require.Len(t, tenants, 1)
	require.Equal(t, "persisted-key", tenants[0].SubjectKey)
	require.Equal(t, domain.BuildTenantInstanceName("mealie", "persisted-key"), tenants[0].TenantInstanceName)
}

func TestSeedServiceCatalogDisablesStaleEntriesAndReenablesDefaults(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	_, err = store.db.ExecContext(ctx, `UPDATE service_catalog SET enabled = 0 WHERE service_id = 'mealie'`)
	require.NoError(t, err)
	_, err = store.db.ExecContext(ctx, `
INSERT INTO service_catalog (
    service_id,
    display_name,
    upstream_service_name,
    transport_type,
    internal_port,
    public_path,
    internal_upstream_path,
    health_path,
    health_probe_expectation,
    resource_profile,
    persistence_policy,
    adapter_requirement,
    secret_contract,
    source,
    enabled
)
VALUES ('stale-service', 'Stale', 'stale', 'streamable-http', 8080, '/stale/mcp', '/mcp', '/health', 'ok', 'small', 'ephemeral', 'none', '[]', 'builtin', 1);`)
	require.NoError(t, err)

	require.NoError(t, store.SeedServiceCatalog(ctx))

	var mealieEnabled, staleEnabled int
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT enabled FROM service_catalog WHERE service_id = 'mealie'`).Scan(&mealieEnabled))
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT enabled FROM service_catalog WHERE service_id = 'stale-service'`).Scan(&staleEnabled))
	require.Equal(t, 1, mealieEnabled)
	require.Equal(t, 0, staleEnabled)
}

func TestManualServiceGrantSurvivesAuthentikSnapshotSync(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	require.NoError(t, store.UpsertManualServiceGrant(ctx, domain.Subject{Sub: "manual-sub"}, "mealie"))
	require.NoError(t, store.SyncSubjectGrantSnapshot(ctx, nil, nil))

	grants, err := store.ListSubjectServiceGrants(ctx, "manual-sub")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, "mealie", grants[0].ServiceID)
	require.Equal(t, "manual", grants[0].SourceGroup)
}

func TestListSubjectServiceGrantsExcludesDisabledServices(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	require.NoError(t, store.UpsertManualServiceGrant(ctx, domain.Subject{Sub: "manual-sub"}, "mealie"))
	_, err = store.db.ExecContext(ctx, `UPDATE service_catalog SET enabled = 0 WHERE service_id = 'mealie'`)
	require.NoError(t, err)

	grants, err := store.ListSubjectServiceGrants(ctx, "manual-sub")
	require.NoError(t, err)
	require.Empty(t, grants)
}

func TestManualServiceGrantPreservesExistingSubjectMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))
	require.NoError(t, store.UpsertSubject(ctx, domain.Subject{
		Sub:               "manual-sub",
		SubjectKey:        "manual-key",
		PreferredUsername: "existing-user",
		Email:             "existing@example.com",
		DisplayName:       "Existing User",
	}))

	require.NoError(t, store.UpsertManualServiceGrant(ctx, domain.Subject{Sub: "manual-sub"}, "mealie"))

	var preferredUsername, email, displayName string
	var subjectKey string
	require.NoError(t, store.db.QueryRowContext(ctx, `SELECT subject_key, preferred_username, email, display_name FROM subjects WHERE subject_sub = 'manual-sub'`).Scan(&subjectKey, &preferredUsername, &email, &displayName))
	require.Equal(t, "manual-key", subjectKey)
	require.Equal(t, "existing-user", preferredUsername)
	require.Equal(t, "existing@example.com", email)
	require.Equal(t, "Existing User", displayName)
}

func TestManualGrantDeletePreservesAuthentikGrantSource(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store, err := NewStore(ctx, "file:"+filepath.Join(t.TempDir(), "mcp-platform.db"), zerolog.New(io.Discard))
	require.NoError(t, err)
	defer store.Close()
	require.NoError(t, store.RunMigrations(ctx))
	require.NoError(t, store.SeedServiceCatalog(ctx))

	subject := domain.Subject{Sub: "overlap-sub", SubjectKey: "overlap-key"}
	require.NoError(t, store.SyncSubjectGrantSnapshot(ctx, []domain.Subject{subject}, []ServiceGrant{{SubjectSub: subject.Sub, ServiceID: "mealie", SourceGroup: "mcp-service-mealie"}}))
	require.NoError(t, store.UpsertManualServiceGrant(ctx, subject, "mealie"))

	grants, err := store.ListSubjectServiceGrants(ctx, subject.Sub)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, "manual", grants[0].SourceGroup)

	require.NoError(t, store.DeleteManualServiceGrant(ctx, subject.Sub, "mealie"))
	grants, err = store.ListSubjectServiceGrants(ctx, subject.Sub)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, "mcp-service-mealie", grants[0].SourceGroup)
}
