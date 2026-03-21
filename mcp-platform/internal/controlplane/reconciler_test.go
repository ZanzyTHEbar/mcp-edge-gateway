package controlplane

import (
	"context"
	"testing"
	"time"

	"dragonserver/mcp-platform/internal/domain"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestPlanTenantAction(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		tenant   TenantInstance
		expected TenantPlan
	}{
		{
			name: "enabled ready becomes noop",
			tenant: TenantInstance{
				DesiredState: domain.TenantDesiredStateEnabled,
				RuntimeState: domain.TenantRuntimeStateReady,
			},
			expected: TenantPlan{
				Action: ReconcileActionNoop,
				Reason: "tenant already ready",
			},
		},
		{
			name: "enabled degraded becomes ensure",
			tenant: TenantInstance{
				DesiredState: domain.TenantDesiredStateEnabled,
				RuntimeState: domain.TenantRuntimeStateDegraded,
			},
			expected: TenantPlan{
				Action: ReconcileActionEnsure,
				Reason: "tenant is degraded and requires repair",
			},
		},
		{
			name: "disabled ready becomes disable",
			tenant: TenantInstance{
				DesiredState: domain.TenantDesiredStateDisabled,
				RuntimeState: domain.TenantRuntimeStateReady,
			},
			expected: TenantPlan{
				Action: ReconcileActionDisable,
				Reason: "tenant should be disabled by control-plane intent",
			},
		},
		{
			name: "deleted deleting stays in delete until confirmed",
			tenant: TenantInstance{
				DesiredState: domain.TenantDesiredStateDeleted,
				RuntimeState: domain.TenantRuntimeStateDeleting,
			},
			expected: TenantPlan{
				Action: ReconcileActionDelete,
				Reason: "tenant deletion must be confirmed and finalized",
			},
		},
		{
			name: "deleted ready becomes delete",
			tenant: TenantInstance{
				DesiredState: domain.TenantDesiredStateDeleted,
				RuntimeState: domain.TenantRuntimeStateReady,
			},
			expected: TenantPlan{
				Action: ReconcileActionDelete,
				Reason: "tenant should be deleted by control-plane intent",
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			actual := PlanTenantAction(testCase.tenant)
			require.Equal(t, testCase.expected, actual)
		})
	}
}

func TestReconcilerRunOnceRecordsDeferredRuns(t *testing.T) {
	t.Parallel()

	store := &fakeTenantStore{
		tenants: []TenantInstance{
			{
				TenantID:     uuid.New(),
				SubjectSub:   "authentik|user-1",
				ServiceID:    "mealie",
				DesiredState: domain.TenantDesiredStateEnabled,
				RuntimeState: domain.TenantRuntimeStateDegraded,
				LastError:    "tenant identity drift detected; reprovision required",
			},
			{
				TenantID:     uuid.New(),
				SubjectSub:   "authentik|user-2",
				ServiceID:    "actualbudget",
				DesiredState: domain.TenantDesiredStateDeleted,
				RuntimeState: domain.TenantRuntimeStateReady,
			},
		},
	}

	reconciler := NewReconciler(store, zerolog.Nop())
	summary, err := reconciler.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, summary.Scanned)
	require.Equal(t, 0, summary.Applied)
	require.Equal(t, 0, summary.Noop)
	require.Equal(t, 2, summary.Deferred)
	require.Len(t, store.recordedRuns, 2)
	require.Len(t, store.markedTenants, 2)
	require.Equal(t, "tenant identity drift detected; reprovision required", store.markedTenantErrors[store.tenants[0].TenantID])
}

func TestReconcilerRunOncePreservesRuntimeLastError(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	store := &fakeTenantStore{
		tenants: []TenantInstance{
			{
				TenantID:     tenantID,
				SubjectSub:   "authentik|user-3",
				ServiceID:    "memory",
				DesiredState: domain.TenantDesiredStateEnabled,
				RuntimeState: domain.TenantRuntimeStateReady,
			},
		},
	}

	runtime := fakeRuntimeClient{
		resultsByTenant: map[uuid.UUID]RuntimeApplyResult{
			tenantID: {
				Status:        "degraded",
				ObservedState: domain.TenantRuntimeStateDegraded,
				LastError:     stringPointer("health probe failed"),
			},
		},
	}

	reconciler := NewReconcilerWithRuntime(store, runtime, zerolog.Nop())
	summary, err := reconciler.RunOnce(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, summary.Scanned)
	require.Equal(t, 1, summary.Applied)
	require.Equal(t, 0, summary.Deferred)
	require.Equal(t, "health probe failed", store.markedTenantErrors[tenantID])
	require.Equal(t, domain.TenantRuntimeStateDegraded, store.recordedRuns[0].ObservedState)
}

func TestReconcilerRunOnceDeletesCompletedTenants(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	store := &fakeTenantStore{
		tenants: []TenantInstance{
			{
				TenantID:     tenantID,
				SubjectSub:   "authentik|user-4",
				ServiceID:    "actualbudget",
				DesiredState: domain.TenantDesiredStateDeleted,
				RuntimeState: domain.TenantRuntimeStateDeleting,
			},
		},
	}

	runtime := fakeRuntimeClient{
		resultsByTenant: map[uuid.UUID]RuntimeApplyResult{
			tenantID: {
				Status:          "deleted",
				ObservedState:   domain.TenantRuntimeStateDeleting,
				DeleteCompleted: true,
			},
		},
	}

	reconciler := NewReconcilerWithRuntime(store, runtime, zerolog.Nop())
	_, err := reconciler.RunOnce(context.Background())
	require.NoError(t, err)
	require.Contains(t, store.deletedTenants, tenantID)
	require.NotContains(t, store.markedTenants, tenantID)
}

func TestReconcilerRunOnceSkipsReconcileMarkWhenRuntimeRequestsIt(t *testing.T) {
	t.Parallel()

	tenantID := uuid.New()
	store := &fakeTenantStore{
		tenants: []TenantInstance{
			{
				TenantID:     tenantID,
				SubjectSub:   "authentik|user-5",
				ServiceID:    "memory",
				DesiredState: domain.TenantDesiredStateDeleted,
				RuntimeState: domain.TenantRuntimeStateDeleting,
			},
		},
	}

	runtime := fakeRuntimeClient{
		resultsByTenant: map[uuid.UUID]RuntimeApplyResult{
			tenantID: {
				Status:            "deleting",
				ObservedState:     domain.TenantRuntimeStateDeleting,
				SkipReconcileMark: true,
			},
		},
	}

	reconciler := NewReconcilerWithRuntime(store, runtime, zerolog.Nop())
	_, err := reconciler.RunOnce(context.Background())
	require.NoError(t, err)
	require.Empty(t, store.markedTenants)
	require.Empty(t, store.deletedTenants)
	require.Len(t, store.recordedRuns, 1)
}

func TestPreservedTenantErrorClearsForHealthyNoop(t *testing.T) {
	t.Parallel()

	healthyTenant := TenantInstance{
		DesiredState: domain.TenantDesiredStateEnabled,
		RuntimeState: domain.TenantRuntimeStateReady,
		LastError:    "old transient error",
	}

	require.Empty(t, preservedTenantError(healthyTenant, TenantPlan{
		Action: ReconcileActionNoop,
	}))

	degradedTenant := healthyTenant
	degradedTenant.RuntimeState = domain.TenantRuntimeStateDegraded
	require.Equal(t, "old transient error", preservedTenantError(degradedTenant, TenantPlan{
		Action: ReconcileActionNoop,
	}))
}

type fakeTenantStore struct {
	tenants            []TenantInstance
	recordedRuns       []ReconcileRunInput
	markedTenants      []uuid.UUID
	deletedTenants     []uuid.UUID
	markedTenantErrors map[uuid.UUID]string
}

func (f *fakeTenantStore) ListTenantInstances(ctx context.Context) ([]TenantInstance, error) {
	return append([]TenantInstance(nil), f.tenants...), nil
}

func (f *fakeTenantStore) RecordReconcileRun(ctx context.Context, input ReconcileRunInput) error {
	f.recordedRuns = append(f.recordedRuns, input)
	return nil
}

func (f *fakeTenantStore) MarkTenantReconciled(ctx context.Context, tenantID uuid.UUID, reconciledAt time.Time, lastError string) error {
	if f.markedTenantErrors == nil {
		f.markedTenantErrors = make(map[uuid.UUID]string)
	}
	f.markedTenants = append(f.markedTenants, tenantID)
	f.markedTenantErrors[tenantID] = lastError
	return nil
}

func (f *fakeTenantStore) DeleteTenantInstance(ctx context.Context, tenantID uuid.UUID) error {
	f.deletedTenants = append(f.deletedTenants, tenantID)
	return nil
}

type fakeRuntimeClient struct {
	resultsByTenant map[uuid.UUID]RuntimeApplyResult
	errByTenant     map[uuid.UUID]error
}

func (f fakeRuntimeClient) Apply(ctx context.Context, tenant TenantInstance, plan TenantPlan) (RuntimeApplyResult, error) {
	if err, ok := f.errByTenant[tenant.TenantID]; ok {
		return RuntimeApplyResult{}, err
	}
	if result, ok := f.resultsByTenant[tenant.TenantID]; ok {
		return result, nil
	}
	return NoopRuntimeClient{}.Apply(ctx, tenant, plan)
}
