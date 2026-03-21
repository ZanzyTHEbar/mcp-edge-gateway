package controlplane

import (
	"context"
	"time"

	"dragonserver/mcp-platform/internal/domain"

	"github.com/rs/zerolog"
)

type RuntimeClient interface {
	Apply(context.Context, TenantInstance, TenantPlan) (RuntimeApplyResult, error)
}

type RuntimeApplyResult struct {
	Status            string
	Details           map[string]any
	ObservedState     domain.TenantRuntimeState
	LastError         *string
	DeleteCompleted   bool
	SkipReconcileMark bool
}

type Reconciler struct {
	store   tenantStore
	runtime RuntimeClient
	logger  zerolog.Logger
}

type NoopRuntimeClient struct{}

func NewReconciler(store tenantStore, logger zerolog.Logger) *Reconciler {
	return NewReconcilerWithRuntime(store, NoopRuntimeClient{}, logger)
}

func NewReconcilerWithRuntime(store tenantStore, runtime RuntimeClient, logger zerolog.Logger) *Reconciler {
	return &Reconciler{
		store:   store,
		runtime: runtime,
		logger:  logger,
	}
}

func (r *Reconciler) RunOnce(ctx context.Context) (ReconcileSummary, error) {
	tenants, err := r.store.ListTenantInstances(ctx)
	if err != nil {
		return ReconcileSummary{}, err
	}

	summary := ReconcileSummary{
		Scanned:   len(tenants),
		LastRunAt: time.Now().UTC(),
	}

	for _, tenant := range tenants {
		plan := PlanTenantAction(tenant)
		startedAt := time.Now().UTC()
		result, applyErr := r.runtime.Apply(ctx, tenant, plan)
		finishedAt := time.Now().UTC()

		status := result.Status
		if status == "" {
			status = "deferred"
		}

		details := make(map[string]any)
		if plan.Reason != "" {
			details["reason"] = plan.Reason
		}
		for key, value := range result.Details {
			details[key] = value
		}

		observedState := tenant.RuntimeState
		if result.ObservedState != "" {
			observedState = result.ObservedState
		}
		lastError := preservedTenantError(tenant, plan)
		if result.LastError != nil {
			lastError = *result.LastError
		}
		if applyErr != nil {
			status = "failed"
			lastError = applyErr.Error()
			details["error"] = applyErr.Error()
			summary.Failures++
		} else if status == "noop" {
			summary.Noop++
		} else if status == "deferred" {
			summary.Deferred++
		} else {
			summary.Applied++
		}

		if err := r.store.RecordReconcileRun(ctx, ReconcileRunInput{
			TenantID:      tenant.TenantID,
			DesiredState:  tenant.DesiredState,
			ObservedState: observedState,
			Action:        string(plan.Action),
			Status:        status,
			Details:       details,
			StartedAt:     startedAt,
			FinishedAt:    finishedAt,
		}); err != nil {
			return ReconcileSummary{}, err
		}
		if result.DeleteCompleted {
			if err := r.store.DeleteTenantInstance(ctx, tenant.TenantID); err != nil {
				return ReconcileSummary{}, err
			}
			continue
		}
		if result.SkipReconcileMark {
			continue
		}
		if err := r.store.MarkTenantReconciled(ctx, tenant.TenantID, finishedAt, lastError); err != nil {
			return ReconcileSummary{}, err
		}

		r.logger.Info().
			Str("tenant_id", tenant.TenantID.String()).
			Str("subject_sub", tenant.SubjectSub).
			Str("service_id", tenant.ServiceID).
			Str("desired_state", string(tenant.DesiredState)).
			Str("runtime_state", string(tenant.RuntimeState)).
			Str("action", string(plan.Action)).
			Str("status", status).
			Msg("control-plane reconcile decision")
	}

	return summary, nil
}

func PlanTenantAction(tenant TenantInstance) TenantPlan {
	switch tenant.DesiredState {
	case domain.TenantDesiredStateEnabled:
		switch tenant.RuntimeState {
		case domain.TenantRuntimeStateReady:
			return TenantPlan{
				Action: ReconcileActionNoop,
				Reason: "tenant already ready",
			}
		case domain.TenantRuntimeStateDisabled:
			return TenantPlan{
				Action: ReconcileActionEnable,
				Reason: "tenant is disabled but desired state is enabled",
			}
		case domain.TenantRuntimeStateDegraded:
			return TenantPlan{
				Action: ReconcileActionEnsure,
				Reason: "tenant is degraded and requires repair",
			}
		case domain.TenantRuntimeStateDeleting:
			return TenantPlan{
				Action: ReconcileActionNoop,
				Reason: "tenant delete is still in progress before re-enable can occur",
			}
		default:
			return TenantPlan{
				Action: ReconcileActionEnsure,
				Reason: "tenant must be provisioned or observed until ready",
			}
		}

	case domain.TenantDesiredStateDisabled:
		if tenant.RuntimeState == domain.TenantRuntimeStateDisabled {
			return TenantPlan{
				Action: ReconcileActionNoop,
				Reason: "tenant already disabled",
			}
		}
		return TenantPlan{
			Action: ReconcileActionDisable,
			Reason: "tenant should be disabled by control-plane intent",
		}

	case domain.TenantDesiredStateDeleted:
		if tenant.RuntimeState == domain.TenantRuntimeStateDeleting {
			return TenantPlan{
				Action: ReconcileActionDelete,
				Reason: "tenant deletion must be confirmed and finalized",
			}
		}
		return TenantPlan{
			Action: ReconcileActionDelete,
			Reason: "tenant should be deleted by control-plane intent",
		}

	default:
		return TenantPlan{
			Action: ReconcileActionNoop,
			Reason: "tenant desired state is unknown",
		}
	}
}

func (NoopRuntimeClient) Apply(_ context.Context, tenant TenantInstance, plan TenantPlan) (RuntimeApplyResult, error) {
	if plan.Action == ReconcileActionNoop {
		return RuntimeApplyResult{
			Status:        "noop",
			ObservedState: tenant.RuntimeState,
			Details: map[string]any{
				"runtime_state": tenant.RuntimeState,
			},
		}, nil
	}

	return RuntimeApplyResult{
		Status:        "deferred",
		ObservedState: tenant.RuntimeState,
		Details: map[string]any{
			"runtime_clients_configured": false,
		},
	}, nil
}

func preservedTenantError(tenant TenantInstance, plan TenantPlan) string {
	if plan.Action != ReconcileActionNoop {
		return tenant.LastError
	}

	switch tenant.RuntimeState {
	case domain.TenantRuntimeStateDegraded, domain.TenantRuntimeStateProvisioning, domain.TenantRuntimeStateDeleting:
		return tenant.LastError
	default:
		return ""
	}
}
