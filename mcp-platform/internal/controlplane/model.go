package controlplane

import (
	"encoding/json"
	"time"

	"dragonserver/mcp-platform/internal/domain"

	"github.com/google/uuid"
)

type ServiceGrant struct {
	SubjectSub   string
	ServiceID    string
	SourceGroup  string
	GrantedAt    time.Time
	LastSyncedAt time.Time
}

type TenantInstance struct {
	TenantID             uuid.UUID
	SubjectSub           string
	ServiceID            string
	SubjectKey           string
	TenantInstanceName   string
	InternalDNSName      string
	DesiredState         domain.TenantDesiredState
	RuntimeState         domain.TenantRuntimeState
	CoolifyResourceID    string
	CoolifyApplicationID string
	UpstreamURL          string
	SecretVersion        string
	LastHealthyAt        *time.Time
	LastReconciledAt     *time.Time
	LastError            string
	Metadata             json.RawMessage
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type ReconcileAction string

const (
	ReconcileActionNoop    ReconcileAction = "noop"
	ReconcileActionEnsure  ReconcileAction = "ensure_present"
	ReconcileActionEnable  ReconcileAction = "enable"
	ReconcileActionDisable ReconcileAction = "disable"
	ReconcileActionDelete  ReconcileAction = "delete"
)

type TenantPlan struct {
	Action ReconcileAction
	Reason string
}

type ReconcileRunInput struct {
	TenantID      uuid.UUID
	DesiredState  domain.TenantDesiredState
	ObservedState domain.TenantRuntimeState
	Action        string
	Status        string
	Details       map[string]any
	StartedAt     time.Time
	FinishedAt    time.Time
}

type ReconcileSummary struct {
	Scanned   int
	Applied   int
	Noop      int
	Deferred  int
	Failures  int
	LastRunAt time.Time
}
