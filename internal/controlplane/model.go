package controlplane

import (
	"encoding/json"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"
	"dragonserver/mcp-platform/internal/ids"
)

type ServiceCatalogAdminEntry struct {
	ServiceID              string                     `json:"service_id"`
	DisplayName            string                     `json:"display_name"`
	UpstreamServiceName    string                     `json:"upstream_service_name"`
	TransportType          catalog.TransportType      `json:"transport_type"`
	InternalPort           int                        `json:"internal_port"`
	PublicPath             string                     `json:"public_path"`
	InternalUpstreamPath   string                     `json:"internal_upstream_path"`
	HealthPath             string                     `json:"health_path"`
	HealthProbeExpectation string                     `json:"health_probe_expectation"`
	ResourceProfile        string                     `json:"resource_profile"`
	PersistencePolicy      string                     `json:"persistence_policy"`
	AdapterRequirement     catalog.AdapterRequirement `json:"adapter_requirement"`
	SecretContract         []catalog.SecretDefinition `json:"secret_contract"`
	Enabled                bool                       `json:"enabled"`
	Source                 string                     `json:"source"`
}

type ServiceGrant struct {
	SubjectSub   string    `json:"subject_sub"`
	ServiceID    string    `json:"service_id"`
	SourceGroup  string    `json:"source_group"`
	GrantedAt    time.Time `json:"granted_at"`
	LastSyncedAt time.Time `json:"last_synced_at"`
}

type StaticUpstreamBinding struct {
	SubjectSub  string    `json:"subject_sub"`
	ServiceID   string    `json:"service_id"`
	UpstreamURL string    `json:"upstream_url"`
	VerifiedAt  time.Time `json:"verified_at"`
}

type TenantInstance struct {
	TenantID             ids.UUID
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

type TenantRuntimeUpdate struct {
	TenantID               ids.UUID
	RuntimeState           domain.TenantRuntimeState
	CoolifyResourceID      string
	CoolifyApplicationID   string
	UpstreamURL            string
	LastHealthyAt          *time.Time
	ClearRuntimeReferences bool
	LastError              string
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
	TenantID      ids.UUID
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
