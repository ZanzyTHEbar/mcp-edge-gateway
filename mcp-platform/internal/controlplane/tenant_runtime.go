package controlplane

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"

	"github.com/rs/zerolog"
)

const (
	defaultTenantImageActualBudget = "actual-mcp-server:latest"
	defaultTenantImageMemory       = "ghcr.io/zanzythebar/mcp-memory-libsql-go:latest"
	defaultTenantImageMealie       = "mealie-mcp:latest"
	deleteRequeueInterval          = 2 * time.Minute
)

type CoolifyTenantRuntime struct {
	cfg           Config
	store         *Store
	coolify       *CoolifyClient
	secrets       *InfisicalClient
	logger        zerolog.Logger
	healthClient  *http.Client
	serviceByID   map[string]catalog.ServiceCatalogEntry
	templatesByID map[string]tenantTemplate
}

type tenantTemplate interface {
	Render(Config, TenantInstance, catalog.ServiceCatalogEntry, map[string]string) (renderedTenantService, error)
}

type renderedTenantService struct {
	CreateRequest CoolifyCreateServiceRequest
	UpdateRequest CoolifyUpdateServiceRequest
	EnvVars       []CoolifyEnvVar
	UpstreamURL   string
}

type staticTenantTemplate struct {
	render func(Config, TenantInstance, catalog.ServiceCatalogEntry, map[string]string) (renderedTenantService, error)
}

func (t staticTenantTemplate) Render(cfg Config, tenant TenantInstance, service catalog.ServiceCatalogEntry, secrets map[string]string) (renderedTenantService, error) {
	return t.render(cfg, tenant, service, secrets)
}

func NewCoolifyTenantRuntime(cfg Config, store *Store, clients *DependencyClients, logger zerolog.Logger) *CoolifyTenantRuntime {
	serviceByID := make(map[string]catalog.ServiceCatalogEntry)
	for _, entry := range catalog.DefaultCatalogV1() {
		serviceByID[entry.ServiceID] = entry
	}

	return &CoolifyTenantRuntime{
		cfg:     cfg,
		store:   store,
		coolify: clients.Coolify,
		secrets: clients.Infisical,
		logger:  logger,
		healthClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		serviceByID: serviceByID,
		templatesByID: map[string]tenantTemplate{
			"mealie":       staticTenantTemplate{render: renderMealieTenant},
			"actualbudget": staticTenantTemplate{render: renderActualBudgetTenant},
			"memory":       staticTenantTemplate{render: renderMemoryTenant},
		},
	}
}

func (r *CoolifyTenantRuntime) Apply(ctx context.Context, tenant TenantInstance, plan TenantPlan) (RuntimeApplyResult, error) {
	service, ok := r.serviceByID[tenant.ServiceID]
	if !ok {
		return RuntimeApplyResult{}, fmt.Errorf("service %s is not present in the tenant runtime catalog", tenant.ServiceID)
	}

	switch plan.Action {
	case ReconcileActionNoop:
		if tenant.RuntimeState == domain.TenantRuntimeStateReady ||
			tenant.RuntimeState == domain.TenantRuntimeStateProvisioning ||
			tenant.RuntimeState == domain.TenantRuntimeStateDegraded {
			return r.observe(ctx, tenant, service)
		}
		return RuntimeApplyResult{
			Status: "noop",
			Details: map[string]any{
				"runtime_state": tenant.RuntimeState,
			},
		}, nil

	case ReconcileActionEnsure:
		return r.ensure(ctx, tenant, service)

	case ReconcileActionEnable:
		return r.enable(ctx, tenant, service)

	case ReconcileActionDisable:
		return r.disable(ctx, tenant)

	case ReconcileActionDelete:
		return r.delete(ctx, tenant)

	default:
		return RuntimeApplyResult{}, fmt.Errorf("unsupported reconcile action %s", plan.Action)
	}
}

func (r *CoolifyTenantRuntime) ensure(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry) (RuntimeApplyResult, error) {
	rendered, err := r.renderTenant(ctx, tenant, service)
	if err != nil {
		return RuntimeApplyResult{}, err
	}

	serviceUUID := tenant.CoolifyResourceID
	if serviceUUID != "" {
		_, err := r.coolify.GetService(ctx, serviceUUID)
		if err != nil {
			if IsHTTPStatus(err, http.StatusNotFound) {
				serviceUUID = ""
			} else {
				return RuntimeApplyResult{}, err
			}
		}
	}

	created := false
	if serviceUUID == "" {
		createResponse, err := r.coolify.CreateService(ctx, rendered.CreateRequest)
		if err != nil {
			_ = r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
				TenantID:     tenant.TenantID,
				RuntimeState: domain.TenantRuntimeStateDegraded,
				LastError:    err.Error(),
				UpstreamURL:  rendered.UpstreamURL,
			})
			return RuntimeApplyResult{}, err
		}
		serviceUUID = createResponse.UUID
		created = true
	}

	existingService, err := r.coolify.GetService(ctx, serviceUUID)
	if err != nil {
		return RuntimeApplyResult{}, err
	}
	metadataDrift := existingService.Name != rendered.UpdateRequest.Name || existingService.Description != rendered.UpdateRequest.Description
	composeDrift := existingService.DockerComposeRaw != rendered.UpdateRequest.DockerComposeRaw
	if metadataDrift || composeDrift {
		if err := r.coolify.UpdateService(ctx, serviceUUID, rendered.UpdateRequest); err != nil {
			return RuntimeApplyResult{}, err
		}
	}

	currentEnvs, err := r.coolify.ListServiceEnvs(ctx, serviceUUID)
	if err != nil {
		return RuntimeApplyResult{}, err
	}
	envDrift := envsDrifted(currentEnvs, rendered.EnvVars)
	if envDrift {
		if _, err := r.coolify.UpdateServiceEnvsBulk(ctx, serviceUUID, rendered.EnvVars); err != nil {
			return RuntimeApplyResult{}, err
		}
	}

	if created || envDrift || composeDrift {
		if _, err := r.coolify.RestartService(ctx, serviceUUID, false); err != nil {
			return RuntimeApplyResult{}, err
		}
	}

	if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:          tenant.TenantID,
		RuntimeState:      domain.TenantRuntimeStateProvisioning,
		CoolifyResourceID: serviceUUID,
		UpstreamURL:       rendered.UpstreamURL,
		LastError:         "",
	}); err != nil {
		return RuntimeApplyResult{}, err
	}

	result, err := r.observeWithURL(ctx, tenant, service, serviceUUID, rendered.UpstreamURL)
	if err != nil {
		return RuntimeApplyResult{}, err
	}
	if created {
		if result.Details == nil {
			result.Details = make(map[string]any)
		}
		result.Details["created"] = true
	}
	if envDrift {
		if result.Details == nil {
			result.Details = make(map[string]any)
		}
		result.Details["env_drift_corrected"] = true
	}
	if composeDrift {
		if result.Details == nil {
			result.Details = make(map[string]any)
		}
		result.Details["compose_drift_corrected"] = true
	}
	return result, nil
}

func (r *CoolifyTenantRuntime) enable(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry) (RuntimeApplyResult, error) {
	if tenant.CoolifyResourceID == "" {
		return r.ensure(ctx, tenant, service)
	}

	if _, err := r.coolify.StartService(ctx, tenant.CoolifyResourceID); err != nil {
		if IsHTTPStatus(err, http.StatusNotFound) {
			return r.ensure(ctx, tenant, service)
		}
		return RuntimeApplyResult{}, err
	}
	if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:     tenant.TenantID,
		RuntimeState: domain.TenantRuntimeStateProvisioning,
		LastError:    "",
	}); err != nil {
		return RuntimeApplyResult{}, err
	}

	return r.observe(ctx, tenant, service)
}

func (r *CoolifyTenantRuntime) disable(ctx context.Context, tenant TenantInstance) (RuntimeApplyResult, error) {
	if tenant.CoolifyResourceID != "" {
		if _, err := r.coolify.StopService(ctx, tenant.CoolifyResourceID, true); err != nil && !IsHTTPStatus(err, http.StatusNotFound) {
			return RuntimeApplyResult{}, err
		}
	}

	if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:     tenant.TenantID,
		RuntimeState: domain.TenantRuntimeStateDisabled,
		LastError:    "",
	}); err != nil {
		return RuntimeApplyResult{}, err
	}

	return RuntimeApplyResult{
		Status:        "disabled",
		ObservedState: domain.TenantRuntimeStateDisabled,
		LastError:     stringPointer(""),
		Details: map[string]any{
			"service_uuid": tenant.CoolifyResourceID,
		},
	}, nil
}

func (r *CoolifyTenantRuntime) delete(ctx context.Context, tenant TenantInstance) (RuntimeApplyResult, error) {
	if tenant.CoolifyResourceID == "" {
		return RuntimeApplyResult{
			Status:          "deleted",
			ObservedState:   domain.TenantRuntimeStateDeleting,
			LastError:       stringPointer(""),
			DeleteCompleted: true,
		}, nil
	}

	_, err := r.coolify.GetService(ctx, tenant.CoolifyResourceID)
	if err != nil {
		if IsHTTPStatus(err, http.StatusNotFound) {
			return RuntimeApplyResult{
				Status:          "deleted",
				ObservedState:   domain.TenantRuntimeStateDeleting,
				LastError:       stringPointer(""),
				DeleteCompleted: true,
				Details: map[string]any{
					"service_uuid": tenant.CoolifyResourceID,
				},
			}, nil
		}
		return RuntimeApplyResult{}, err
	}

	deleteQueued := false
	deleteRequeued := false
	shouldQueueDelete := tenant.RuntimeState != domain.TenantRuntimeStateDeleting
	if !shouldQueueDelete && shouldRequeueDelete(tenant.LastReconciledAt) {
		shouldQueueDelete = true
		deleteRequeued = true
	}
	if shouldQueueDelete {
		if _, err := r.coolify.DeleteService(ctx, tenant.CoolifyResourceID, CoolifyDeleteServiceOptions{
			DeleteConfigurations:    true,
			DeleteVolumes:           true,
			DockerCleanup:           true,
			DeleteConnectedNetworks: true,
		}); err != nil {
			if IsHTTPStatus(err, http.StatusNotFound) {
				return RuntimeApplyResult{
					Status:          "deleted",
					ObservedState:   domain.TenantRuntimeStateDeleting,
					LastError:       stringPointer(""),
					DeleteCompleted: true,
					Details: map[string]any{
						"service_uuid": tenant.CoolifyResourceID,
					},
				}, nil
			}
			return RuntimeApplyResult{}, err
		}
		deleteQueued = true
	}

	if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:     tenant.TenantID,
		RuntimeState: domain.TenantRuntimeStateDeleting,
		LastError:    "",
	}); err != nil {
		return RuntimeApplyResult{}, err
	}

	return RuntimeApplyResult{
		Status:            "deleting",
		ObservedState:     domain.TenantRuntimeStateDeleting,
		LastError:         stringPointer(""),
		SkipReconcileMark: !deleteQueued,
		Details: map[string]any{
			"service_uuid":    tenant.CoolifyResourceID,
			"delete_queued":   deleteQueued,
			"delete_requeued": deleteRequeued,
		},
	}, nil
}

func (r *CoolifyTenantRuntime) observe(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry) (RuntimeApplyResult, error) {
	upstreamURL := tenant.UpstreamURL
	if upstreamURL == "" {
		upstreamURL = buildUpstreamURL(tenant, service)
	}
	return r.observeWithURL(ctx, tenant, service, tenant.CoolifyResourceID, upstreamURL)
}

func (r *CoolifyTenantRuntime) observeWithURL(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry, serviceUUID string, upstreamURL string) (RuntimeApplyResult, error) {
	healthy, statusDetail, err := r.probeTenantHealth(ctx, tenant, service)
	if err != nil {
		if updateErr := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
			TenantID:          tenant.TenantID,
			RuntimeState:      domain.TenantRuntimeStateDegraded,
			CoolifyResourceID: serviceUUID,
			UpstreamURL:       upstreamURL,
			LastError:         err.Error(),
		}); updateErr != nil {
			return RuntimeApplyResult{}, updateErr
		}
		return RuntimeApplyResult{
			Status:        "degraded",
			ObservedState: domain.TenantRuntimeStateDegraded,
			LastError:     stringPointer(err.Error()),
			Details: map[string]any{
				"health": statusDetail,
			},
		}, nil
	}

	now := time.Now().UTC()
	if healthy {
		if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
			TenantID:          tenant.TenantID,
			RuntimeState:      domain.TenantRuntimeStateReady,
			CoolifyResourceID: serviceUUID,
			UpstreamURL:       upstreamURL,
			LastHealthyAt:     &now,
			LastError:         "",
		}); err != nil {
			return RuntimeApplyResult{}, err
		}
		return RuntimeApplyResult{
			Status:        "ready",
			ObservedState: domain.TenantRuntimeStateReady,
			LastError:     stringPointer(""),
			Details: map[string]any{
				"health": statusDetail,
			},
		}, nil
	}

	if err := r.store.UpdateTenantRuntimeStatus(ctx, TenantRuntimeUpdate{
		TenantID:          tenant.TenantID,
		RuntimeState:      domain.TenantRuntimeStateDegraded,
		CoolifyResourceID: serviceUUID,
		UpstreamURL:       upstreamURL,
		LastError:         statusDetail,
	}); err != nil {
		return RuntimeApplyResult{}, err
	}
	return RuntimeApplyResult{
		Status:        "degraded",
		ObservedState: domain.TenantRuntimeStateDegraded,
		LastError:     stringPointer(statusDetail),
		Details: map[string]any{
			"health": statusDetail,
		},
	}, nil
}

func (r *CoolifyTenantRuntime) renderTenant(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry) (renderedTenantService, error) {
	template, ok := r.templatesByID[tenant.ServiceID]
	if !ok {
		return renderedTenantService{}, fmt.Errorf("tenant template for service %s is not configured", tenant.ServiceID)
	}

	secretValues := make(map[string]string, len(service.SecretContract))
	for _, secretDefinition := range service.SecretContract {
		secretReference := domain.BuildTenantSecretPath(tenant.SubjectKey, tenant.ServiceID, secretDefinition.Key)
		secretValue, err := r.secrets.ResolveSecretReference(ctx, secretReference)
		if err != nil {
			if secretDefinition.Required {
				return renderedTenantService{}, err
			}
			continue
		}
		secretValues[secretDefinition.Key] = secretValue
	}

	return template.Render(r.cfg, tenant, service, secretValues)
}

func (r *CoolifyTenantRuntime) probeTenantHealth(ctx context.Context, tenant TenantInstance, service catalog.ServiceCatalogEntry) (bool, string, error) {
	expectedInternalDNSName := domain.BuildTenantInstanceName(tenant.ServiceID, tenant.SubjectKey)
	if tenant.InternalDNSName != "" && tenant.InternalDNSName != expectedInternalDNSName {
		return false, "", fmt.Errorf("tenant internal dns drift detected for %s", tenant.TenantID)
	}

	requestURL := "http://" + expectedInternalDNSName + ":" + itoa(service.InternalPort) + service.HealthPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return false, "", err
	}

	response, err := r.healthClient.Do(request)
	if err != nil {
		return false, "health request failed", err
	}
	defer response.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
	bodyText := strings.TrimSpace(string(bodyBytes))
	contentType := response.Header.Get("Content-Type")

	switch service.ServiceID {
	case "actualbudget":
		if response.StatusCode == http.StatusOK || response.StatusCode == http.StatusBadRequest {
			return true, "actualbudget responded on /http", nil
		}
	case "memory":
		if response.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(contentType), "text/event-stream") {
			return true, "memory returned an event stream", nil
		}
	case "mealie":
		if response.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(bodyText), "streamable") {
			return true, "mealie returned discovery json", nil
		}
	}

	return false, fmt.Sprintf("unexpected health response: status=%d content_type=%s body=%s", response.StatusCode, contentType, bodyText), nil
}

func buildUpstreamURL(tenant TenantInstance, service catalog.ServiceCatalogEntry) string {
	internalDNSName := domain.BuildTenantInstanceName(tenant.ServiceID, tenant.SubjectKey)
	return "http://" + internalDNSName + ":" + itoa(service.InternalPort) + service.InternalUpstreamPath
}

func stringPointer(value string) *string {
	return &value
}

func shouldRequeueDelete(lastReconciledAt *time.Time) bool {
	if lastReconciledAt == nil {
		return true
	}
	return time.Since(lastReconciledAt.UTC()) >= deleteRequeueInterval
}

func envsDrifted(current []CoolifyEnvVar, expected []CoolifyEnvVar) bool {
	currentByKey := make(map[string]CoolifyEnvVar, len(current))
	for _, currentEnv := range current {
		currentByKey[currentEnv.Key] = currentEnv
	}

	for _, expectedEnv := range expected {
		currentEnv, ok := currentByKey[expectedEnv.Key]
		if !ok {
			return true
		}
		if currentEnv.Value != expectedEnv.Value ||
			currentEnv.IsLiteral != expectedEnv.IsLiteral ||
			currentEnv.IsMultiline != expectedEnv.IsMultiline ||
			currentEnv.IsPreview != expectedEnv.IsPreview ||
			currentEnv.IsShownOnce != expectedEnv.IsShownOnce {
			return true
		}
	}
	return false
}

func renderMealieTenant(cfg Config, tenant TenantInstance, service catalog.ServiceCatalogEntry, secrets map[string]string) (renderedTenantService, error) {
	mealieBaseURL := strings.TrimSpace(cfg.MealieBaseURL)
	if mealieBaseURL == "" {
		return renderedTenantService{}, fmt.Errorf("mealie base url is required for mealie tenant rendering")
	}

	image := valueOrDefault(cfg.TenantImageMealie, defaultTenantImageMealie)
	compose := fmt.Sprintf(`services:
  %s:
    image: %s
    restart: unless-stopped
    environment:
      PORT: ${PORT}
      MEALIE_BASE_URL: ${MEALIE_BASE_URL}
      BEARER_TOKEN_OAUTH2PASSWORDBEARER: ${BEARER_TOKEN_OAUTH2PASSWORDBEARER}
    networks:
      - coolify
networks:
  coolify:
    external: true
`, tenant.TenantInstanceName, image)

	envs := []CoolifyEnvVar{
		{Key: "PORT", Value: itoa(service.InternalPort)},
		{Key: "MEALIE_BASE_URL", Value: mealieBaseURL},
		{Key: "BEARER_TOKEN_OAUTH2PASSWORDBEARER", Value: secrets["api-token"]},
	}

	return renderedTenantService{
		CreateRequest: buildCreateServiceRequest(cfg, tenant, compose),
		UpdateRequest: buildUpdateServiceRequest(cfg, tenant, compose),
		EnvVars:       envs,
		UpstreamURL:   buildUpstreamURL(tenant, service),
	}, nil
}

func renderActualBudgetTenant(cfg Config, tenant TenantInstance, service catalog.ServiceCatalogEntry, secrets map[string]string) (renderedTenantService, error) {
	actualServerURL := strings.TrimSpace(cfg.ActualServerURL)
	if actualServerURL == "" {
		return renderedTenantService{}, fmt.Errorf("actual server url is required for actualbudget tenant rendering")
	}

	image := valueOrDefault(cfg.TenantImageActualBudget, defaultTenantImageActualBudget)
	compose := fmt.Sprintf(`services:
  %s:
    image: %s
    restart: unless-stopped
    environment:
      HOST: ${HOST}
      MCP_BRIDGE_BIND_HOST: ${MCP_BRIDGE_BIND_HOST}
      MCP_BRIDGE_PORT: ${MCP_BRIDGE_PORT}
      MCP_BRIDGE_DATA_DIR: ${MCP_BRIDGE_DATA_DIR}
      MCP_BRIDGE_LOG_DIR: ${MCP_BRIDGE_LOG_DIR}
      NODE_ENV: ${NODE_ENV}
      TZ: ${TZ}
      ACTUAL_SERVER_URL: ${ACTUAL_SERVER_URL}
      ACTUAL_PASSWORD: ${ACTUAL_PASSWORD}
      ACTUAL_BUDGET_SYNC_ID: ${ACTUAL_BUDGET_SYNC_ID}
      ACTUAL_BUDGET_PASSWORD: ${ACTUAL_BUDGET_PASSWORD}
    volumes:
      - mcp_data:/data
      - mcp_logs:/app/logs
    networks:
      - coolify
volumes:
  mcp_data: {}
  mcp_logs: {}
networks:
  coolify:
    external: true
`, tenant.TenantInstanceName, image)

	envs := []CoolifyEnvVar{
		{Key: "HOST", Value: "0.0.0.0"},
		{Key: "MCP_BRIDGE_BIND_HOST", Value: "0.0.0.0"},
		{Key: "MCP_BRIDGE_PORT", Value: itoa(service.InternalPort)},
		{Key: "MCP_BRIDGE_DATA_DIR", Value: "/data"},
		{Key: "MCP_BRIDGE_LOG_DIR", Value: "/app/logs"},
		{Key: "NODE_ENV", Value: "production"},
		{Key: "TZ", Value: "UTC"},
		{Key: "ACTUAL_SERVER_URL", Value: actualServerURL},
		{Key: "ACTUAL_PASSWORD", Value: secrets["actual-api-key"]},
		{Key: "ACTUAL_BUDGET_SYNC_ID", Value: secrets["budget-sync-id"]},
	}
	if value := secrets["actual-budget-encryption-password"]; value != "" {
		envs = append(envs, CoolifyEnvVar{Key: "ACTUAL_BUDGET_PASSWORD", Value: value})
	}

	return renderedTenantService{
		CreateRequest: buildCreateServiceRequest(cfg, tenant, compose),
		UpdateRequest: buildUpdateServiceRequest(cfg, tenant, compose),
		EnvVars:       envs,
		UpstreamURL:   buildUpstreamURL(tenant, service),
	}, nil
}

func renderMemoryTenant(cfg Config, tenant TenantInstance, service catalog.ServiceCatalogEntry, secrets map[string]string) (renderedTenantService, error) {
	image := valueOrDefault(cfg.TenantImageMemory, defaultTenantImageMemory)
	compose := fmt.Sprintf(`services:
  %s:
    image: %s
    restart: unless-stopped
    command: ["-transport", "stdio", "-projects-dir", "/data/projects"]
    environment:
      PORT: ${PORT}
      TRANSPORT: ${TRANSPORT}
      SSE_ENDPOINT: ${SSE_ENDPOINT}
      MODE: ${MODE}
      MULTI_PROJECT_AUTH_REQUIRED: ${MULTI_PROJECT_AUTH_REQUIRED}
      RUN_ONCE: ${RUN_ONCE}
      PROJECTS_DIR: ${PROJECTS_DIR}
      METRICS_PORT: ${METRICS_PORT}
      METRICS_PROMETHEUS: ${METRICS_PROMETHEUS}
      LIBSQL_URL: ${LIBSQL_URL}
      LIBSQL_AUTH_TOKEN: ${LIBSQL_AUTH_TOKEN}
    volumes:
      - memory_data:/data
    networks:
      - coolify
volumes:
  memory_data: {}
networks:
  coolify:
    external: true
`, tenant.TenantInstanceName, image)

	envs := []CoolifyEnvVar{
		{Key: "PORT", Value: itoa(service.InternalPort)},
		{Key: "TRANSPORT", Value: "sse"},
		{Key: "SSE_ENDPOINT", Value: "/sse"},
		{Key: "MODE", Value: "multi"},
		{Key: "MULTI_PROJECT_AUTH_REQUIRED", Value: "false"},
		{Key: "RUN_ONCE", Value: "false"},
		{Key: "PROJECTS_DIR", Value: "/data/projects"},
		{Key: "METRICS_PORT", Value: "9090"},
		{Key: "METRICS_PROMETHEUS", Value: "true"},
		{Key: "LIBSQL_URL", Value: secrets["libsql-url"]},
		{Key: "LIBSQL_AUTH_TOKEN", Value: secrets["libsql-auth-token"]},
	}

	return renderedTenantService{
		CreateRequest: buildCreateServiceRequest(cfg, tenant, compose),
		UpdateRequest: buildUpdateServiceRequest(cfg, tenant, compose),
		EnvVars:       envs,
		UpstreamURL:   buildUpstreamURL(tenant, service),
	}, nil
}

func buildCreateServiceRequest(cfg Config, tenant TenantInstance, compose string) CoolifyCreateServiceRequest {
	return CoolifyCreateServiceRequest{
		Type:             "docker-compose",
		Name:             tenant.TenantInstanceName,
		Description:      "DragonServer MCP tenant " + tenant.ServiceID + " for " + tenant.SubjectKey,
		ProjectUUID:      cfg.CoolifyProjectUUID,
		EnvironmentName:  cfg.CoolifyEnvironmentName,
		EnvironmentUUID:  cfg.CoolifyEnvironmentUUID,
		ServerUUID:       cfg.CoolifyServerUUID,
		DestinationUUID:  cfg.CoolifyDestinationUUID,
		InstantDeploy:    true,
		DockerComposeRaw: compose,
	}
}

func buildUpdateServiceRequest(cfg Config, tenant TenantInstance, compose string) CoolifyUpdateServiceRequest {
	return CoolifyUpdateServiceRequest{
		Name:             tenant.TenantInstanceName,
		Description:      "DragonServer MCP tenant " + tenant.ServiceID + " for " + tenant.SubjectKey,
		ProjectUUID:      cfg.CoolifyProjectUUID,
		EnvironmentName:  cfg.CoolifyEnvironmentName,
		EnvironmentUUID:  cfg.CoolifyEnvironmentUUID,
		ServerUUID:       cfg.CoolifyServerUUID,
		DestinationUUID:  cfg.CoolifyDestinationUUID,
		InstantDeploy:    true,
		DockerComposeRaw: compose,
	}
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}
