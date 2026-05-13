package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"dragonserver/mcp-platform/internal/catalog"
)

var controlPlaneServiceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

type serviceCatalogRequest struct {
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
}

func (a *App) handleServices(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/services" {
		http.NotFound(w, r)
		return
	}
	if !a.requireAdminToken(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	entries, err := a.store.ListServiceCatalog(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "list_service_catalog_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"services": entries})
}

func (a *App) handleService(w http.ResponseWriter, r *http.Request) {
	serviceID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/services/"))
	if serviceID == "" || strings.Contains(serviceID, "/") {
		http.NotFound(w, r)
		return
	}
	if !a.requireAdminToken(w, r) {
		return
	}

	switch r.Method {
	case http.MethodPut:
		a.handleServicePut(w, r, serviceID)
	case http.MethodDelete:
		if err := validateServiceID(serviceID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if err := a.store.DisableServiceCatalogEntry(r.Context(), serviceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "disable_service_failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (a *App) handleServicePut(w http.ResponseWriter, r *http.Request, serviceID string) {
	var request serviceCatalogRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	entry := catalog.ServiceCatalogEntry{
		ServiceID:              serviceID,
		DisplayName:            strings.TrimSpace(request.DisplayName),
		UpstreamServiceName:    strings.TrimSpace(request.UpstreamServiceName),
		TransportType:          request.TransportType,
		InternalPort:           request.InternalPort,
		PublicPath:             strings.TrimRight(strings.TrimSpace(request.PublicPath), "/"),
		InternalUpstreamPath:   strings.TrimRight(strings.TrimSpace(request.InternalUpstreamPath), "/"),
		HealthPath:             strings.TrimRight(strings.TrimSpace(request.HealthPath), "/"),
		HealthProbeExpectation: strings.TrimSpace(request.HealthProbeExpectation),
		ResourceProfile:        strings.TrimSpace(request.ResourceProfile),
		PersistencePolicy:      strings.TrimSpace(request.PersistencePolicy),
		AdapterRequirement:     request.AdapterRequirement,
		SecretContract:         request.SecretContract,
	}
	if err := validateServiceCatalogEntry(entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := a.store.UpsertAdminServiceCatalogEntry(r.Context(), entry); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "upsert_service_failed"})
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (a *App) requireAdminToken(w http.ResponseWriter, r *http.Request) bool {
	if a.cfg.AdminTokenPath == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "admin_api_not_configured"})
		return false
	}
	expectedToken, err := ReadSecretFromFile(a.cfg.AdminTokenPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "admin_token_unavailable"})
		return false
	}
	providedToken := bearerToken(r.Header.Get("Authorization"))
	if providedToken == "" || subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return false
	}
	return true
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func validateServiceCatalogEntry(entry catalog.ServiceCatalogEntry) error {
	if err := validateServiceID(entry.ServiceID); err != nil {
		return err
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "display_name", value: entry.DisplayName},
		{name: "upstream_service_name", value: entry.UpstreamServiceName},
		{name: "health_probe_expectation", value: entry.HealthProbeExpectation},
		{name: "resource_profile", value: entry.ResourceProfile},
		{name: "persistence_policy", value: entry.PersistencePolicy},
	} {
		if field.value == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if entry.TransportType != catalog.TransportTypeStreamableHTTP && entry.TransportType != catalog.TransportTypeSSE {
		return fmt.Errorf("transport_type must be one of: streamable-http, sse")
	}
	if entry.AdapterRequirement != catalog.AdapterRequirementNone && entry.AdapterRequirement != catalog.AdapterRequirementPathTranslation && entry.AdapterRequirement != catalog.AdapterRequirementSSEToStreamableHTTP {
		return fmt.Errorf("adapter_requirement must be one of: none, path-translation, sse-to-streamable-http")
	}
	if entry.InternalPort < 1 || entry.InternalPort > 65535 {
		return fmt.Errorf("internal_port must be between 1 and 65535")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "public_path", value: entry.PublicPath},
		{name: "internal_upstream_path", value: entry.InternalUpstreamPath},
		{name: "health_path", value: entry.HealthPath},
	} {
		if field.value == "" || !strings.HasPrefix(field.value, "/") {
			return fmt.Errorf("%s must be an absolute path", field.name)
		}
	}
	if publicPathReservedForControlPlane(entry.PublicPath) {
		return fmt.Errorf("public_path conflicts with a reserved edge route")
	}
	for _, secret := range entry.SecretContract {
		if strings.TrimSpace(secret.Key) == "" {
			return fmt.Errorf("secret_contract key is required")
		}
	}
	return nil
}

func validateServiceID(serviceID string) error {
	if !controlPlaneServiceIDPattern.MatchString(strings.TrimSpace(serviceID)) {
		return fmt.Errorf("service_id must match %s", controlPlaneServiceIDPattern.String())
	}
	return nil
}

func publicPathReservedForControlPlane(publicPath string) bool {
	for _, reserved := range []string{"/health", "/health/live", "/health/ready", "/auth", "/oauth", "/.well-known", "/v1"} {
		if publicPath == reserved || strings.HasPrefix(publicPath, reserved+"/") {
			return true
		}
	}
	return false
}
