package controlplane

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"
)

type staticUpstreamRequest struct {
	UpstreamURL       string `json:"upstream_url"`
	SubjectKey        string `json:"subject_key"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	DisplayName       string `json:"display_name"`
}

var lookupStaticUpstreamIP = net.LookupIP

var newStaticUpstreamHealthClient = func() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (a *App) handleStaticUpstreamPut(w http.ResponseWriter, r *http.Request, subjectSub string, serviceID string) {
	var request staticUpstreamRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	subject := domain.Subject{
		Sub:               subjectSub,
		SubjectKey:        strings.TrimSpace(request.SubjectKey),
		PreferredUsername: strings.TrimSpace(request.PreferredUsername),
		Email:             strings.TrimSpace(request.Email),
		DisplayName:       strings.TrimSpace(request.DisplayName),
	}
	if subject.Sub == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "subject_sub is required"})
		return
	}
	upstreamURL, err := normalizeStaticUpstreamURL(request.UpstreamURL)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	service, err := a.store.GetEnabledServiceCatalogEntry(r.Context(), serviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "service_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "load_service_failed"})
		return
	}
	granted, err := a.store.SubjectServiceGranted(r.Context(), subject.Sub, serviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "check_service_grant_failed"})
		return
	}
	if !granted {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "service_not_granted"})
		return
	}
	verifiedAt, err := verifyStaticUpstreamHealth(r, upstreamURL, service)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream_healthcheck_failed", "detail": err.Error()})
		return
	}
	if err := a.store.UpsertStaticTenantUpstream(r.Context(), subject, serviceID, upstreamURL, verifiedAt); err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "service_not_found"})
		case errors.Is(err, ErrSubjectServiceGrantNotFound):
			writeJSON(w, http.StatusConflict, map[string]any{"error": "service_not_granted"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "upsert_static_upstream_failed"})
		}
		return
	}
	writeJSON(w, http.StatusOK, StaticUpstreamBinding{SubjectSub: subjectSub, ServiceID: serviceID, UpstreamURL: upstreamURL, VerifiedAt: verifiedAt})
}

func normalizeStaticUpstreamURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", fmt.Errorf("upstream_url is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("upstream_url is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("upstream_url scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("upstream_url host is required")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("upstream_url must not include user info")
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil && !allowedStaticUpstreamIP(ip) {
		return "", fmt.Errorf("upstream_url ip address is not allowed")
	} else if ip == nil {
		ips, err := lookupStaticUpstreamIP(host)
		if err != nil || len(ips) == 0 {
			return "", fmt.Errorf("upstream_url host could not be resolved")
		}
		for _, resolvedIP := range ips {
			if !allowedStaticUpstreamIP(resolvedIP) {
				return "", fmt.Errorf("upstream_url resolved ip address is not allowed")
			}
		}
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed.String(), nil
}

func verifyStaticUpstreamHealth(r *http.Request, upstreamURL string, service catalog.ServiceCatalogEntry) (time.Time, error) {
	runtime := &CoolifyTenantRuntime{healthClient: newStaticUpstreamHealthClient()}
	healthy, detail, err := runtime.probeTenantHealth(r.Context(), TenantInstance{ServiceID: service.ServiceID}, service, "", upstreamURL)
	if err != nil {
		return time.Time{}, err
	}
	if !healthy {
		return time.Time{}, fmt.Errorf("%s", detail)
	}
	return time.Now().UTC(), nil
}

func allowedStaticUpstreamIP(ip net.IP) bool {
	return !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}

func staticUpstreamHealthURL(upstreamURL string, healthPath string) (string, error) {
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(healthPath)
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("health path must be absolute")
	}
	parsed.Path = path
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
