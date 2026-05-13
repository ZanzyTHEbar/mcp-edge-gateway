package controlplane

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"dragonserver/mcp-platform/internal/domain"
)

const manualGrantSource = "manual"

type manualGrantRequest struct {
	SubjectKey        string `json:"subject_key"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	DisplayName       string `json:"display_name"`
}

func (a *App) handleSubject(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdminToken(w, r) {
		return
	}
	subjectSub, tail, ok := parseSubjectAdminPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if tail == "grants" {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		grants, err := a.store.ListSubjectServiceGrants(r.Context(), subjectSub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "list_grants_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"subject_sub": subjectSub, "grants": grants})
		return
	}
	if serviceID, ok := parseSubjectServiceUpstreamTail(tail); ok {
		if err := validateServiceID(serviceID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if r.Method != http.MethodPut {
			w.Header().Set("Allow", http.MethodPut)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
			return
		}
		a.handleStaticUpstreamPut(w, r, subjectSub, serviceID)
		return
	}

	serviceID := strings.TrimPrefix(tail, "grants/")
	if serviceID == tail || serviceID == "" || strings.Contains(serviceID, "/") {
		http.NotFound(w, r)
		return
	}
	if err := validateServiceID(serviceID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	switch r.Method {
	case http.MethodPut:
		a.handleManualGrantPut(w, r, subjectSub, serviceID)
	case http.MethodDelete:
		if err := a.store.DeleteManualServiceGrant(r.Context(), subjectSub, serviceID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete_grant_failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodPut, http.MethodDelete}, ", "))
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (a *App) handleManualGrantPut(w http.ResponseWriter, r *http.Request, subjectSub string, serviceID string) {
	var request manualGrantRequest
	if r.Body != nil {
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
			return
		}
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
	if err := a.store.UpsertManualServiceGrant(r.Context(), subject, serviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "service_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "upsert_manual_grant_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subject_sub": subjectSub, "service_id": serviceID, "source_group": manualGrantSource})
}

func parseSubjectServiceUpstreamTail(tail string) (string, bool) {
	if !strings.HasPrefix(tail, "services/") || !strings.HasSuffix(tail, "/upstream") {
		return "", false
	}
	serviceID := strings.TrimSuffix(strings.TrimPrefix(tail, "services/"), "/upstream")
	if serviceID == "" || strings.Contains(serviceID, "/") {
		return "", false
	}
	return serviceID, true
}

func parseSubjectAdminPath(requestPath string) (string, string, bool) {
	remainder := strings.TrimPrefix(requestPath, "/v1/subjects/")
	if remainder == requestPath || remainder == "" {
		return "", "", false
	}
	separator := strings.Index(remainder, "/grants")
	if serviceSeparator := strings.Index(remainder, "/services/"); separator < 0 || serviceSeparator >= 0 && serviceSeparator < separator {
		separator = serviceSeparator
	}
	if separator <= 0 {
		return "", "", false
	}
	subjectSub := strings.TrimSpace(remainder[:separator])
	tail := strings.TrimPrefix(remainder[separator:], "/")
	return subjectSub, tail, subjectSub != "" && tail != ""
}
