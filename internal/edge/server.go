package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/ids"

	"github.com/rs/zerolog"
)

const correlationIDHeader = "X-Correlation-ID"

type requestContextKey string

const correlationIDContextKey requestContextKey = "correlation_id"

var ErrServiceNotFound = errors.New("service not found")

type Server struct {
	logger                    zerolog.Logger
	publicURL                 string
	resolver                  Resolver
	catalogCache              *CatalogCache
	fixtureInsecureSkipVerify bool
	stateStore                edgeStateStore
	oauth                     *OAuthService
	auth                      *AuthRuntime
}

func NewServer(cfg Config, logger zerolog.Logger, resolver Resolver) (*Server, error) {
	return NewServerWithStateStore(context.Background(), cfg, logger, resolver, nil)
}

func NewServerWithStateStore(ctx context.Context, cfg Config, logger zerolog.Logger, resolver Resolver, stateStore edgeStateStore) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	stateStoreOwned := false
	if stateStore == nil {
		var err error
		stateStore, err = newEdgeStateStore(ctx, cfg, logger)
		if err != nil {
			return nil, err
		}
		stateStoreOwned = true
	}
	catalogCache := NewCatalogCache(stateStore, logger)
	if err := catalogCache.Refresh(ctx); err != nil {
		if stateStoreOwned {
			_ = stateStore.Close()
		}
		return nil, err
	}
	if catalogCache.Len() == 0 {
		if stateStoreOwned {
			_ = stateStore.Close()
		}
		return nil, errors.New("no enabled services in service catalog")
	}
	if resolver == nil {
		var err error
		resolver, err = buildDefaultResolver(cfg, catalogCache, stateStore)
		if err != nil {
			if stateStoreOwned {
				_ = stateStore.Close()
			}
			return nil, err
		}
	}

	authRuntime, err := NewAuthRuntime(cfg, logger, stateStore)
	if err != nil {
		if stateStoreOwned {
			_ = stateStore.Close()
		}
		return nil, err
	}
	oauthService, err := NewOAuthService(cfg, logger, catalogCache, stateStore, authRuntime, authRuntime)
	if err != nil {
		if stateStoreOwned {
			_ = stateStore.Close()
		}
		return nil, err
	}

	return &Server{
		logger:                    logger,
		publicURL:                 cfg.PublicBaseURL,
		resolver:                  resolver,
		catalogCache:              catalogCache,
		fixtureInsecureSkipVerify: cfg.FixtureInsecureSkipVerify,
		stateStore:                stateStore,
		auth:                      authRuntime,
		oauth:                     oauthService,
	}, nil
}

func (s *Server) Close() error {
	if s.stateStore == nil {
		return nil
	}
	return s.stateStore.Close()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", s.handleLiveness)
	mux.HandleFunc("/health/ready", s.handleReadiness)
	mux.HandleFunc("/health", s.handleReadiness)
	s.auth.RegisterRoutes(mux)
	s.oauth.RegisterRoutes(mux)
	mux.HandleFunc("/", s.handleServiceRequest)

	return s.withRequestContext(mux)
}

func (s *Server) ListenAndServe(ctx context.Context, cfg Config) error {
	server := &http.Server{
		Addr:              cfg.HTTPBindAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go s.catalogCache.RunRefreshLoop(ctx, edgeCatalogRefreshInterval)

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	s.logger.Info().
		Str("bind_addr", cfg.HTTPBindAddr).
		Str("public_base_url", cfg.PublicBaseURL).
		Msg("starting mcp-edge http server")

	err := server.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "live",
		"ts":     time.Now().UTC(),
	})
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if s.stateStore != nil {
		if err := s.stateStore.Ping(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":            "not_ready",
				"public_base_url":   s.publicURL,
				"services":          s.catalogCache.Len(),
				"catalog_loaded_at": s.catalogCache.LoadedAt(),
				"catalog_error":     s.catalogCache.LastError(),
				"error":             "state_store_unavailable",
				"ts":                time.Now().UTC(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ready",
		"public_base_url":   s.publicURL,
		"services":          s.catalogCache.Len(),
		"catalog_loaded_at": s.catalogCache.LoadedAt(),
		"catalog_error":     s.catalogCache.LastError(),
		"ts":                time.Now().UTC(),
	})
}

func (s *Server) handleServiceRequest(w http.ResponseWriter, r *http.Request) {
	service, ok := s.catalogCache.MatchPublicPath(r.URL.Path)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "service_not_found", "requested service is not registered on this edge")
		return
	}
	s.handleServiceRoute(service)(w, r)
}

func (s *Server) handleServiceRoute(service catalog.ServiceCatalogEntry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		tokenInfo, err := s.oauth.ValidateBearerToken(r)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-edge", resource_metadata="`+strings.TrimRight(s.publicURL, "/")+`/.well-known/oauth-protected-resource"`)
			s.recordAuditEvent(r.Context(), edgeAuditEvent{
				ServiceID:   service.ServiceID,
				EventType:   "mcp.service.access.denied",
				EventStatus: "invalid_token",
				Payload: map[string]any{
					"path": r.URL.Path,
				},
			})
			writeJSONError(w, http.StatusUnauthorized, "invalid_token", "a valid bearer token is required for MCP service access")
			return
		}
		if !scopeIncludesService(tokenInfo.GetScope(), service.ServiceID) {
			s.recordAuditEvent(r.Context(), edgeAuditEvent{
				ActorSubjectSub: tokenInfo.GetUserID(),
				ServiceID:       service.ServiceID,
				EventType:       "mcp.service.access.denied",
				EventStatus:     "insufficient_scope",
				Payload: map[string]any{
					"scope": tokenInfo.GetScope(),
				},
			})
			writeJSONError(w, http.StatusForbidden, "insufficient_scope", "token scope does not cover this MCP service")
			return
		}
		if s.auth != nil {
			allowed, err := s.auth.Allowed(r.Context(), tokenInfo.GetUserID(), service.ServiceID)
			if err != nil {
				s.logger.Error().
					Err(err).
					Str("service_id", service.ServiceID).
					Str("subject_sub", tokenInfo.GetUserID()).
					Msg("service grant lookup failed")
				s.recordAuditEvent(r.Context(), edgeAuditEvent{
					ActorSubjectSub: tokenInfo.GetUserID(),
					ServiceID:       service.ServiceID,
					EventType:       "mcp.service.access.denied",
					EventStatus:     "authorization_unavailable",
				})
				writeJSONError(w, http.StatusServiceUnavailable, "authorization_unavailable", "unable to validate subject service grants")
				return
			}
			if !allowed {
				s.recordAuditEvent(r.Context(), edgeAuditEvent{
					ActorSubjectSub: tokenInfo.GetUserID(),
					ServiceID:       service.ServiceID,
					EventType:       "mcp.service.access.denied",
					EventStatus:     "service_not_granted",
				})
				writeJSONError(w, http.StatusForbidden, "service_not_granted", "subject is not entitled to this MCP service")
				return
			}
		}

		target, err := s.resolver.Resolve(r.Context(), service.ServiceID, tokenInfo.GetUserID())
		if err != nil {
			statusCode := http.StatusServiceUnavailable
			errorCode := "tenant_resolution_unavailable"
			message := "unable to resolve tenant backend for this service"
			if errors.Is(err, ErrServiceNotFound) {
				statusCode = http.StatusNotFound
				errorCode = "service_not_found"
				message = "requested service is not registered on this edge"
			} else if errors.Is(err, ErrTenantNotReady) {
				errorCode = "tenant_not_ready"
				message = "requested tenant backend is not ready yet"
			} else if errors.Is(err, ErrTenantUpstreamNotConfigured) {
				errorCode = "tenant_not_configured"
				message = "requested tenant backend is not available yet"
			}
			s.logger.Error().
				Err(err).
				Str("service_id", service.ServiceID).
				Str("subject_sub", tokenInfo.GetUserID()).
				Msg("tenant resolution failed")
			s.recordAuditEvent(r.Context(), edgeAuditEvent{
				ActorSubjectSub: tokenInfo.GetUserID(),
				ServiceID:       service.ServiceID,
				EventType:       "mcp.service.access.denied",
				EventStatus:     errorCode,
			})
			writeJSONError(w, statusCode, errorCode, message)
			return
		}

		s.recordAuditEvent(r.Context(), edgeAuditEvent{
			ActorSubjectSub: tokenInfo.GetUserID(),
			ServiceID:       service.ServiceID,
			EventType:       "mcp.service.access.allowed",
			EventStatus:     "allowed",
			Payload: map[string]any{
				"path": r.URL.Path,
			},
		})

		if service.AdapterRequirement == catalog.AdapterRequirementSSEToStreamableHTTP {
			bridge := NewSSEToStreamableHTTPBridge(
				target.BaseURL,
				service.PublicPath,
				service.InternalUpstreamPath,
				s.fixtureInsecureSkipVerify,
				s.logger,
			)
			bridge.ServeHTTP(w, r)
			return
		}

		proxy := NewStreamSafeReverseProxy(
			target.BaseURL,
			service.PublicPath,
			service.InternalUpstreamPath,
			s.fixtureInsecureSkipVerify,
			s.logger,
		)
		proxy.ServeHTTP(w, r)
	}
}

func (s *Server) withRequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		correlationID := strings.TrimSpace(r.Header.Get(correlationIDHeader))
		if correlationID == "" {
			correlationID = ids.New().String()
		}

		r = r.WithContext(context.WithValue(r.Context(), correlationIDContextKey, correlationID))
		r = s.auth.InjectBrowserSubject(r)
		w.Header().Set(correlationIDHeader, correlationID)
		s.logger.Info().
			Str("correlation_id", correlationID).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Msg("edge request")

		next.ServeHTTP(w, r)
	})
}

func (s *Server) recordAuditEvent(ctx context.Context, event edgeAuditEvent) {
	if s.stateStore == nil {
		return
	}
	if correlationID, ok := ctx.Value(correlationIDContextKey).(string); ok && event.CorrelationID == "" {
		event.CorrelationID = correlationID
	}
	if err := s.stateStore.RecordAuditEvent(ctx, event); err != nil {
		s.logger.Error().Err(err).Str("event_type", event.EventType).Msg("failed to record edge audit event")
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, statusCode int, code string, message string) {
	writeJSON(w, statusCode, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func scopeIncludesService(scope string, serviceID string) bool {
	if strings.TrimSpace(scope) == "" {
		return false
	}
	targetScope := "mcp:" + serviceID
	for _, scopeEntry := range strings.Fields(scope) {
		if scopeEntry == targetScope {
			return true
		}
	}
	return false
}
