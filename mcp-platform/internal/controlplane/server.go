package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

type App struct {
	cfg        Config
	logger     zerolog.Logger
	store      *Store
	deps       *DependencyClients
	reconciler *Reconciler
	health     *healthState
}

type healthState struct {
	mu              sync.RWMutex
	ready           bool
	databaseOK      bool
	databaseError   string
	reconcileError  string
	lastReconcileAt *time.Time
	lastSummary     ReconcileSummary
}

type healthSnapshot struct {
	Ready           bool             `json:"ready"`
	DatabaseOK      bool             `json:"database_ok"`
	LastError       string           `json:"last_error,omitempty"`
	LastReconcileAt *time.Time       `json:"last_reconcile_at,omitempty"`
	LastSummary     ReconcileSummary `json:"last_summary"`
}

func NewApp(ctx context.Context, cfg Config, logger zerolog.Logger) (*App, error) {
	store, err := NewStore(ctx, cfg.DatabaseURL, logger)
	if err != nil {
		return nil, err
	}

	app := &App{
		cfg:        cfg,
		logger:     logger,
		store:      store,
		reconciler: NewReconciler(store, logger),
		health:     &healthState{},
	}
	if err := app.configureDependencies(ctx); err != nil {
		app.Close()
		return nil, err
	}
	return app, nil
}

func (a *App) Close() {
	if a.store != nil {
		a.store.Close()
	}
}

func (a *App) Run(ctx context.Context) error {
	if err := a.runStartupSequence(ctx); err != nil {
		return err
	}

	server := &http.Server{
		Addr:              a.cfg.HTTPBindAddr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go a.runLoops(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	a.logger.Info().
		Str("bind_addr", a.cfg.HTTPBindAddr).
		Msg("starting mcp-control-plane http server")

	err := server.ListenAndServe()
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *App) runStartupSequence(ctx context.Context) error {
	return runStartupSequence(
		ctx,
		a.logger,
		a.store.RunMigrations,
		a.store.SeedServiceCatalog,
		a.runHealthProbe,
		a.runReconcileCycle,
	)
}

func runStartupSequence(
	ctx context.Context,
	logger zerolog.Logger,
	runMigrations func(context.Context) error,
	seedServiceCatalog func(context.Context) error,
	runHealthProbe func(context.Context) error,
	runReconcileCycle func(context.Context) (ReconcileSummary, error),
) error {
	if err := runMigrations(ctx); err != nil {
		return err
	}
	if err := seedServiceCatalog(ctx); err != nil {
		return err
	}
	if err := runHealthProbe(ctx); err != nil {
		return err
	}
	if _, err := runReconcileCycle(ctx); err != nil {
		logger.Error().Err(err).Msg("initial control-plane reconcile failed; starting in degraded mode")
	}
	return nil
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", a.handleLiveness)
	mux.HandleFunc("/health/ready", a.handleReadiness)
	mux.HandleFunc("/health", a.handleReadiness)
	return mux
}

func (a *App) runLoops(ctx context.Context) {
	reconcileTicker := time.NewTicker(a.cfg.ReconcileInterval)
	healthTicker := time.NewTicker(a.cfg.HealthcheckInterval)
	defer reconcileTicker.Stop()
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-reconcileTicker.C:
			if _, err := a.runReconcileCycle(ctx); err != nil {
				a.logger.Error().Err(err).Msg("control-plane reconcile cycle failed")
			}
		case <-healthTicker.C:
			if err := a.runHealthProbe(ctx); err != nil {
				a.logger.Error().Err(err).Msg("control-plane health probe failed")
			}
		}
	}
}

func (a *App) runHealthProbe(ctx context.Context) error {
	err := a.store.Ping(ctx)
	a.health.setDatabaseStatus(err)
	if err != nil {
		return err
	}
	return nil
}

func (a *App) runReconcileCycle(ctx context.Context) (ReconcileSummary, error) {
	if a.deps != nil && a.deps.Authentik != nil {
		if err := a.deps.Authentik.SyncStore(ctx, a.store); err != nil {
			a.health.setReconcileResult(ReconcileSummary{}, err)
			return ReconcileSummary{}, err
		}
	}
	if err := a.store.ReconcileDesiredTenants(ctx); err != nil {
		a.health.setReconcileResult(ReconcileSummary{}, err)
		return ReconcileSummary{}, err
	}

	summary, err := a.reconciler.RunOnce(ctx)
	a.health.setReconcileResult(summary, err)
	if err != nil {
		return ReconcileSummary{}, err
	}
	return summary, nil
}

func (a *App) configureDependencies(ctx context.Context) error {
	if !a.cfg.HasDependencyConfig() {
		a.logger.Info().Msg("control-plane external dependency clients are not configured; using noop runtime")
		return nil
	}

	deps, err := NewDependencyClients(ctx, a.cfg, a.logger)
	if err != nil {
		return err
	}
	a.deps = deps

	if !a.cfg.HasTenantRuntimeConfig() {
		a.logger.Info().Msg("control-plane tenant runtime target is not configured; keeping noop runtime")
		return nil
	}

	a.reconciler = NewReconcilerWithRuntime(a.store, NewCoolifyTenantRuntime(a.cfg, a.store, deps, a.logger), a.logger)
	return nil
}

func (a *App) handleLiveness(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "live",
		"ts":     time.Now().UTC(),
	})
}

func (a *App) handleReadiness(w http.ResponseWriter, r *http.Request) {
	snapshot := a.health.snapshot()
	statusCode := http.StatusOK
	statusText := "ready"
	if !snapshot.Ready {
		statusCode = http.StatusServiceUnavailable
		statusText = "not_ready"
	}

	writeJSON(w, statusCode, map[string]any{
		"status":            statusText,
		"database_ok":       snapshot.DatabaseOK,
		"last_error":        snapshot.LastError,
		"last_reconcile_at": snapshot.LastReconcileAt,
		"last_summary":      snapshot.LastSummary,
		"ts":                time.Now().UTC(),
	})
}

func (h *healthState) snapshot() healthSnapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return healthSnapshot{
		Ready:           h.ready,
		DatabaseOK:      h.databaseOK,
		LastError:       h.currentError(),
		LastReconcileAt: h.lastReconcileAt,
		LastSummary:     h.lastSummary,
	}
}

func (h *healthState) setDatabaseStatus(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.databaseOK = err == nil
	if err != nil {
		h.databaseError = err.Error()
		h.ready = false
		return
	}
	h.databaseError = ""
	h.ready = h.reconcileError == ""
}

func (h *healthState) setReconcileResult(summary ReconcileSummary, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastSummary = summary
	if !summary.LastRunAt.IsZero() {
		runAt := summary.LastRunAt
		h.lastReconcileAt = &runAt
	}
	if err != nil {
		h.reconcileError = err.Error()
		h.ready = false
		return
	}
	h.reconcileError = ""
	h.ready = h.databaseOK
}

func (h *healthState) currentError() string {
	if h.reconcileError != "" {
		return h.reconcileError
	}
	return h.databaseError
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
