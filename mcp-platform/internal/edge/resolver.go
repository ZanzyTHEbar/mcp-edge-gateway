package edge

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"dragonserver/mcp-platform/internal/catalog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrTenantUpstreamNotConfigured = errors.New("tenant upstream not configured")
var ErrTenantNotReady = errors.New("tenant is not ready")

type UpstreamTarget struct {
	Service catalog.ServiceCatalogEntry
	BaseURL *url.URL
}

type Resolver interface {
	Resolve(ctx context.Context, serviceID string, subjectSub string) (UpstreamTarget, error)
}

type FixtureResolver struct {
	services  map[string]catalog.ServiceCatalogEntry
	upstreams map[string]*url.URL
}

type DatabaseResolver struct {
	services map[string]catalog.ServiceCatalogEntry
	pool     *pgxpool.Pool
}

func NewFixtureResolver(cfg Config) (*FixtureResolver, error) {
	entries := catalog.DefaultCatalogV1()
	services := make(map[string]catalog.ServiceCatalogEntry, len(entries))
	for _, entry := range entries {
		services[entry.ServiceID] = entry
	}

	upstreams := make(map[string]*url.URL, len(entries))
	if err := addUpstream(upstreams, "mealie", cfg.FixtureUpstreamMealieURL); err != nil {
		return nil, err
	}
	if err := addUpstream(upstreams, "actualbudget", cfg.FixtureUpstreamActualBudgetURL); err != nil {
		return nil, err
	}
	if err := addUpstream(upstreams, "memory", cfg.FixtureUpstreamMemoryURL); err != nil {
		return nil, err
	}

	return &FixtureResolver{
		services:  services,
		upstreams: upstreams,
	}, nil
}

func NewDatabaseResolver(entries []catalog.ServiceCatalogEntry, stateStore edgeStateStore) (*DatabaseResolver, error) {
	postgresStore, ok := stateStore.(*postgresEdgeStateStore)
	if !ok {
		return nil, fmt.Errorf("database resolver requires postgres-backed edge state")
	}
	services := make(map[string]catalog.ServiceCatalogEntry, len(entries))
	for _, entry := range entries {
		services[entry.ServiceID] = entry
	}
	return &DatabaseResolver{
		services: services,
		pool:     postgresStore.pool,
	}, nil
}

func buildDefaultResolver(cfg Config, entries []catalog.ServiceCatalogEntry, stateStore edgeStateStore) (Resolver, error) {
	if cfg.EnableFixtureMode {
		return NewFixtureResolver(cfg)
	}
	return NewDatabaseResolver(entries, stateStore)
}

func (r *FixtureResolver) Resolve(_ context.Context, serviceID string, _ string) (UpstreamTarget, error) {
	service, ok := r.services[serviceID]
	if !ok {
		return UpstreamTarget{}, ErrServiceNotFound
	}

	target, ok := r.upstreams[serviceID]
	if !ok || target == nil {
		return UpstreamTarget{}, ErrTenantUpstreamNotConfigured
	}

	return UpstreamTarget{
		Service: service,
		BaseURL: target,
	}, nil
}

func (r *DatabaseResolver) Resolve(ctx context.Context, serviceID string, subjectSub string) (UpstreamTarget, error) {
	service, ok := r.services[serviceID]
	if !ok {
		return UpstreamTarget{}, ErrServiceNotFound
	}
	var (
		upstreamURL  string
		desiredState string
		runtimeState string
	)
	err := r.pool.QueryRow(
		ctx,
		`
			select
				coalesce(upstream_url, ''),
				desired_state,
				runtime_state
			from tenant_instances
			where subject_sub = $1
				and service_id = $2
		`,
		subjectSub,
		serviceID,
	).Scan(&upstreamURL, &desiredState, &runtimeState)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return UpstreamTarget{}, ErrTenantUpstreamNotConfigured
		}
		return UpstreamTarget{}, fmt.Errorf("resolve tenant upstream for %s/%s: %w", subjectSub, serviceID, err)
	}
	if desiredState != "enabled" || runtimeState != "ready" {
		return UpstreamTarget{}, ErrTenantNotReady
	}
	if strings.TrimSpace(upstreamURL) == "" {
		return UpstreamTarget{}, ErrTenantUpstreamNotConfigured
	}
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil {
		return UpstreamTarget{}, fmt.Errorf("parse tenant upstream url for %s/%s: %w", subjectSub, serviceID, err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return UpstreamTarget{}, fmt.Errorf("tenant upstream url is incomplete for %s/%s", subjectSub, serviceID)
	}
	return UpstreamTarget{
		Service: service,
		BaseURL: parsedURL,
	}, nil
}

func addUpstream(upstreams map[string]*url.URL, serviceID string, rawURL string) error {
	if rawURL == "" {
		return nil
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return err
	}

	upstreams[serviceID] = parsedURL
	return nil
}
