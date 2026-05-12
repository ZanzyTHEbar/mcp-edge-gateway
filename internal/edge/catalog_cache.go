package edge

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"dragonserver/mcp-platform/internal/catalog"

	"github.com/rs/zerolog"
)

const edgeCatalogRefreshInterval = 15 * time.Second

var serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

type CatalogSnapshot struct {
	entries      []catalog.ServiceCatalogEntry
	byServiceID  map[string]catalog.ServiceCatalogEntry
	publicPaths  []string
	byPublicPath map[string]catalog.ServiceCatalogEntry
	scopes       []string
	loadedAt     time.Time
}

type CatalogCache struct {
	store     edgeStateStore
	logger    zerolog.Logger
	snapshot  atomic.Pointer[CatalogSnapshot]
	lastError atomic.Value
}

func NewCatalogCache(store edgeStateStore, logger zerolog.Logger) *CatalogCache {
	return &CatalogCache{store: store, logger: logger}
}

func (c *CatalogCache) Refresh(ctx context.Context) error {
	entries, err := c.store.ListEnabledServiceCatalog(ctx)
	if err != nil {
		c.lastError.Store(err.Error())
		return err
	}
	snapshot, err := newCatalogSnapshot(entries, time.Now().UTC())
	if err != nil {
		c.lastError.Store(err.Error())
		return err
	}
	c.snapshot.Store(snapshot)
	c.lastError.Store("")
	return nil
}

func (c *CatalogCache) RunRefreshLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = edgeCatalogRefreshInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(ctx); err != nil {
				c.logger.Error().Err(err).Msg("edge service catalog refresh failed; keeping last good snapshot")
			}
		}
	}
}

func (c *CatalogCache) Current() *CatalogSnapshot {
	return c.snapshot.Load()
}

func (c *CatalogCache) Len() int {
	if snapshot := c.Current(); snapshot != nil {
		return len(snapshot.entries)
	}
	return 0
}

func (c *CatalogCache) LastError() string {
	if value := c.lastError.Load(); value != nil {
		return value.(string)
	}
	return ""
}

func (c *CatalogCache) LoadedAt() *time.Time {
	if snapshot := c.Current(); snapshot != nil {
		loadedAt := snapshot.loadedAt
		return &loadedAt
	}
	return nil
}

func (c *CatalogCache) ServiceByID(serviceID string) (catalog.ServiceCatalogEntry, bool) {
	if snapshot := c.Current(); snapshot != nil {
		return snapshot.ServiceByID(serviceID)
	}
	return catalog.ServiceCatalogEntry{}, false
}

func (c *CatalogCache) MatchPublicPath(path string) (catalog.ServiceCatalogEntry, bool) {
	if snapshot := c.Current(); snapshot != nil {
		return snapshot.MatchPublicPath(path)
	}
	return catalog.ServiceCatalogEntry{}, false
}

func (c *CatalogCache) Scopes() []string {
	if snapshot := c.Current(); snapshot != nil {
		return snapshot.Scopes()
	}
	return nil
}

func newCatalogSnapshot(entries []catalog.ServiceCatalogEntry, loadedAt time.Time) (*CatalogSnapshot, error) {
	snapshot := &CatalogSnapshot{
		entries:      make([]catalog.ServiceCatalogEntry, 0, len(entries)),
		byServiceID:  make(map[string]catalog.ServiceCatalogEntry, len(entries)),
		byPublicPath: make(map[string]catalog.ServiceCatalogEntry, len(entries)),
		publicPaths:  make([]string, 0, len(entries)),
		scopes:       make([]string, 0, len(entries)),
		loadedAt:     loadedAt,
	}

	for _, entry := range entries {
		serviceID := strings.TrimSpace(entry.ServiceID)
		if serviceID == "" {
			return nil, fmt.Errorf("service catalog entry has empty service_id")
		}
		if !serviceIDPattern.MatchString(serviceID) {
			return nil, fmt.Errorf("service catalog entry has invalid service_id %q", serviceID)
		}
		if _, exists := snapshot.byServiceID[serviceID]; exists {
			return nil, fmt.Errorf("duplicate service catalog service_id %q", serviceID)
		}
		publicPath := strings.TrimRight(strings.TrimSpace(entry.PublicPath), "/")
		if publicPath == "" || !strings.HasPrefix(publicPath, "/") {
			return nil, fmt.Errorf("service %s has invalid public path %q", serviceID, entry.PublicPath)
		}
		if publicPathReserved(publicPath) {
			return nil, fmt.Errorf("service %s public path %q conflicts with a reserved edge route", serviceID, publicPath)
		}
		if _, exists := snapshot.byPublicPath[publicPath]; exists {
			return nil, fmt.Errorf("duplicate service catalog public path %q", publicPath)
		}
		entry.ServiceID = serviceID
		entry.PublicPath = publicPath
		entry.SecretContract = slices.Clone(entry.SecretContract)
		snapshot.entries = append(snapshot.entries, entry)
		snapshot.byServiceID[serviceID] = entry
		snapshot.byPublicPath[publicPath] = entry
		snapshot.publicPaths = append(snapshot.publicPaths, publicPath)
		snapshot.scopes = append(snapshot.scopes, "mcp:"+serviceID)
	}

	slices.SortFunc(snapshot.publicPaths, func(a, b string) int {
		return len(b) - len(a)
	})
	slices.Sort(snapshot.scopes)
	return snapshot, nil
}

func publicPathReserved(publicPath string) bool {
	for _, reserved := range []string{"/health", "/health/live", "/health/ready", "/auth", "/oauth", "/.well-known"} {
		if publicPath == reserved || strings.HasPrefix(publicPath, reserved+"/") {
			return true
		}
	}
	return false
}

func (s *CatalogSnapshot) ServiceByID(serviceID string) (catalog.ServiceCatalogEntry, bool) {
	entry, ok := s.byServiceID[serviceID]
	return entry, ok
}

func (s *CatalogSnapshot) MatchPublicPath(path string) (catalog.ServiceCatalogEntry, bool) {
	for _, publicPath := range s.publicPaths {
		if path == publicPath || strings.HasPrefix(path, publicPath+"/") {
			return s.byPublicPath[publicPath], true
		}
	}
	return catalog.ServiceCatalogEntry{}, false
}

func (s *CatalogSnapshot) Scopes() []string {
	return slices.Clone(s.scopes)
}
