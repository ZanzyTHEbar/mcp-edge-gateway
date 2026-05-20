package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"
	"dragonserver/mcp-platform/internal/ids"
	platformsqlite "dragonserver/mcp-platform/internal/platform/sqlite"
	"dragonserver/mcp-platform/internal/platform/sqlite/platformdb"

	"github.com/rs/zerolog"
)

type Store struct {
	db      *sql.DB
	queries *platformdb.Queries
	logger  zerolog.Logger
}

type desiredTenantSpec struct {
	subject   domain.Subject
	serviceID string
}

type tenantStore interface {
	ListTenantInstances(context.Context) ([]TenantInstance, error)
	RecordReconcileRun(context.Context, ReconcileRunInput) error
	MarkTenantReconciled(context.Context, ids.UUID, time.Time, string) error
	DeleteTenantInstance(context.Context, ids.UUID) error
}

type ControlPlaneLock struct {
	mu       sync.Mutex
	store    *Store
	holderID string
	released bool
}

const controlPlaneLeaseName = "mcp-control-plane"

const controlPlaneLeaseTTL = 2 * time.Minute

const controlPlaneLeaseRenewInterval = controlPlaneLeaseTTL / 3

var ErrSubjectServiceGrantNotFound = errors.New("subject service grant not found")
var ErrCatalogBuiltinMutation = errors.New("builtin service catalog entries cannot be changed through the admin API")
var ErrCatalogPathConflict = errors.New("service public path conflicts with an existing enabled service")

func NewStore(ctx context.Context, databaseURL string, logger zerolog.Logger) (*Store, error) {
	db, err := platformsqlite.Open(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, queries: platformdb.New(db), logger: logger}
	if err := store.Ping(ctx); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() {
	if s.db != nil {
		_ = s.db.Close()
	}
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

func (s *Store) AcquireControlPlaneLock(ctx context.Context) (*ControlPlaneLock, error) {
	holderID := ids.New().String()
	now := time.Now().UTC()
	holder, err := s.queries.AcquireControlPlaneLease(ctx, platformdb.AcquireControlPlaneLeaseParams{
		LeaseName: controlPlaneLeaseName,
		HolderID:  holderID,
		ExpiresAt: now.Add(controlPlaneLeaseTTL).UnixNano(),
		Now:       now.UnixNano(),
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("control-plane lease is already held")
		}
		return nil, fmt.Errorf("acquire control-plane lease: %w", err)
	}
	if holder != holderID {
		return nil, fmt.Errorf("control-plane lease is held by another instance")
	}
	return &ControlPlaneLock{store: s, holderID: holderID}, nil
}

func (l *ControlPlaneLock) Release(ctx context.Context) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	if l.store != nil {
		if err := l.store.queries.ReleaseControlPlaneLease(ctx, platformdb.ReleaseControlPlaneLeaseParams{LeaseName: controlPlaneLeaseName, HolderID: l.holderID}); err != nil {
			return fmt.Errorf("release control-plane lease: %w", err)
		}
	}
	l.released = true
	return nil
}

func (l *ControlPlaneLock) Held(ctx context.Context) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released || l.store == nil {
		return false
	}
	now := time.Now().UTC()
	holder, err := l.store.queries.AcquireControlPlaneLease(ctx, platformdb.AcquireControlPlaneLeaseParams{
		LeaseName: controlPlaneLeaseName,
		HolderID:  l.holderID,
		ExpiresAt: now.Add(controlPlaneLeaseTTL).UnixNano(),
		Now:       now.UnixNano(),
	})
	if err != nil || holder != l.holderID {
		l.released = true
		return false
	}
	return true
}

func (s *Store) RunMigrations(ctx context.Context) error {
	return platformsqlite.RunMigrations(ctx, s.db)
}

func (s *Store) SeedServiceCatalog(ctx context.Context) error {
	entries := catalog.DefaultCatalogV1()
	serviceIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		serviceIDs = append(serviceIDs, entry.ServiceID)
		secretContract, err := json.Marshal(entry.SecretContract)
		if err != nil {
			return fmt.Errorf("marshal secret contract for %s: %w", entry.ServiceID, err)
		}
		identityContext, err := json.Marshal(entry.IdentityContext.Normalized())
		if err != nil {
			return fmt.Errorf("marshal identity context for %s: %w", entry.ServiceID, err)
		}
		if err := s.queries.UpsertServiceCatalogEntry(ctx, platformdb.UpsertServiceCatalogEntryParams{
			ServiceID:              entry.ServiceID,
			DisplayName:            entry.DisplayName,
			UpstreamServiceName:    entry.UpstreamServiceName,
			TransportType:          string(entry.TransportType),
			InternalPort:           int64(entry.InternalPort),
			PublicPath:             entry.PublicPath,
			InternalUpstreamPath:   entry.InternalUpstreamPath,
			HealthPath:             entry.HealthPath,
			HealthProbeExpectation: entry.HealthProbeExpectation,
			ResourceProfile:        entry.ResourceProfile,
			PersistencePolicy:      entry.PersistencePolicy,
			AdapterRequirement:     string(entry.AdapterRequirement),
			SecretContract:         string(secretContract),
			IdentityContext:        string(identityContext),
			Enabled:                1,
			Source:                 "builtin",
		}); err != nil {
			return fmt.Errorf("seed service catalog entry %s: %w", entry.ServiceID, err)
		}
	}
	if len(serviceIDs) > 0 {
		if err := s.queries.DisableServiceCatalogEntriesNotIn(ctx, platformdb.DisableServiceCatalogEntriesNotInParams{ServiceIds: serviceIDs}); err != nil {
			return fmt.Errorf("disable stale service catalog entries: %w", err)
		}
	}
	return nil
}

func (s *Store) ListServiceCatalog(ctx context.Context) ([]ServiceCatalogAdminEntry, error) {
	records, err := s.queries.ListServiceCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("list service catalog: %w", err)
	}
	return convertServiceCatalogAdminEntries(records)
}

func (s *Store) GetServiceCatalogAdminEntry(ctx context.Context, serviceID string) (ServiceCatalogAdminEntry, error) {
	record, err := s.queries.GetServiceCatalogEntry(ctx, platformdb.GetServiceCatalogEntryParams{ServiceID: serviceID})
	if err != nil {
		return ServiceCatalogAdminEntry{}, fmt.Errorf("get service catalog entry %s: %w", serviceID, err)
	}
	return convertServiceCatalogAdminEntry(record)
}

func (s *Store) ListEnabledServiceIDs(ctx context.Context) ([]string, error) {
	serviceIDs, err := s.queries.ListEnabledServiceIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list enabled service IDs: %w", err)
	}
	return serviceIDs, nil
}

func (s *Store) GetEnabledServiceCatalogEntry(ctx context.Context, serviceID string) (catalog.ServiceCatalogEntry, error) {
	record, err := s.queries.GetEnabledServiceCatalogEntry(ctx, platformdb.GetEnabledServiceCatalogEntryParams{ServiceID: serviceID})
	if err != nil {
		return catalog.ServiceCatalogEntry{}, fmt.Errorf("get enabled service catalog entry %s: %w", serviceID, err)
	}
	return convertEnabledServiceCatalogRecord(record)
}

func (s *Store) UpsertAdminServiceCatalogEntry(ctx context.Context, entry catalog.ServiceCatalogEntry) error {
	secretContract, err := json.Marshal(entry.SecretContract)
	if err != nil {
		return fmt.Errorf("marshal secret contract for %s: %w", entry.ServiceID, err)
	}
	identityContext, err := json.Marshal(entry.IdentityContext.Normalized())
	if err != nil {
		return fmt.Errorf("marshal identity context for %s: %w", entry.ServiceID, err)
	}
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		if existing, err := q.GetServiceCatalogEntry(ctx, platformdb.GetServiceCatalogEntryParams{ServiceID: entry.ServiceID}); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("load existing service catalog entry %s: %w", entry.ServiceID, err)
		} else if err == nil && existing.Source == "builtin" {
			return ErrCatalogBuiltinMutation
		}
		if err := ensureNoPublicPathConflict(ctx, q, entry.ServiceID, entry.PublicPath); err != nil {
			return err
		}
		if err := q.UpsertServiceCatalogEntry(ctx, platformdb.UpsertServiceCatalogEntryParams{
			ServiceID:              entry.ServiceID,
			DisplayName:            entry.DisplayName,
			UpstreamServiceName:    entry.UpstreamServiceName,
			TransportType:          string(entry.TransportType),
			InternalPort:           int64(entry.InternalPort),
			PublicPath:             entry.PublicPath,
			InternalUpstreamPath:   entry.InternalUpstreamPath,
			HealthPath:             entry.HealthPath,
			HealthProbeExpectation: entry.HealthProbeExpectation,
			ResourceProfile:        entry.ResourceProfile,
			PersistencePolicy:      entry.PersistencePolicy,
			AdapterRequirement:     string(entry.AdapterRequirement),
			SecretContract:         string(secretContract),
			IdentityContext:        string(identityContext),
			Enabled:                1,
			Source:                 "admin_api",
		}); err != nil {
			return fmt.Errorf("upsert admin service catalog entry %s: %w", entry.ServiceID, err)
		}
		return nil
	})

}

func (s *Store) DisableServiceCatalogEntry(ctx context.Context, serviceID string) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		existing, err := q.GetServiceCatalogEntry(ctx, platformdb.GetServiceCatalogEntryParams{ServiceID: serviceID})
		if err != nil {
			return fmt.Errorf("load existing service catalog entry %s: %w", serviceID, err)
		}
		if existing.Source == "builtin" {
			return ErrCatalogBuiltinMutation
		}
		if err := q.DisableServiceCatalogEntry(ctx, platformdb.DisableServiceCatalogEntryParams{ServiceID: serviceID}); err != nil {
			return fmt.Errorf("disable service catalog entry %s: %w", serviceID, err)
		}
		return nil
	})
}

func (s *Store) UpsertSubject(ctx context.Context, subject domain.Subject) error {
	if err := s.queries.UpsertSubject(ctx, platformdb.UpsertSubjectParams{
		SubjectSub:          subject.Sub,
		SubjectKey:          subject.SubjectKey,
		PreferredUsername:   sqlNullString(subject.PreferredUsername),
		Email:               sqlNullString(subject.Email),
		DisplayName:         sqlNullString(subject.DisplayName),
		AccountBindingID:    sqlNullString(subject.AccountBindingID),
		AccountBindingClaim: sqlNullString(subject.AccountBindingClaim),
	}); err != nil {
		return fmt.Errorf("upsert subject %s: %w", subject.Sub, err)
	}
	return nil
}

func (s *Store) ReplaceSubjectGrants(ctx context.Context, subjectSub string, grants []ServiceGrant) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		if err := q.DeleteSubjectGrants(ctx, platformdb.DeleteSubjectGrantsParams{SubjectSub: subjectSub}); err != nil {
			return fmt.Errorf("delete existing grants for %s: %w", subjectSub, err)
		}
		if err := q.DeleteSubjectGrantSources(ctx, platformdb.DeleteSubjectGrantSourcesParams{SubjectSub: subjectSub}); err != nil {
			return fmt.Errorf("delete existing grant sources for %s: %w", subjectSub, err)
		}
		if err := insertGrants(ctx, q, subjectSub, grants); err != nil {
			return err
		}
		return rebuildEffectiveServiceGrants(ctx, q)
	})
}

func (s *Store) ListSubjectServiceGrants(ctx context.Context, subjectSub string) ([]ServiceGrant, error) {
	rows, err := s.queries.ListSubjectServiceGrants(ctx, platformdb.ListSubjectServiceGrantsParams{SubjectSub: subjectSub})
	if err != nil {
		return nil, fmt.Errorf("list service grants for %s: %w", subjectSub, err)
	}
	grants := make([]ServiceGrant, 0, len(rows))
	for _, row := range rows {
		grant := ServiceGrant{
			SubjectSub:  row.SubjectSub,
			ServiceID:   row.ServiceID,
			SourceGroup: row.SourceGroup,
		}
		grantedAt, err := parseSQLiteTime(row.GrantedAt)
		if err != nil {
			return nil, fmt.Errorf("parse grant granted_at: %w", err)
		}
		lastSyncedAt, err := parseSQLiteTime(row.LastSyncedAt)
		if err != nil {
			return nil, fmt.Errorf("parse grant last_synced_at: %w", err)
		}
		grant.GrantedAt = grantedAt
		grant.LastSyncedAt = lastSyncedAt
		grants = append(grants, grant)
	}
	return grants, nil
}

func (s *Store) UpsertManualServiceGrant(ctx context.Context, subject domain.Subject, serviceID string) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		if _, err := q.GetEnabledServiceCatalogEntry(ctx, platformdb.GetEnabledServiceCatalogEntryParams{ServiceID: serviceID}); err != nil {
			return fmt.Errorf("load enabled service %s: %w", serviceID, err)
		}
		if subject.SubjectKey == "" {
			subject.SubjectKey = domain.DeriveSubjectKey(subject.Sub)
		}
		if err := q.UpsertSubjectPreservingMetadata(ctx, platformdb.UpsertSubjectPreservingMetadataParams{
			SubjectSub:          subject.Sub,
			SubjectKey:          subject.SubjectKey,
			PreferredUsername:   sqlNullString(subject.PreferredUsername),
			Email:               sqlNullString(subject.Email),
			DisplayName:         sqlNullString(subject.DisplayName),
			AccountBindingID:    sqlNullString(subject.AccountBindingID),
			AccountBindingClaim: sqlNullString(subject.AccountBindingClaim),
		}); err != nil {
			return fmt.Errorf("upsert subject %s for manual grant: %w", subject.Sub, err)
		}
		if err := q.UpsertManualServiceGrantSource(ctx, platformdb.UpsertManualServiceGrantSourceParams{SubjectSub: subject.Sub, ServiceID: serviceID}); err != nil {
			return fmt.Errorf("upsert manual grant %s/%s: %w", subject.Sub, serviceID, err)
		}
		return rebuildEffectiveServiceGrants(ctx, q)
	})
}

func (s *Store) DeleteManualServiceGrant(ctx context.Context, subjectSub string, serviceID string) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		if err := q.DeleteManualServiceGrantSource(ctx, platformdb.DeleteManualServiceGrantSourceParams{SubjectSub: subjectSub, ServiceID: serviceID}); err != nil {
			return fmt.Errorf("delete manual service grant %s/%s: %w", subjectSub, serviceID, err)
		}
		return rebuildEffectiveServiceGrants(ctx, q)
	})
}

func (s *Store) SubjectServiceGranted(ctx context.Context, subjectSub string, serviceID string) (bool, error) {
	grantCount, err := s.queries.CountSubjectServiceGrant(ctx, platformdb.CountSubjectServiceGrantParams{SubjectSub: subjectSub, ServiceID: serviceID})
	if err != nil {
		return false, fmt.Errorf("count service grant %s/%s: %w", subjectSub, serviceID, err)
	}
	return grantCount > 0, nil
}

func (s *Store) UpsertStaticTenantUpstream(ctx context.Context, subject domain.Subject, serviceID string, upstreamURL string, verifiedAt time.Time) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		if _, err := q.GetEnabledServiceCatalogEntry(ctx, platformdb.GetEnabledServiceCatalogEntryParams{ServiceID: serviceID}); err != nil {
			return fmt.Errorf("load enabled service %s: %w", serviceID, err)
		}
		if subject.SubjectKey == "" {
			subject.SubjectKey = domain.DeriveSubjectKey(subject.Sub)
		}
		if err := q.UpsertSubjectPreservingMetadata(ctx, platformdb.UpsertSubjectPreservingMetadataParams{
			SubjectSub:          subject.Sub,
			SubjectKey:          subject.SubjectKey,
			PreferredUsername:   sqlNullString(subject.PreferredUsername),
			Email:               sqlNullString(subject.Email),
			DisplayName:         sqlNullString(subject.DisplayName),
			AccountBindingID:    sqlNullString(subject.AccountBindingID),
			AccountBindingClaim: sqlNullString(subject.AccountBindingClaim),
		}); err != nil {
			return fmt.Errorf("upsert subject %s for static upstream: %w", subject.Sub, err)
		}
		persistedSubject, err := q.GetSubject(ctx, platformdb.GetSubjectParams{SubjectSub: subject.Sub})
		if err != nil {
			return fmt.Errorf("load subject %s for static upstream: %w", subject.Sub, err)
		}
		subject.SubjectKey = persistedSubject.SubjectKey
		grantCount, err := q.CountSubjectServiceGrant(ctx, platformdb.CountSubjectServiceGrantParams{SubjectSub: subject.Sub, ServiceID: serviceID})
		if err != nil {
			return fmt.Errorf("count service grant %s/%s: %w", subject.Sub, serviceID, err)
		}
		if grantCount == 0 {
			return ErrSubjectServiceGrantNotFound
		}
		tenantInstanceName := domain.BuildTenantInstanceName(serviceID, subject.SubjectKey)
		if err := q.UpsertStaticTenantUpstream(ctx, platformdb.UpsertStaticTenantUpstreamParams{
			TenantID:           ids.New().Bytes(),
			SubjectSub:         subject.Sub,
			ServiceID:          serviceID,
			SubjectKey:         subject.SubjectKey,
			TenantInstanceName: tenantInstanceName,
			InternalDnsName:    tenantInstanceName,
			UpstreamUrl:        sql.NullString{String: upstreamURL, Valid: true},
			LastHealthyAt:      sql.NullString{String: formatSQLiteTime(verifiedAt), Valid: true},
		}); err != nil {
			return fmt.Errorf("upsert static upstream %s/%s: %w", subject.Sub, serviceID, err)
		}
		return nil
	})
}

func (s *Store) SyncSubjectGrantSnapshot(ctx context.Context, subjects []domain.Subject, grants []ServiceGrant) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		subjectsBySub := make(map[string]domain.Subject, len(subjects))
		for _, subject := range subjects {
			subjectsBySub[subject.Sub] = subject
		}
		subjectSubs := mapsSortedKeys(subjectsBySub)
		for _, subjectSub := range subjectSubs {
			subject := subjectsBySub[subjectSub]
			if err := q.UpsertSubject(ctx, platformdb.UpsertSubjectParams{
				SubjectSub:          subject.Sub,
				SubjectKey:          subject.SubjectKey,
				PreferredUsername:   sqlNullString(subject.PreferredUsername),
				Email:               sqlNullString(subject.Email),
				DisplayName:         sqlNullString(subject.DisplayName),
				AccountBindingID:    sqlNullString(subject.AccountBindingID),
				AccountBindingClaim: sqlNullString(subject.AccountBindingClaim),
			}); err != nil {
				return fmt.Errorf("upsert subject %s during snapshot sync: %w", subject.Sub, err)
			}
		}
		if len(subjectSubs) == 0 {
			if err := q.DeleteAllServiceGrants(ctx); err != nil {
				return fmt.Errorf("clear service grants for empty snapshot: %w", err)
			}
		} else if err := q.DeleteStaleServiceGrants(ctx, platformdb.DeleteStaleServiceGrantsParams{SubjectSubs: subjectSubs}); err != nil {
			return fmt.Errorf("delete stale service grants: %w", err)
		}
		grantsBySubject := make(map[string][]ServiceGrant)
		for _, grant := range grants {
			grantsBySubject[grant.SubjectSub] = append(grantsBySubject[grant.SubjectSub], grant)
		}
		for _, subjectSub := range subjectSubs {
			if err := q.DeleteSubjectSyncedGrantSources(ctx, platformdb.DeleteSubjectSyncedGrantSourcesParams{SubjectSub: subjectSub}); err != nil {
				return fmt.Errorf("delete existing synced grants for %s during snapshot sync: %w", subjectSub, err)
			}
			if err := insertGrants(ctx, q, subjectSub, grantsBySubject[subjectSub]); err != nil {
				return err
			}
		}
		return rebuildEffectiveServiceGrants(ctx, q)
	})
}

func (s *Store) ReconcileDesiredTenants(ctx context.Context) error {
	return s.withTx(ctx, func(q *platformdb.Queries) error {
		desiredSpecs, err := loadDesiredTenantSpecs(ctx, q)
		if err != nil {
			return err
		}
		currentTenants, err := loadTenantInstances(ctx, q)
		if err != nil {
			return err
		}
		for _, key := range mapsSortedKeys(desiredSpecs) {
			spec := desiredSpecs[key]
			tenant, ok := currentTenants[key]
			if !ok {
				if err := insertTenantInstance(ctx, q, spec); err != nil {
					return err
				}
				continue
			}
			if err := enableTenantInstance(ctx, q, tenant, spec); err != nil {
				return err
			}
		}
		for _, key := range mapsSortedKeys(currentTenants) {
			tenant := currentTenants[key]
			if _, ok := desiredSpecs[key]; ok || tenant.DesiredState == domain.TenantDesiredStateDeleted {
				continue
			}
			if err := q.MarkTenantDesiredDeleted(ctx, platformdb.MarkTenantDesiredDeletedParams{TenantID: tenant.TenantID.Bytes(), DesiredState: string(domain.TenantDesiredStateDeleted)}); err != nil {
				return fmt.Errorf("mark tenant %s as deleted: %w", tenant.TenantID, err)
			}
		}
		return nil
	})
}

func (s *Store) ListTenantInstances(ctx context.Context) ([]TenantInstance, error) {
	records, err := s.queries.ListTenantInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenant instances: %w", err)
	}
	return convertTenantInstances(records)
}

func (s *Store) RecordReconcileRun(ctx context.Context, input ReconcileRunInput) error {
	detailsJSON, err := json.Marshal(input.Details)
	if err != nil {
		return fmt.Errorf("marshal reconcile details: %w", err)
	}
	if err := s.queries.InsertReconcileRun(ctx, platformdb.InsertReconcileRunParams{
		RunID:         ids.New().Bytes(),
		TenantID:      input.TenantID.Bytes(),
		DesiredState:  string(input.DesiredState),
		ObservedState: sql.NullString{String: string(input.ObservedState), Valid: input.ObservedState != ""},
		Action:        input.Action,
		Status:        input.Status,
		Details:       string(detailsJSON),
		StartedAt:     formatSQLiteTime(input.StartedAt),
		FinishedAt:    sqlNullTime(input.FinishedAt),
	}); err != nil {
		return fmt.Errorf("insert reconcile run for tenant %s: %w", input.TenantID, err)
	}
	return nil
}

func (s *Store) MarkTenantReconciled(ctx context.Context, tenantID ids.UUID, reconciledAt time.Time, lastError string) error {
	if err := s.queries.MarkTenantReconciled(ctx, platformdb.MarkTenantReconciledParams{TenantID: tenantID.Bytes(), LastReconciledAt: sqlNullTime(reconciledAt), LastError: lastError}); err != nil {
		return fmt.Errorf("mark tenant %s reconciled: %w", tenantID, err)
	}
	return nil
}

func (s *Store) UpdateTenantRuntimeStatus(ctx context.Context, update TenantRuntimeUpdate) error {
	var lastHealthyAt any
	if update.LastHealthyAt != nil {
		lastHealthyAt = formatSQLiteTime(*update.LastHealthyAt)
	}
	if err := s.queries.UpdateTenantRuntimeStatus(ctx, platformdb.UpdateTenantRuntimeStatusParams{
		TenantID:               update.TenantID.Bytes(),
		RuntimeState:           string(update.RuntimeState),
		CoolifyResourceID:      update.CoolifyResourceID,
		CoolifyApplicationID:   update.CoolifyApplicationID,
		UpstreamUrl:            update.UpstreamURL,
		LastHealthyAt:          lastHealthyAt,
		ClearRuntimeReferences: update.ClearRuntimeReferences,
		LastError:              update.LastError,
	}); err != nil {
		return fmt.Errorf("update tenant runtime status for %s: %w", update.TenantID, err)
	}
	return nil
}

func (s *Store) DeleteTenantInstance(ctx context.Context, tenantID ids.UUID) error {
	if err := s.queries.DeleteTenantInstance(ctx, platformdb.DeleteTenantInstanceParams{TenantID: tenantID.Bytes()}); err != nil {
		return fmt.Errorf("delete tenant instance %s: %w", tenantID, err)
	}
	return nil
}

func (s *Store) withTx(ctx context.Context, fn func(*platformdb.Queries) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(s.queries.WithTx(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func insertGrants(ctx context.Context, q *platformdb.Queries, subjectSub string, grants []ServiceGrant) error {
	for _, grant := range grants {
		grantedAt := grant.GrantedAt
		if grantedAt.IsZero() {
			grantedAt = time.Now().UTC()
		}
		lastSyncedAt := grant.LastSyncedAt
		if lastSyncedAt.IsZero() {
			lastSyncedAt = time.Now().UTC()
		}
		if err := q.InsertServiceGrantSource(ctx, platformdb.InsertServiceGrantSourceParams{SubjectSub: subjectSub, ServiceID: grant.ServiceID, SourceGroup: grant.SourceGroup, GrantedAt: formatSQLiteTime(grantedAt), LastSyncedAt: formatSQLiteTime(lastSyncedAt)}); err != nil {
			return fmt.Errorf("insert grant %s/%s: %w", subjectSub, grant.ServiceID, err)
		}
	}
	return nil
}

func rebuildEffectiveServiceGrants(ctx context.Context, q *platformdb.Queries) error {
	if err := q.RebuildEffectiveServiceGrants(ctx); err != nil {
		return fmt.Errorf("clear effective service grants: %w", err)
	}
	if err := q.InsertEffectiveServiceGrantsFromSources(ctx); err != nil {
		return fmt.Errorf("insert effective service grants: %w", err)
	}
	return nil
}

func loadDesiredTenantSpecs(ctx context.Context, q *platformdb.Queries) (map[string]desiredTenantSpec, error) {
	rows, err := q.ListDesiredTenantSpecs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load desired tenant specs: %w", err)
	}
	desiredSpecs := make(map[string]desiredTenantSpec, len(rows))
	for _, row := range rows {
		spec := desiredTenantSpec{subject: domain.Subject{Sub: row.SubjectSub, SubjectKey: row.SubjectKey, PreferredUsername: row.PreferredUsername, Email: row.Email, DisplayName: row.DisplayName, AccountBindingID: row.AccountBindingID, AccountBindingClaim: row.AccountBindingClaim}, serviceID: row.ServiceID}
		desiredSpecs[tenantMapKey(row.SubjectSub, row.ServiceID)] = spec
	}
	return desiredSpecs, nil
}

func loadTenantInstances(ctx context.Context, q *platformdb.Queries) (map[string]TenantInstance, error) {
	records, err := q.ListTenantInstances(ctx)
	if err != nil {
		return nil, fmt.Errorf("load current tenant instances: %w", err)
	}
	tenants, err := convertTenantInstances(records)
	if err != nil {
		return nil, err
	}
	tenantMap := make(map[string]TenantInstance, len(tenants))
	for _, tenant := range tenants {
		tenantMap[tenantMapKey(tenant.SubjectSub, tenant.ServiceID)] = tenant
	}
	return tenantMap, nil
}

func insertTenantInstance(ctx context.Context, q *platformdb.Queries, spec desiredTenantSpec) error {
	tenantInstanceName := domain.BuildTenantInstanceName(spec.serviceID, spec.subject.SubjectKey)
	if err := q.InsertTenantInstance(ctx, platformdb.InsertTenantInstanceParams{
		TenantID:           ids.New().Bytes(),
		SubjectSub:         spec.subject.Sub,
		ServiceID:          spec.serviceID,
		SubjectKey:         spec.subject.SubjectKey,
		TenantInstanceName: tenantInstanceName,
		InternalDnsName:    tenantInstanceName,
		DesiredState:       string(domain.TenantDesiredStateEnabled),
		RuntimeState:       string(domain.TenantRuntimeStateProvisioning),
	}); err != nil {
		return fmt.Errorf("insert tenant instance %s/%s: %w", spec.subject.Sub, spec.serviceID, err)
	}
	return nil
}

func enableTenantInstance(ctx context.Context, q *platformdb.Queries, tenant TenantInstance, spec desiredTenantSpec) error {
	tenantInstanceName := domain.BuildTenantInstanceName(spec.serviceID, spec.subject.SubjectKey)
	runtimeState := tenant.RuntimeState
	lastError := tenant.LastError
	if tenant.SubjectKey != spec.subject.SubjectKey || tenant.TenantInstanceName != tenantInstanceName || tenant.InternalDNSName != tenantInstanceName {
		runtimeState = domain.TenantRuntimeStateDegraded
		lastError = "tenant identity drift detected; reprovision required"
	}
	if err := q.EnableTenantInstance(ctx, platformdb.EnableTenantInstanceParams{
		TenantID:           tenant.TenantID.Bytes(),
		SubjectKey:         spec.subject.SubjectKey,
		TenantInstanceName: tenantInstanceName,
		InternalDnsName:    tenantInstanceName,
		DesiredState:       string(domain.TenantDesiredStateEnabled),
		RuntimeState:       string(runtimeState),
		LastError:          lastError,
	}); err != nil {
		return fmt.Errorf("enable tenant instance %s: %w", tenant.TenantID, err)
	}
	return nil
}

func ensureNoPublicPathConflict(ctx context.Context, q *platformdb.Queries, serviceID string, publicPath string) error {
	records, err := q.ListServiceCatalog(ctx)
	if err != nil {
		return fmt.Errorf("list service catalog for path conflict check: %w", err)
	}
	publicPath = strings.TrimRight(publicPath, "/")
	for _, record := range records {
		if record.ServiceID == serviceID || record.Enabled == 0 {
			continue
		}
		existingPath := strings.TrimRight(record.PublicPath, "/")
		if publicPath == existingPath || strings.HasPrefix(publicPath, existingPath+"/") || strings.HasPrefix(existingPath, publicPath+"/") {
			return fmt.Errorf("%w: %s overlaps %s", ErrCatalogPathConflict, publicPath, existingPath)
		}
	}
	return nil
}

func convertServiceCatalogAdminEntries(records []platformdb.ListServiceCatalogRow) ([]ServiceCatalogAdminEntry, error) {
	entries := make([]ServiceCatalogAdminEntry, 0, len(records))
	for _, record := range records {
		entry := ServiceCatalogAdminEntry{
			ServiceID:              record.ServiceID,
			DisplayName:            record.DisplayName,
			UpstreamServiceName:    record.UpstreamServiceName,
			TransportType:          catalog.TransportType(record.TransportType),
			InternalPort:           int(record.InternalPort),
			PublicPath:             record.PublicPath,
			InternalUpstreamPath:   record.InternalUpstreamPath,
			HealthPath:             record.HealthPath,
			HealthProbeExpectation: record.HealthProbeExpectation,
			ResourceProfile:        record.ResourceProfile,
			PersistencePolicy:      record.PersistencePolicy,
			AdapterRequirement:     catalog.AdapterRequirement(record.AdapterRequirement),
			IdentityContext:        catalog.IdentityContextConfig{},
			Enabled:                record.Enabled != 0,
			Source:                 record.Source,
		}
		if err := json.Unmarshal([]byte(record.SecretContract), &entry.SecretContract); err != nil {
			return nil, fmt.Errorf("decode secret contract for %s: %w", entry.ServiceID, err)
		}
		if err := json.Unmarshal([]byte(record.IdentityContext), &entry.IdentityContext); err != nil {
			return nil, fmt.Errorf("decode identity context for %s: %w", entry.ServiceID, err)
		}
		entry.IdentityContext = entry.IdentityContext.Normalized()
		entries = append(entries, entry)
	}
	return entries, nil
}

func convertServiceCatalogAdminEntry(record platformdb.GetServiceCatalogEntryRow) (ServiceCatalogAdminEntry, error) {
	entry := ServiceCatalogAdminEntry{
		ServiceID:              record.ServiceID,
		DisplayName:            record.DisplayName,
		UpstreamServiceName:    record.UpstreamServiceName,
		TransportType:          catalog.TransportType(record.TransportType),
		InternalPort:           int(record.InternalPort),
		PublicPath:             record.PublicPath,
		InternalUpstreamPath:   record.InternalUpstreamPath,
		HealthPath:             record.HealthPath,
		HealthProbeExpectation: record.HealthProbeExpectation,
		ResourceProfile:        record.ResourceProfile,
		PersistencePolicy:      record.PersistencePolicy,
		AdapterRequirement:     catalog.AdapterRequirement(record.AdapterRequirement),
		IdentityContext:        catalog.IdentityContextConfig{},
		Enabled:                record.Enabled != 0,
		Source:                 record.Source,
	}
	if err := json.Unmarshal([]byte(record.SecretContract), &entry.SecretContract); err != nil {
		return ServiceCatalogAdminEntry{}, fmt.Errorf("decode secret contract for %s: %w", entry.ServiceID, err)
	}
	if err := json.Unmarshal([]byte(record.IdentityContext), &entry.IdentityContext); err != nil {
		return ServiceCatalogAdminEntry{}, fmt.Errorf("decode identity context for %s: %w", entry.ServiceID, err)
	}
	entry.IdentityContext = entry.IdentityContext.Normalized()
	return entry, nil
}

func convertEnabledServiceCatalogRecord(record platformdb.GetEnabledServiceCatalogEntryRow) (catalog.ServiceCatalogEntry, error) {
	entry := catalog.ServiceCatalogEntry{
		ServiceID:              record.ServiceID,
		DisplayName:            record.DisplayName,
		UpstreamServiceName:    record.UpstreamServiceName,
		TransportType:          catalog.TransportType(record.TransportType),
		InternalPort:           int(record.InternalPort),
		PublicPath:             record.PublicPath,
		InternalUpstreamPath:   record.InternalUpstreamPath,
		HealthPath:             record.HealthPath,
		HealthProbeExpectation: record.HealthProbeExpectation,
		ResourceProfile:        record.ResourceProfile,
		PersistencePolicy:      record.PersistencePolicy,
		AdapterRequirement:     catalog.AdapterRequirement(record.AdapterRequirement),
		IdentityContext:        catalog.IdentityContextConfig{},
	}
	if err := json.Unmarshal([]byte(record.SecretContract), &entry.SecretContract); err != nil {
		return catalog.ServiceCatalogEntry{}, fmt.Errorf("decode secret contract for %s: %w", entry.ServiceID, err)
	}
	if err := json.Unmarshal([]byte(record.IdentityContext), &entry.IdentityContext); err != nil {
		return catalog.ServiceCatalogEntry{}, fmt.Errorf("decode identity context for %s: %w", entry.ServiceID, err)
	}
	entry.IdentityContext = entry.IdentityContext.Normalized()
	return entry, nil
}

func convertTenantInstances(records []platformdb.TenantInstance) ([]TenantInstance, error) {
	tenants := make([]TenantInstance, 0, len(records))
	for _, record := range records {
		tenantID, err := ids.ParseBytes(record.TenantID)
		if err != nil {
			return nil, fmt.Errorf("parse tenant id: %w", err)
		}
		createdAt, err := parseSQLiteTime(record.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse tenant created_at: %w", err)
		}
		updatedAt, err := parseSQLiteTime(record.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("parse tenant updated_at: %w", err)
		}
		tenant := TenantInstance{
			TenantID:             tenantID,
			SubjectSub:           record.SubjectSub,
			ServiceID:            record.ServiceID,
			SubjectKey:           record.SubjectKey,
			TenantInstanceName:   record.TenantInstanceName,
			InternalDNSName:      record.InternalDnsName,
			DesiredState:         domain.TenantDesiredState(record.DesiredState),
			RuntimeState:         domain.TenantRuntimeState(record.RuntimeState),
			CoolifyResourceID:    record.CoolifyResourceID.String,
			CoolifyApplicationID: record.CoolifyApplicationID.String,
			UpstreamURL:          record.UpstreamUrl.String,
			SecretVersion:        record.SecretVersion.String,
			LastError:            record.LastError.String,
			Metadata:             json.RawMessage(record.Metadata),
			CreatedAt:            createdAt,
			UpdatedAt:            updatedAt,
		}
		if value, ok, err := parseSQLiteNullTime(record.LastHealthyAt); err != nil {
			return nil, fmt.Errorf("parse tenant last_healthy_at: %w", err)
		} else if ok {
			tenant.LastHealthyAt = &value
		}
		if value, ok, err := parseSQLiteNullTime(record.LastReconciledAt); err != nil {
			return nil, fmt.Errorf("parse tenant last_reconciled_at: %w", err)
		} else if ok {
			tenant.LastReconciledAt = &value
		}
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

func tenantMapKey(subjectSub string, serviceID string) string { return subjectSub + "::" + serviceID }

func mapsSortedKeys[T any](input map[string]T) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func sqlNullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func sqlNullTime(value time.Time) sql.NullString {
	if value.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: formatSQLiteTime(value), Valid: true}
}

func formatSQLiteTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func parseSQLiteNullTime(value sql.NullString) (time.Time, bool, error) {
	if !value.Valid || value.String == "" {
		return time.Time{}, false, nil
	}
	parsed, err := parseSQLiteTime(value.String)
	return parsed, err == nil, err
}

func parseSQLiteTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC)
}
