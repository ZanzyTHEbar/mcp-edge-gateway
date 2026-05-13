package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
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

func (s *Store) ListServiceCatalog(ctx context.Context) ([]catalog.ServiceCatalogEntry, error) {
	records, err := s.queries.ListServiceCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("list service catalog: %w", err)
	}
	return convertServiceCatalog(records)
}

func (s *Store) UpsertAdminServiceCatalogEntry(ctx context.Context, entry catalog.ServiceCatalogEntry) error {
	secretContract, err := json.Marshal(entry.SecretContract)
	if err != nil {
		return fmt.Errorf("marshal secret contract for %s: %w", entry.ServiceID, err)
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
		Enabled:                1,
		Source:                 "admin_api",
	}); err != nil {
		return fmt.Errorf("upsert admin service catalog entry %s: %w", entry.ServiceID, err)
	}
	return nil
}

func (s *Store) DisableServiceCatalogEntry(ctx context.Context, serviceID string) error {
	if err := s.queries.DisableServiceCatalogEntry(ctx, platformdb.DisableServiceCatalogEntryParams{ServiceID: serviceID}); err != nil {
		return fmt.Errorf("disable service catalog entry %s: %w", serviceID, err)
	}
	return nil
}

func (s *Store) UpsertSubject(ctx context.Context, subject domain.Subject) error {
	if err := s.queries.UpsertSubject(ctx, platformdb.UpsertSubjectParams{
		SubjectSub:        subject.Sub,
		SubjectKey:        subject.SubjectKey,
		PreferredUsername: sqlNullString(subject.PreferredUsername),
		Email:             sqlNullString(subject.Email),
		DisplayName:       sqlNullString(subject.DisplayName),
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
		return insertGrants(ctx, q, subjectSub, grants)
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
				SubjectSub:        subject.Sub,
				SubjectKey:        subject.SubjectKey,
				PreferredUsername: sqlNullString(subject.PreferredUsername),
				Email:             sqlNullString(subject.Email),
				DisplayName:       sqlNullString(subject.DisplayName),
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
			if err := q.DeleteSubjectGrants(ctx, platformdb.DeleteSubjectGrantsParams{SubjectSub: subjectSub}); err != nil {
				return fmt.Errorf("delete existing grants for %s during snapshot sync: %w", subjectSub, err)
			}
			if err := insertGrants(ctx, q, subjectSub, grantsBySubject[subjectSub]); err != nil {
				return err
			}
		}
		return nil
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
		if err := q.InsertServiceGrant(ctx, platformdb.InsertServiceGrantParams{SubjectSub: subjectSub, ServiceID: grant.ServiceID, SourceGroup: grant.SourceGroup, GrantedAt: formatSQLiteTime(grantedAt), LastSyncedAt: formatSQLiteTime(lastSyncedAt)}); err != nil {
			return fmt.Errorf("insert grant %s/%s: %w", subjectSub, grant.ServiceID, err)
		}
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
		spec := desiredTenantSpec{subject: domain.Subject{Sub: row.SubjectSub, SubjectKey: row.SubjectKey, PreferredUsername: row.PreferredUsername, Email: row.Email, DisplayName: row.DisplayName}, serviceID: row.ServiceID}
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

func convertServiceCatalog(records []platformdb.ListServiceCatalogRow) ([]catalog.ServiceCatalogEntry, error) {
	entries := make([]catalog.ServiceCatalogEntry, 0, len(records))
	for _, record := range records {
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
		}
		if err := json.Unmarshal([]byte(record.SecretContract), &entry.SecretContract); err != nil {
			return nil, fmt.Errorf("decode secret contract for %s: %w", entry.ServiceID, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
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
