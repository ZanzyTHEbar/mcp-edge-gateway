package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"time"

	dbmigrations "dragonserver/mcp-platform/db/migrations"
	"dragonserver/mcp-platform/internal/catalog"
	"dragonserver/mcp-platform/internal/domain"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

type Store struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
}

type TenantRuntimeUpdate struct {
	TenantID             uuid.UUID
	RuntimeState         domain.TenantRuntimeState
	CoolifyResourceID    string
	CoolifyApplicationID string
	UpstreamURL          string
	LastHealthyAt        *time.Time
	LastError            string
}

type desiredTenantSpec struct {
	subject   domain.Subject
	serviceID string
}

type tenantStore interface {
	ListTenantInstances(context.Context) ([]TenantInstance, error)
	RecordReconcileRun(context.Context, ReconcileRunInput) error
	MarkTenantReconciled(context.Context, uuid.UUID, time.Time, string) error
	DeleteTenantInstance(context.Context, uuid.UUID) error
}

const (
	migrationLockClassID  int32 = 0x6d6370
	migrationLockObjectID int32 = 1
)

func NewStore(ctx context.Context, databaseURL string, logger zerolog.Logger) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	store := &Store{
		pool:   pool,
		logger: logger,
	}
	if err := store.Ping(ctx); err != nil {
		store.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

func (s *Store) RunMigrations(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer rollbackQuietly(ctx, tx)

	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock($1, $2)`, migrationLockClassID, migrationLockObjectID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		create table if not exists schema_migrations (
			name text primary key,
			applied_at timestamptz not null default now()
		)
	`); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}

	applied := make(map[string]struct{})
	rows, err := tx.Query(ctx, `select name from schema_migrations`)
	if err != nil {
		return fmt.Errorf("list applied migrations: %w", err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("scan applied migration: %w", err)
		}
		applied[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate applied migrations: %w", err)
	}
	rows.Close()

	entries, err := fs.ReadDir(dbmigrations.Files, ".")
	if err != nil {
		return fmt.Errorf("read embedded migrations: %w", err)
	}

	migrationNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		migrationNames = append(migrationNames, entry.Name())
	}
	slices.Sort(migrationNames)

	for _, migrationName := range migrationNames {
		if _, ok := applied[migrationName]; ok {
			continue
		}

		sqlBytes, err := fs.ReadFile(dbmigrations.Files, migrationName)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", migrationName, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("execute migration %s: %w", migrationName, err)
		}
		if _, err := tx.Exec(ctx, `insert into schema_migrations (name) values ($1)`, migrationName); err != nil {
			return fmt.Errorf("record migration %s: %w", migrationName, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func (s *Store) SeedServiceCatalog(ctx context.Context) error {
	const upsertQuery = `
		insert into service_catalog (
			service_id,
			display_name,
			upstream_service_name,
			transport_type,
			internal_port,
			public_path,
			internal_upstream_path,
			health_path,
			health_probe_expectation,
			resource_profile,
			persistence_policy,
			adapter_requirement,
			secret_contract,
			enabled
		) values (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
		on conflict (service_id) do update set
			display_name = excluded.display_name,
			upstream_service_name = excluded.upstream_service_name,
			transport_type = excluded.transport_type,
			internal_port = excluded.internal_port,
			public_path = excluded.public_path,
			internal_upstream_path = excluded.internal_upstream_path,
			health_path = excluded.health_path,
			health_probe_expectation = excluded.health_probe_expectation,
			resource_profile = excluded.resource_profile,
			persistence_policy = excluded.persistence_policy,
			adapter_requirement = excluded.adapter_requirement,
			secret_contract = excluded.secret_contract,
			updated_at = now()
	`

	for _, entry := range catalog.DefaultCatalogV1() {
		secretContract, err := json.Marshal(entry.SecretContract)
		if err != nil {
			return fmt.Errorf("marshal secret contract for %s: %w", entry.ServiceID, err)
		}

		if _, err := s.pool.Exec(
			ctx,
			upsertQuery,
			entry.ServiceID,
			entry.DisplayName,
			entry.UpstreamServiceName,
			entry.TransportType,
			entry.InternalPort,
			entry.PublicPath,
			entry.InternalUpstreamPath,
			entry.HealthPath,
			entry.HealthProbeExpectation,
			entry.ResourceProfile,
			entry.PersistencePolicy,
			entry.AdapterRequirement,
			secretContract,
			true,
		); err != nil {
			return fmt.Errorf("seed service catalog entry %s: %w", entry.ServiceID, err)
		}
	}

	return nil
}

func (s *Store) UpsertSubject(ctx context.Context, subject domain.Subject) error {
	if _, err := s.pool.Exec(
		ctx,
		`
			insert into subjects (
				subject_sub,
				subject_key,
				preferred_username,
				email,
				display_name,
				last_synced_at
			) values ($1, $2, $3, $4, $5, now())
			on conflict (subject_sub) do update set
				subject_key = excluded.subject_key,
				preferred_username = excluded.preferred_username,
				email = excluded.email,
				display_name = excluded.display_name,
				last_synced_at = now(),
				updated_at = now()
		`,
		subject.Sub,
		subject.SubjectKey,
		subject.PreferredUsername,
		subject.Email,
		subject.DisplayName,
	); err != nil {
		return fmt.Errorf("upsert subject %s: %w", subject.Sub, err)
	}
	return nil
}

func (s *Store) ReplaceSubjectGrants(ctx context.Context, subjectSub string, grants []ServiceGrant) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin replace grants transaction: %w", err)
	}
	defer rollbackQuietly(ctx, tx)

	if _, err := tx.Exec(ctx, `delete from service_grants where subject_sub = $1`, subjectSub); err != nil {
		return fmt.Errorf("delete existing grants for %s: %w", subjectSub, err)
	}

	for _, grant := range grants {
		grantedAt := grant.GrantedAt
		if grantedAt.IsZero() {
			grantedAt = time.Now().UTC()
		}
		lastSyncedAt := grant.LastSyncedAt
		if lastSyncedAt.IsZero() {
			lastSyncedAt = time.Now().UTC()
		}

		if _, err := tx.Exec(
			ctx,
			`
				insert into service_grants (
					subject_sub,
					service_id,
					source_group,
					granted_at,
					last_synced_at
				) values ($1, $2, $3, $4, $5)
			`,
			subjectSub,
			grant.ServiceID,
			grant.SourceGroup,
			grantedAt,
			lastSyncedAt,
		); err != nil {
			return fmt.Errorf("insert grant %s/%s: %w", subjectSub, grant.ServiceID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace grants transaction: %w", err)
	}
	return nil
}

func (s *Store) SyncSubjectGrantSnapshot(ctx context.Context, subjects []domain.Subject, grants []ServiceGrant) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin sync subject-grant snapshot transaction: %w", err)
	}
	defer rollbackQuietly(ctx, tx)

	subjectsBySub := make(map[string]domain.Subject, len(subjects))
	for _, subject := range subjects {
		subjectsBySub[subject.Sub] = subject
	}
	subjectSubs := mapsSortedKeys(subjectsBySub)

	for _, subjectSub := range subjectSubs {
		subject := subjectsBySub[subjectSub]
		if _, err := tx.Exec(
			ctx,
			`
				insert into subjects (
					subject_sub,
					subject_key,
					preferred_username,
					email,
					display_name,
					last_synced_at
				) values ($1, $2, $3, $4, $5, now())
				on conflict (subject_sub) do update set
					subject_key = excluded.subject_key,
					preferred_username = excluded.preferred_username,
					email = excluded.email,
					display_name = excluded.display_name,
					last_synced_at = now(),
					updated_at = now()
			`,
			subject.Sub,
			subject.SubjectKey,
			subject.PreferredUsername,
			subject.Email,
			subject.DisplayName,
		); err != nil {
			return fmt.Errorf("upsert subject %s during snapshot sync: %w", subject.Sub, err)
		}
	}

	if len(subjectSubs) == 0 {
		if _, err := tx.Exec(ctx, `delete from service_grants`); err != nil {
			return fmt.Errorf("clear service grants for empty snapshot: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `delete from service_grants where not (subject_sub = any($1))`, subjectSubs); err != nil {
			return fmt.Errorf("delete stale service grants: %w", err)
		}
	}

	grantsBySubject := make(map[string][]ServiceGrant)
	for _, grant := range grants {
		grantsBySubject[grant.SubjectSub] = append(grantsBySubject[grant.SubjectSub], grant)
	}

	for _, subjectSub := range subjectSubs {
		if _, err := tx.Exec(ctx, `delete from service_grants where subject_sub = $1`, subjectSub); err != nil {
			return fmt.Errorf("delete existing grants for %s during snapshot sync: %w", subjectSub, err)
		}

		for _, grant := range grantsBySubject[subjectSub] {
			grantedAt := grant.GrantedAt
			if grantedAt.IsZero() {
				grantedAt = time.Now().UTC()
			}
			lastSyncedAt := grant.LastSyncedAt
			if lastSyncedAt.IsZero() {
				lastSyncedAt = time.Now().UTC()
			}

			if _, err := tx.Exec(
				ctx,
				`
					insert into service_grants (
						subject_sub,
						service_id,
						source_group,
						granted_at,
						last_synced_at
					) values ($1, $2, $3, $4, $5)
				`,
				subjectSub,
				grant.ServiceID,
				grant.SourceGroup,
				grantedAt,
				lastSyncedAt,
			); err != nil {
				return fmt.Errorf("insert grant %s/%s during snapshot sync: %w", subjectSub, grant.ServiceID, err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit sync subject-grant snapshot transaction: %w", err)
	}
	return nil
}

func (s *Store) ReconcileDesiredTenants(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin desired-tenant reconciliation: %w", err)
	}
	defer rollbackQuietly(ctx, tx)

	desiredSpecs, err := s.loadDesiredTenantSpecs(ctx, tx)
	if err != nil {
		return err
	}

	currentTenants, err := s.loadTenantInstances(ctx, tx)
	if err != nil {
		return err
	}

	desiredKeys := mapsSortedKeys(desiredSpecs)
	for _, key := range desiredKeys {
		spec := desiredSpecs[key]
		tenant, ok := currentTenants[key]
		if !ok {
			if err := s.insertTenantInstance(ctx, tx, spec); err != nil {
				return err
			}
			continue
		}

		if err := s.enableTenantInstance(ctx, tx, tenant, spec); err != nil {
			return err
		}
	}

	currentKeys := mapsSortedKeys(currentTenants)
	for _, key := range currentKeys {
		tenant := currentTenants[key]
		if _, ok := desiredSpecs[key]; ok {
			continue
		}
		if tenant.DesiredState == domain.TenantDesiredStateDeleted {
			continue
		}
		if _, err := tx.Exec(
			ctx,
			`
				update tenant_instances
				set desired_state = $2,
					updated_at = now()
				where tenant_id = $1
			`,
			tenant.TenantID,
			domain.TenantDesiredStateDeleted,
		); err != nil {
			return fmt.Errorf("mark tenant %s as deleted: %w", tenant.TenantID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit desired-tenant reconciliation: %w", err)
	}
	return nil
}

func (s *Store) ListTenantInstances(ctx context.Context) ([]TenantInstance, error) {
	rows, err := s.pool.Query(
		ctx,
		`
			select
				tenant_id::text,
				subject_sub,
				service_id,
				subject_key,
				tenant_instance_name,
				internal_dns_name,
				desired_state,
				runtime_state,
				coolify_resource_id,
				coolify_application_id,
				upstream_url,
				secret_version,
				last_healthy_at,
				last_reconciled_at,
				last_error,
				metadata,
				created_at,
				updated_at
			from tenant_instances
			order by service_id, subject_sub
		`,
	)
	if err != nil {
		return nil, fmt.Errorf("list tenant instances: %w", err)
	}
	defer rows.Close()

	return scanTenantInstances(rows)
}

func (s *Store) RecordReconcileRun(ctx context.Context, input ReconcileRunInput) error {
	detailsJSON, err := json.Marshal(input.Details)
	if err != nil {
		return fmt.Errorf("marshal reconcile details: %w", err)
	}

	if _, err := s.pool.Exec(
		ctx,
		`
			insert into reconcile_runs (
				tenant_id,
				desired_state,
				observed_state,
				action,
				status,
				details,
				started_at,
				finished_at
			) values ($1, $2, $3, $4, $5, $6, $7, $8)
		`,
		input.TenantID,
		input.DesiredState,
		input.ObservedState,
		input.Action,
		input.Status,
		detailsJSON,
		input.StartedAt,
		input.FinishedAt,
	); err != nil {
		return fmt.Errorf("insert reconcile run for tenant %s: %w", input.TenantID, err)
	}

	return nil
}

func (s *Store) MarkTenantReconciled(ctx context.Context, tenantID uuid.UUID, reconciledAt time.Time, lastError string) error {
	if _, err := s.pool.Exec(
		ctx,
		`
			update tenant_instances
			set last_reconciled_at = $2,
				last_error = case
					when $3 = '' then null
					else $3
				end,
				updated_at = now()
			where tenant_id = $1
		`,
		tenantID,
		reconciledAt,
		lastError,
	); err != nil {
		return fmt.Errorf("mark tenant %s reconciled: %w", tenantID, err)
	}

	return nil
}

func (s *Store) UpdateTenantRuntimeStatus(ctx context.Context, update TenantRuntimeUpdate) error {
	var lastHealthyAt any
	if update.LastHealthyAt != nil {
		lastHealthyAt = *update.LastHealthyAt
	}

	if _, err := s.pool.Exec(
		ctx,
		`
			update tenant_instances
			set runtime_state = $2,
				coolify_resource_id = case when $3 = '' then coolify_resource_id else $3 end,
				coolify_application_id = case when $4 = '' then coolify_application_id else $4 end,
				upstream_url = case when $5 = '' then upstream_url else $5 end,
				last_healthy_at = case when $6 is null then last_healthy_at else $6 end,
				last_error = case when $7 = '' then null else $7 end,
				updated_at = now()
			where tenant_id = $1
		`,
		update.TenantID,
		update.RuntimeState,
		update.CoolifyResourceID,
		update.CoolifyApplicationID,
		update.UpstreamURL,
		lastHealthyAt,
		update.LastError,
	); err != nil {
		return fmt.Errorf("update tenant runtime status for %s: %w", update.TenantID, err)
	}

	return nil
}

func (s *Store) DeleteTenantInstance(ctx context.Context, tenantID uuid.UUID) error {
	if _, err := s.pool.Exec(ctx, `delete from tenant_instances where tenant_id = $1`, tenantID); err != nil {
		return fmt.Errorf("delete tenant instance %s: %w", tenantID, err)
	}
	return nil
}

func (s *Store) loadDesiredTenantSpecs(ctx context.Context, tx pgx.Tx) (map[string]desiredTenantSpec, error) {
	rows, err := tx.Query(
		ctx,
		`
			select
				subjects.subject_sub,
				subjects.subject_key,
				coalesce(subjects.preferred_username, ''),
				coalesce(subjects.email, ''),
				coalesce(subjects.display_name, ''),
				service_grants.service_id
			from service_grants
			join subjects on subjects.subject_sub = service_grants.subject_sub
			join service_catalog on service_catalog.service_id = service_grants.service_id
			where service_catalog.enabled = true
			order by service_grants.service_id, subjects.subject_sub
		`,
	)
	if err != nil {
		return nil, fmt.Errorf("load desired tenant specs: %w", err)
	}
	defer rows.Close()

	desiredSpecs := make(map[string]desiredTenantSpec)
	for rows.Next() {
		var subjectSub string
		var subjectKey string
		var preferredUsername string
		var email string
		var displayName string
		var serviceID string
		if err := rows.Scan(
			&subjectSub,
			&subjectKey,
			&preferredUsername,
			&email,
			&displayName,
			&serviceID,
		); err != nil {
			return nil, fmt.Errorf("scan desired tenant spec: %w", err)
		}

		spec := desiredTenantSpec{
			subject: domain.Subject{
				Sub:               subjectSub,
				SubjectKey:        subjectKey,
				PreferredUsername: preferredUsername,
				Email:             email,
				DisplayName:       displayName,
			},
			serviceID: serviceID,
		}
		desiredSpecs[tenantMapKey(subjectSub, serviceID)] = spec
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate desired tenant specs: %w", err)
	}

	return desiredSpecs, nil
}

func (s *Store) loadTenantInstances(ctx context.Context, tx pgx.Tx) (map[string]TenantInstance, error) {
	rows, err := tx.Query(
		ctx,
		`
			select
				tenant_id::text,
				subject_sub,
				service_id,
				subject_key,
				tenant_instance_name,
				internal_dns_name,
				desired_state,
				runtime_state,
				coolify_resource_id,
				coolify_application_id,
				upstream_url,
				secret_version,
				last_healthy_at,
				last_reconciled_at,
				last_error,
				metadata,
				created_at,
				updated_at
			from tenant_instances
		`,
	)
	if err != nil {
		return nil, fmt.Errorf("load current tenant instances: %w", err)
	}
	defer rows.Close()

	tenants, err := scanTenantInstances(rows)
	if err != nil {
		return nil, err
	}

	tenantMap := make(map[string]TenantInstance, len(tenants))
	for _, tenant := range tenants {
		tenantMap[tenantMapKey(tenant.SubjectSub, tenant.ServiceID)] = tenant
	}
	return tenantMap, nil
}

func (s *Store) insertTenantInstance(ctx context.Context, tx pgx.Tx, spec desiredTenantSpec) error {
	tenantInstanceName := domain.BuildTenantInstanceName(spec.serviceID, spec.subject.SubjectKey)
	internalDNSName := tenantInstanceName
	if _, err := tx.Exec(
		ctx,
		`
			insert into tenant_instances (
				subject_sub,
				service_id,
				subject_key,
				tenant_instance_name,
				internal_dns_name,
				desired_state,
				runtime_state
			) values ($1, $2, $3, $4, $5, $6, $7)
		`,
		spec.subject.Sub,
		spec.serviceID,
		spec.subject.SubjectKey,
		tenantInstanceName,
		internalDNSName,
		domain.TenantDesiredStateEnabled,
		domain.TenantRuntimeStateProvisioning,
	); err != nil {
		return fmt.Errorf("insert tenant instance %s/%s: %w", spec.subject.Sub, spec.serviceID, err)
	}
	return nil
}

func (s *Store) enableTenantInstance(ctx context.Context, tx pgx.Tx, tenant TenantInstance, spec desiredTenantSpec) error {
	tenantInstanceName := domain.BuildTenantInstanceName(spec.serviceID, spec.subject.SubjectKey)
	internalDNSName := tenantInstanceName
	runtimeState := tenant.RuntimeState
	lastError := tenant.LastError
	if tenant.SubjectKey != spec.subject.SubjectKey ||
		tenant.TenantInstanceName != tenantInstanceName ||
		tenant.InternalDNSName != internalDNSName {
		runtimeState = domain.TenantRuntimeStateDegraded
		lastError = "tenant identity drift detected; reprovision required"
	}
	if _, err := tx.Exec(
		ctx,
		`
			update tenant_instances
			set subject_key = $2,
				tenant_instance_name = $3,
				internal_dns_name = $4,
				desired_state = $5,
				runtime_state = $6,
				last_error = case
					when $7 = '' then null
					else $7
				end,
				updated_at = now()
			where tenant_id = $1
		`,
		tenant.TenantID,
		spec.subject.SubjectKey,
		tenantInstanceName,
		internalDNSName,
		domain.TenantDesiredStateEnabled,
		runtimeState,
		lastError,
	); err != nil {
		return fmt.Errorf("enable tenant instance %s: %w", tenant.TenantID, err)
	}
	return nil
}

func scanTenantInstances(rows pgx.Rows) ([]TenantInstance, error) {
	var tenants []TenantInstance
	for rows.Next() {
		var tenant TenantInstance
		var tenantID string
		var coolifyResourceID sql.NullString
		var coolifyApplicationID sql.NullString
		var upstreamURL sql.NullString
		var secretVersion sql.NullString
		var lastHealthyAt sql.NullTime
		var lastReconciledAt sql.NullTime
		var lastError sql.NullString
		var metadata []byte

		if err := rows.Scan(
			&tenantID,
			&tenant.SubjectSub,
			&tenant.ServiceID,
			&tenant.SubjectKey,
			&tenant.TenantInstanceName,
			&tenant.InternalDNSName,
			&tenant.DesiredState,
			&tenant.RuntimeState,
			&coolifyResourceID,
			&coolifyApplicationID,
			&upstreamURL,
			&secretVersion,
			&lastHealthyAt,
			&lastReconciledAt,
			&lastError,
			&metadata,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant instance: %w", err)
		}

		parsedTenantID, err := uuid.Parse(tenantID)
		if err != nil {
			return nil, fmt.Errorf("parse tenant id %q: %w", tenantID, err)
		}
		tenant.TenantID = parsedTenantID
		tenant.CoolifyResourceID = coolifyResourceID.String
		tenant.CoolifyApplicationID = coolifyApplicationID.String
		tenant.UpstreamURL = upstreamURL.String
		tenant.SecretVersion = secretVersion.String
		tenant.LastError = lastError.String
		tenant.Metadata = append([]byte(nil), metadata...)
		if lastHealthyAt.Valid {
			value := lastHealthyAt.Time
			tenant.LastHealthyAt = &value
		}
		if lastReconciledAt.Valid {
			value := lastReconciledAt.Time
			tenant.LastReconciledAt = &value
		}

		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tenant instances: %w", err)
	}

	return tenants, nil
}

func tenantMapKey(subjectSub string, serviceID string) string {
	return subjectSub + "::" + serviceID
}

func mapsSortedKeys[T any](input map[string]T) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func rollbackQuietly(ctx context.Context, tx pgx.Tx) {
	if tx == nil {
		return
	}
	_ = tx.Rollback(ctx)
}
