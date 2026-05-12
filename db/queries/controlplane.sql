-- name: UpsertSubject :exec
INSERT INTO subjects (subject_sub, subject_key, preferred_username, email, display_name, last_synced_at, updated_at)
VALUES (sqlc.arg(subject_sub), sqlc.arg(subject_key), sqlc.arg(preferred_username), sqlc.arg(email), sqlc.arg(display_name), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(subject_sub) DO UPDATE SET
    subject_key = excluded.subject_key,
    preferred_username = excluded.preferred_username,
    email = excluded.email,
    display_name = excluded.display_name,
    last_synced_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP;

-- name: DeleteSubjectGrants :exec
DELETE FROM service_grants WHERE subject_sub = sqlc.arg(subject_sub);

-- name: InsertServiceGrant :exec
INSERT INTO service_grants (subject_sub, service_id, source_group, granted_at, last_synced_at)
VALUES (sqlc.arg(subject_sub), sqlc.arg(service_id), sqlc.arg(source_group), sqlc.arg(granted_at), sqlc.arg(last_synced_at));

-- name: DeleteAllServiceGrants :exec
DELETE FROM service_grants;

-- name: DeleteStaleServiceGrants :exec
DELETE FROM service_grants WHERE subject_sub NOT IN (sqlc.slice(subject_subs));

-- name: ListDesiredTenantSpecs :many
SELECT subjects.subject_sub,
       subjects.subject_key,
       COALESCE(subjects.preferred_username, '') AS preferred_username,
       COALESCE(subjects.email, '') AS email,
       COALESCE(subjects.display_name, '') AS display_name,
       service_grants.service_id
FROM service_grants
JOIN subjects ON subjects.subject_sub = service_grants.subject_sub
JOIN service_catalog ON service_catalog.service_id = service_grants.service_id
WHERE service_catalog.enabled = 1
ORDER BY service_grants.service_id, subjects.subject_sub;

-- name: ListTenantInstances :many
SELECT tenant_id,
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
FROM tenant_instances
ORDER BY service_id, subject_sub;

-- name: InsertTenantInstance :exec
INSERT INTO tenant_instances (tenant_id, subject_sub, service_id, subject_key, tenant_instance_name, internal_dns_name, desired_state, runtime_state)
VALUES (sqlc.arg(tenant_id), sqlc.arg(subject_sub), sqlc.arg(service_id), sqlc.arg(subject_key), sqlc.arg(tenant_instance_name), sqlc.arg(internal_dns_name), sqlc.arg(desired_state), sqlc.arg(runtime_state));

-- name: MarkTenantDesiredDeleted :exec
UPDATE tenant_instances
SET desired_state = sqlc.arg(desired_state),
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: EnableTenantInstance :exec
UPDATE tenant_instances
SET subject_key = sqlc.arg(subject_key),
    tenant_instance_name = sqlc.arg(tenant_instance_name),
    internal_dns_name = sqlc.arg(internal_dns_name),
    desired_state = sqlc.arg(desired_state),
    runtime_state = sqlc.arg(runtime_state),
    last_error = NULLIF(sqlc.arg(last_error), ''),
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: InsertReconcileRun :exec
INSERT INTO reconcile_runs (run_id, tenant_id, desired_state, observed_state, action, status, details, started_at, finished_at)
VALUES (sqlc.arg(run_id), sqlc.arg(tenant_id), sqlc.arg(desired_state), sqlc.arg(observed_state), sqlc.arg(action), sqlc.arg(status), sqlc.arg(details), sqlc.arg(started_at), sqlc.arg(finished_at));

-- name: MarkTenantReconciled :exec
UPDATE tenant_instances
SET last_reconciled_at = sqlc.arg(last_reconciled_at),
    last_error = NULLIF(sqlc.arg(last_error), ''),
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: UpdateTenantRuntimeStatus :exec
UPDATE tenant_instances
SET runtime_state = sqlc.arg(runtime_state),
    coolify_resource_id = CASE WHEN CAST(sqlc.arg(clear_runtime_references) AS boolean) THEN NULL WHEN sqlc.arg(coolify_resource_id) = '' THEN coolify_resource_id ELSE sqlc.arg(coolify_resource_id) END,
    coolify_application_id = CASE WHEN sqlc.arg(clear_runtime_references) THEN NULL WHEN sqlc.arg(coolify_application_id) = '' THEN coolify_application_id ELSE sqlc.arg(coolify_application_id) END,
    upstream_url = CASE WHEN sqlc.arg(clear_runtime_references) THEN NULL WHEN sqlc.arg(upstream_url) = '' THEN upstream_url ELSE sqlc.arg(upstream_url) END,
    last_healthy_at = CASE WHEN sqlc.arg(clear_runtime_references) THEN NULL WHEN sqlc.narg(last_healthy_at) IS NULL THEN last_healthy_at ELSE sqlc.narg(last_healthy_at) END,
    last_error = NULLIF(sqlc.arg(last_error), ''),
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = sqlc.arg(tenant_id);

-- name: DeleteTenantInstance :exec
DELETE FROM tenant_instances WHERE tenant_id = sqlc.arg(tenant_id);
