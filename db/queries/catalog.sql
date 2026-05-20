-- name: ListEnabledServiceCatalog :many
SELECT service_id,
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
    identity_context,
    enabled,
    source,
    created_at,
    updated_at
FROM service_catalog
WHERE enabled = 1
ORDER BY service_id;

-- name: GetEnabledServiceCatalogEntry :one
SELECT service_id,
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
    identity_context,
    enabled,
    source,
    created_at,
    updated_at
FROM service_catalog
WHERE service_id = ?1
  AND enabled = 1;

-- name: GetServiceCatalogEntry :one
SELECT service_id,
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
    identity_context,
    enabled,
    source,
    created_at,
    updated_at
FROM service_catalog
WHERE service_id = ?1;

-- name: ListEnabledServiceIDs :many
SELECT service_id
FROM service_catalog
WHERE enabled = 1
ORDER BY service_id;

-- name: ListServiceCatalog :many
SELECT service_id,
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
    identity_context,
    enabled,
    source,
    created_at,
    updated_at
FROM service_catalog
ORDER BY service_id;

-- name: UpsertServiceCatalogEntry :exec
INSERT INTO service_catalog (
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
    identity_context,
    enabled,
    source,
    updated_at
)
VALUES (
    sqlc.arg(service_id),
    sqlc.arg(display_name),
    sqlc.arg(upstream_service_name),
    sqlc.arg(transport_type),
    sqlc.arg(internal_port),
    sqlc.arg(public_path),
    sqlc.arg(internal_upstream_path),
    sqlc.arg(health_path),
    sqlc.arg(health_probe_expectation),
    sqlc.arg(resource_profile),
    sqlc.arg(persistence_policy),
    sqlc.arg(adapter_requirement),
    sqlc.arg(secret_contract),
    sqlc.arg(identity_context),
    sqlc.arg(enabled),
    sqlc.arg(source),
    CURRENT_TIMESTAMP
)
ON CONFLICT(service_id) DO UPDATE SET
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
    enabled = excluded.enabled,
    secret_contract = excluded.secret_contract,
    identity_context = excluded.identity_context,
    source = excluded.source,
    updated_at = CURRENT_TIMESTAMP;

-- name: DisableServiceCatalogEntriesNotIn :exec
UPDATE service_catalog
SET enabled = 0,
    updated_at = CURRENT_TIMESTAMP
WHERE service_id NOT IN (sqlc.slice(service_ids))
  AND source = 'builtin';

-- name: DisableServiceCatalogEntry :exec
UPDATE service_catalog
SET enabled = 0,
    updated_at = CURRENT_TIMESTAMP
WHERE service_id = ?1;
