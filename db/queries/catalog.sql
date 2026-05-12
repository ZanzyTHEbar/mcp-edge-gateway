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
    enabled,
    created_at,
    updated_at
FROM service_catalog
WHERE enabled = 1
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
    enabled,
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
    sqlc.arg(enabled),
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
    secret_contract = excluded.secret_contract,
    updated_at = CURRENT_TIMESTAMP;
