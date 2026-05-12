-- +goose Up
CREATE TABLE IF NOT EXISTS subjects (
    subject_sub TEXT PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE,
    preferred_username TEXT,
    email TEXT,
    display_name TEXT,
    last_synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS service_catalog (
    service_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    upstream_service_name TEXT NOT NULL,
    transport_type TEXT NOT NULL CHECK(transport_type IN ('streamable-http', 'sse')),
    internal_port INTEGER NOT NULL,
    public_path TEXT NOT NULL UNIQUE,
    internal_upstream_path TEXT NOT NULL,
    health_path TEXT NOT NULL,
    health_probe_expectation TEXT NOT NULL,
    resource_profile TEXT NOT NULL,
    persistence_policy TEXT NOT NULL,
    adapter_requirement TEXT NOT NULL,
    secret_contract TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(secret_contract)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS service_grants (
    subject_sub TEXT NOT NULL REFERENCES subjects(subject_sub) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES service_catalog(service_id) ON DELETE CASCADE,
    source_group TEXT NOT NULL,
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subject_sub, service_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS tenant_instances (
    tenant_id BLOB PRIMARY KEY CHECK(length(tenant_id) = 16),
    subject_sub TEXT NOT NULL REFERENCES subjects(subject_sub) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES service_catalog(service_id) ON DELETE CASCADE,
    subject_key TEXT NOT NULL,
    tenant_instance_name TEXT NOT NULL UNIQUE,
    internal_dns_name TEXT NOT NULL,
    desired_state TEXT NOT NULL CHECK(desired_state IN ('enabled', 'disabled', 'deleted')),
    runtime_state TEXT NOT NULL CHECK(runtime_state IN ('provisioning', 'ready', 'degraded', 'disabled', 'deleting')),
    coolify_resource_id TEXT,
    coolify_application_id TEXT,
    upstream_url TEXT,
    secret_version TEXT,
    last_healthy_at TEXT,
    last_reconciled_at TEXT,
    last_error TEXT,
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (subject_sub, service_id)
) STRICT;

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    created_by_subject_sub TEXT REFERENCES subjects(subject_sub) ON DELETE SET NULL,
    redirect_uris TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(redirect_uris)),
    grant_types TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(grant_types)),
    response_types TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(response_types)),
    scopes TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(scopes)),
    token_endpoint_auth_method TEXT NOT NULL,
    client_secret_hash TEXT,
    metadata TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(metadata)),
    disabled_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS oauth_sessions (
    session_id BLOB PRIMARY KEY CHECK(length(session_id) = 16),
    subject_sub TEXT REFERENCES subjects(subject_sub) ON DELETE SET NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    service_id TEXT REFERENCES service_catalog(service_id) ON DELETE SET NULL,
    redirect_uri TEXT NOT NULL,
    state TEXT,
    nonce TEXT,
    scope TEXT NOT NULL DEFAULT '',
    code_challenge TEXT,
    code_challenge_method TEXT,
    authorization_code_hash TEXT,
    authorization_code_ciphertext BLOB,
    access_token_hash TEXT,
    access_token_ciphertext BLOB,
    refresh_token_hash TEXT,
    refresh_token_ciphertext BLOB,
    code_create_at TEXT,
    code_expires_in_seconds INTEGER NOT NULL DEFAULT 0,
    access_create_at TEXT,
    access_expires_in_seconds INTEGER NOT NULL DEFAULT 0,
    refresh_create_at TEXT,
    refresh_expires_in_seconds INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS edge_browser_sessions (
    session_id TEXT PRIMARY KEY,
    subject_sub TEXT,
    claims TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(claims)),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS edge_pending_logins (
    state TEXT PRIMARY KEY,
    return_to TEXT NOT NULL,
    nonce TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS audit_events (
    event_id BLOB PRIMARY KEY CHECK(length(event_id) = 16),
    correlation_id TEXT NOT NULL,
    actor_subject_sub TEXT REFERENCES subjects(subject_sub) ON DELETE SET NULL,
    service_id TEXT REFERENCES service_catalog(service_id) ON DELETE SET NULL,
    tenant_id BLOB REFERENCES tenant_instances(tenant_id) ON DELETE SET NULL CHECK(tenant_id IS NULL OR length(tenant_id) = 16),
    event_type TEXT NOT NULL,
    event_status TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS reconcile_runs (
    run_id BLOB PRIMARY KEY CHECK(length(run_id) = 16),
    tenant_id BLOB REFERENCES tenant_instances(tenant_id) ON DELETE CASCADE CHECK(tenant_id IS NULL OR length(tenant_id) = 16),
    desired_state TEXT NOT NULL,
    observed_state TEXT,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details)),
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
) STRICT;

CREATE INDEX IF NOT EXISTS idx_subjects_subject_key ON subjects(subject_key);
CREATE INDEX IF NOT EXISTS idx_service_grants_service_id ON service_grants(service_id);
CREATE INDEX IF NOT EXISTS idx_tenant_instances_runtime_state ON tenant_instances(runtime_state);
CREATE INDEX IF NOT EXISTS idx_tenant_instances_service_id ON tenant_instances(service_id);
CREATE INDEX IF NOT EXISTS idx_tenant_instances_subject_sub ON tenant_instances(subject_sub);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_client_id ON oauth_sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_subject_sub ON oauth_sessions(subject_sub);
CREATE INDEX IF NOT EXISTS idx_oauth_sessions_expires_at ON oauth_sessions(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_sessions_authorization_code_hash ON oauth_sessions(authorization_code_hash) WHERE authorization_code_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_sessions_access_token_hash ON oauth_sessions(access_token_hash) WHERE access_token_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_sessions_refresh_token_hash ON oauth_sessions(refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_edge_browser_sessions_subject_sub ON edge_browser_sessions(subject_sub);
CREATE INDEX IF NOT EXISTS idx_edge_browser_sessions_expires_at ON edge_browser_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_edge_pending_logins_expires_at ON edge_pending_logins(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reconcile_runs_tenant_id ON reconcile_runs(tenant_id, started_at DESC);

-- +goose Down
DROP TABLE IF EXISTS reconcile_runs;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS edge_pending_logins;
DROP TABLE IF EXISTS edge_browser_sessions;
DROP TABLE IF EXISTS oauth_sessions;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS tenant_instances;
DROP TABLE IF EXISTS service_grants;
DROP TABLE IF EXISTS service_catalog;
DROP TABLE IF EXISTS subjects;
