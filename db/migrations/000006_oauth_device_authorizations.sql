-- +goose Up
CREATE TABLE IF NOT EXISTS oauth_device_authorizations (
    device_authorization_id BLOB PRIMARY KEY CHECK(length(device_authorization_id) = 16),
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    subject_sub TEXT REFERENCES subjects(subject_sub) ON DELETE SET NULL,
    service_id TEXT NOT NULL REFERENCES service_catalog(service_id) ON DELETE CASCADE,
    resource TEXT NOT NULL,
    scope TEXT NOT NULL,
    device_code_hash TEXT NOT NULL UNIQUE,
    user_code_hash TEXT NOT NULL UNIQUE,
    user_code_display TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'denied', 'expired', 'consumed')),
    interval_seconds INTEGER NOT NULL DEFAULT 5,
    last_poll_at TEXT,
    poll_count INTEGER NOT NULL DEFAULT 0,
    approved_at TEXT,
    denied_at TEXT,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE INDEX IF NOT EXISTS idx_oauth_device_authorizations_client_id ON oauth_device_authorizations(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_device_authorizations_subject_sub ON oauth_device_authorizations(subject_sub);
CREATE INDEX IF NOT EXISTS idx_oauth_device_authorizations_expires_at ON oauth_device_authorizations(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_device_authorizations_status ON oauth_device_authorizations(status);

-- +goose Down
DROP TABLE IF EXISTS oauth_device_authorizations;
