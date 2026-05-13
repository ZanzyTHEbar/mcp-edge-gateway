-- +goose Up
CREATE TABLE IF NOT EXISTS service_grant_sources (
    subject_sub TEXT NOT NULL REFERENCES subjects(subject_sub) ON DELETE CASCADE,
    service_id TEXT NOT NULL REFERENCES service_catalog(service_id) ON DELETE CASCADE,
    source_group TEXT NOT NULL,
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subject_sub, service_id, source_group)
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO service_grant_sources (subject_sub, service_id, source_group, granted_at, last_synced_at, created_at, updated_at)
SELECT subject_sub, service_id, source_group, granted_at, last_synced_at, created_at, updated_at
FROM service_grants;

CREATE INDEX IF NOT EXISTS idx_service_grant_sources_service_id ON service_grant_sources(service_id);
CREATE INDEX IF NOT EXISTS idx_service_grant_sources_source_group ON service_grant_sources(source_group);

-- +goose Down
DROP TABLE IF EXISTS service_grant_sources;
