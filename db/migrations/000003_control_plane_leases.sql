-- +goose Up
CREATE TABLE IF NOT EXISTS control_plane_leases (
    lease_name TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- +goose Down
DROP TABLE IF EXISTS control_plane_leases;
