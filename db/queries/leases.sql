-- name: AcquireControlPlaneLease :one
INSERT INTO control_plane_leases (
    lease_name,
    holder_id,
    expires_at,
    updated_at
)
VALUES (
    sqlc.arg(lease_name),
    sqlc.arg(holder_id),
    sqlc.arg(expires_at),
    sqlc.arg(now)
)
ON CONFLICT(lease_name) DO UPDATE SET
    holder_id = excluded.holder_id,
    expires_at = excluded.expires_at,
    updated_at = excluded.updated_at
WHERE control_plane_leases.holder_id = excluded.holder_id
    OR control_plane_leases.expires_at <= excluded.updated_at
RETURNING holder_id;

-- name: ReleaseControlPlaneLease :exec
DELETE FROM control_plane_leases
WHERE lease_name = sqlc.arg(lease_name)
    AND holder_id = sqlc.arg(holder_id);
