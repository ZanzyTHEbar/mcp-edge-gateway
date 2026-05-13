-- name: CreateOAuthClient :exec
INSERT INTO oauth_clients (client_id, client_name, created_by_subject_sub, redirect_uris, grant_types, response_types, scopes, token_endpoint_auth_method, client_secret_hash, metadata, created_at, updated_at)
VALUES (sqlc.arg(client_id), sqlc.arg(client_name), NULLIF(sqlc.arg(created_by_subject_sub), ''), sqlc.arg(redirect_uris), sqlc.arg(grant_types), sqlc.arg(response_types), sqlc.arg(scopes), sqlc.arg(token_endpoint_auth_method), sqlc.narg(client_secret_hash), '{}', sqlc.arg(created_at), sqlc.arg(created_at));

-- name: GetOAuthClient :one
SELECT redirect_uris, scopes, created_by_subject_sub, token_endpoint_auth_method, client_secret_hash, disabled_at
FROM oauth_clients
WHERE client_id = sqlc.arg(client_id);

-- name: UpsertOAuthSession :exec
INSERT INTO oauth_sessions (session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at, consumed_at, updated_at)
VALUES (sqlc.arg(session_id), NULLIF(sqlc.arg(subject_sub), ''), sqlc.arg(client_id), NULLIF(sqlc.arg(service_id), ''), sqlc.arg(resource), sqlc.arg(redirect_uri), sqlc.arg(scope), NULLIF(sqlc.arg(code_challenge), ''), NULLIF(sqlc.arg(code_challenge_method), ''), sqlc.narg(authorization_code_hash), sqlc.arg(authorization_code_ciphertext), sqlc.narg(access_token_hash), sqlc.arg(access_token_ciphertext), sqlc.narg(refresh_token_hash), sqlc.arg(refresh_token_ciphertext), sqlc.narg(code_create_at), sqlc.arg(code_expires_in_seconds), sqlc.narg(access_create_at), sqlc.arg(access_expires_in_seconds), sqlc.narg(refresh_create_at), sqlc.arg(refresh_expires_in_seconds), sqlc.narg(expires_at), NULL, CURRENT_TIMESTAMP)
ON CONFLICT(session_id) DO UPDATE SET
    subject_sub = excluded.subject_sub,
    client_id = excluded.client_id,
    service_id = excluded.service_id,
    resource = excluded.resource,
    redirect_uri = excluded.redirect_uri,
    scope = excluded.scope,
    code_challenge = excluded.code_challenge,
    code_challenge_method = excluded.code_challenge_method,
    authorization_code_hash = excluded.authorization_code_hash,
    authorization_code_ciphertext = excluded.authorization_code_ciphertext,
    access_token_hash = excluded.access_token_hash,
    access_token_ciphertext = excluded.access_token_ciphertext,
    refresh_token_hash = excluded.refresh_token_hash,
    refresh_token_ciphertext = excluded.refresh_token_ciphertext,
    code_create_at = excluded.code_create_at,
    code_expires_in_seconds = excluded.code_expires_in_seconds,
    access_create_at = excluded.access_create_at,
    access_expires_in_seconds = excluded.access_expires_in_seconds,
    refresh_create_at = excluded.refresh_create_at,
    refresh_expires_in_seconds = excluded.refresh_expires_in_seconds,
    expires_at = excluded.expires_at,
    consumed_at = NULL,
    updated_at = CURRENT_TIMESTAMP;

-- name: DeleteOAuthSessionByCodeHash :exec
DELETE FROM oauth_sessions WHERE authorization_code_hash = sqlc.arg(authorization_code_hash);

-- name: DeleteOAuthSessionByAccessHash :exec
DELETE FROM oauth_sessions WHERE access_token_hash = sqlc.arg(access_token_hash);

-- name: DeleteOAuthSessionByRefreshHash :exec
DELETE FROM oauth_sessions WHERE refresh_token_hash = sqlc.arg(refresh_token_hash);

-- name: GetOAuthSessionByAccessHash :one
SELECT session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at
FROM oauth_sessions
WHERE access_token_hash = sqlc.arg(access_token_hash);

-- name: GetOAuthSessionByRefreshHash :one
SELECT session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at
FROM oauth_sessions
WHERE refresh_token_hash = sqlc.arg(refresh_token_hash);

-- name: GetOAuthSessionByCodeHash :one
SELECT session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at
FROM oauth_sessions
WHERE authorization_code_hash = sqlc.arg(authorization_code_hash) AND consumed_at IS NULL;

-- name: ConsumeOAuthSessionByCodeHash :one
UPDATE oauth_sessions
SET consumed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE authorization_code_hash = sqlc.arg(authorization_code_hash) AND consumed_at IS NULL
RETURNING session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at;

-- name: ConsumeOAuthSessionByRefreshHash :one
UPDATE oauth_sessions
SET consumed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
WHERE refresh_token_hash = sqlc.arg(refresh_token_hash) AND consumed_at IS NULL
RETURNING session_id, subject_sub, client_id, service_id, resource, redirect_uri, scope, code_challenge, code_challenge_method, authorization_code_hash, authorization_code_ciphertext, access_token_hash, access_token_ciphertext, refresh_token_hash, refresh_token_ciphertext, code_create_at, code_expires_in_seconds, access_create_at, access_expires_in_seconds, refresh_create_at, refresh_expires_in_seconds, expires_at;

-- name: PutPendingLogin :exec
INSERT INTO edge_pending_logins (state, return_to, nonce, expires_at, updated_at)
VALUES (sqlc.arg(state), sqlc.arg(return_to), sqlc.arg(nonce), sqlc.arg(expires_at), CURRENT_TIMESTAMP)
ON CONFLICT(state) DO UPDATE SET return_to = excluded.return_to, nonce = excluded.nonce, expires_at = excluded.expires_at, updated_at = CURRENT_TIMESTAMP;

-- name: GetPendingLogin :one
SELECT state, return_to, nonce, expires_at
FROM edge_pending_logins
WHERE state = sqlc.arg(state);

-- name: DeletePendingLogin :exec
DELETE FROM edge_pending_logins WHERE state = sqlc.arg(state);

-- name: PutBrowserSession :exec
INSERT INTO edge_browser_sessions (session_id, subject_sub, claims, expires_at, updated_at)
VALUES (sqlc.arg(session_id), NULLIF(sqlc.arg(subject_sub), ''), sqlc.arg(claims), sqlc.arg(expires_at), CURRENT_TIMESTAMP)
ON CONFLICT(session_id) DO UPDATE SET subject_sub = excluded.subject_sub, claims = excluded.claims, expires_at = excluded.expires_at, updated_at = CURRENT_TIMESTAMP;

-- name: GetBrowserSession :one
SELECT claims, expires_at
FROM edge_browser_sessions
WHERE session_id = sqlc.arg(session_id);

-- name: DeleteBrowserSession :exec
DELETE FROM edge_browser_sessions WHERE session_id = sqlc.arg(session_id);

-- name: AllowedServiceGrant :one
SELECT EXISTS (
    SELECT 1
    FROM service_grants
    JOIN service_catalog ON service_catalog.service_id = service_grants.service_id
    WHERE service_grants.subject_sub = sqlc.arg(subject_sub)
      AND service_grants.service_id = sqlc.arg(service_id)
      AND service_catalog.enabled = 1
) AS allowed;

-- name: CountAllowedServiceGrants :one
SELECT COUNT(DISTINCT service_grants.service_id) AS allowed_count
FROM service_grants
JOIN service_catalog ON service_catalog.service_id = service_grants.service_id
WHERE service_grants.subject_sub = sqlc.arg(subject_sub)
  AND service_catalog.enabled = 1
  AND service_grants.service_id IN (sqlc.slice(service_ids));

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (event_id, correlation_id, actor_subject_sub, service_id, event_type, event_status, payload)
VALUES (sqlc.arg(event_id), sqlc.arg(correlation_id), sqlc.narg(actor_subject_sub), sqlc.narg(service_id), sqlc.arg(event_type), sqlc.arg(event_status), sqlc.arg(payload));

-- name: CountAuditEventsByType :one
SELECT COUNT(*) AS audit_count
FROM audit_events
WHERE event_type = sqlc.arg(event_type);

-- name: EdgeUpsertSubject :exec
INSERT INTO subjects (subject_sub, subject_key, preferred_username, email, display_name, last_synced_at, created_at, updated_at)
VALUES (sqlc.arg(subject_sub), sqlc.arg(subject_key), NULLIF(sqlc.arg(preferred_username), ''), NULLIF(sqlc.arg(email), ''), NULLIF(sqlc.arg(display_name), ''), CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(subject_sub) DO UPDATE SET
    subject_key = excluded.subject_key,
    preferred_username = COALESCE(excluded.preferred_username, subjects.preferred_username),
    email = COALESCE(excluded.email, subjects.email),
    display_name = COALESCE(excluded.display_name, subjects.display_name),
    last_synced_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP;

-- name: GetTenantUpstream :one
SELECT COALESCE(upstream_url, '') AS upstream_url,
       desired_state,
       runtime_state
FROM tenant_instances
WHERE subject_sub = sqlc.arg(subject_sub)
  AND service_id = sqlc.arg(service_id);
