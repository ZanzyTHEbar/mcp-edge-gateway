alter table oauth_sessions
    add column if not exists scope text not null default '';

alter table oauth_sessions
    add column if not exists code_create_at timestamptz;

alter table oauth_sessions
    add column if not exists code_expires_in_seconds bigint not null default 0;

alter table oauth_sessions
    add column if not exists access_create_at timestamptz;

alter table oauth_sessions
    add column if not exists access_expires_in_seconds bigint not null default 0;

alter table oauth_sessions
    add column if not exists refresh_create_at timestamptz;

alter table oauth_sessions
    add column if not exists refresh_expires_in_seconds bigint not null default 0;

alter table oauth_sessions
    add column if not exists authorization_code_ciphertext bytea;

alter table oauth_sessions
    add column if not exists access_token_ciphertext bytea;

alter table oauth_sessions
    add column if not exists refresh_token_ciphertext bytea;

create index if not exists idx_oauth_sessions_expires_at
    on oauth_sessions(expires_at);

create unique index if not exists idx_oauth_sessions_authorization_code_hash
    on oauth_sessions(authorization_code_hash)
    where authorization_code_hash is not null;

create unique index if not exists idx_oauth_sessions_access_token_hash
    on oauth_sessions(access_token_hash)
    where access_token_hash is not null;

create unique index if not exists idx_oauth_sessions_refresh_token_hash
    on oauth_sessions(refresh_token_hash)
    where refresh_token_hash is not null;

create table if not exists edge_browser_sessions (
    session_id text primary key,
    subject_sub text,
    claims jsonb not null default '{}'::jsonb,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_edge_browser_sessions_subject_sub
    on edge_browser_sessions(subject_sub);

create index if not exists idx_edge_browser_sessions_expires_at
    on edge_browser_sessions(expires_at);

create table if not exists edge_pending_logins (
    state text primary key,
    return_to text not null,
    nonce text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_edge_pending_logins_expires_at
    on edge_pending_logins(expires_at);
