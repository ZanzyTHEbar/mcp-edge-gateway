# Database Schema V1

Status: Frozen for Batch 1
Date: 2026-03-21

This document defines the initial PostgreSQL schema for the MCP platform.

## 1. Tables

### 1.1 `subjects`

Purpose:

- canonical identity keyed by OIDC `sub`

Columns:

- `subject_sub text primary key`
- `subject_key text not null unique`
- `preferred_username text`
- `email text`
- `display_name text`
- `last_synced_at timestamptz not null default now()`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

### 1.2 `service_catalog`

Purpose:

- platform-supported MCP services and their runtime contracts

Columns:

- `service_id text primary key`
- `display_name text not null`
- `upstream_service_name text not null`
- `transport_type text not null`
- `internal_port integer not null`
- `public_path text not null unique`
- `internal_upstream_path text not null`
- `health_path text not null`
- `health_probe_expectation text not null`
- `resource_profile text not null`
- `persistence_policy text not null`
- `adapter_requirement text not null`
- `secret_contract jsonb not null default '[]'::jsonb`
- `enabled boolean not null default true`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

### 1.3 `service_grants`

Purpose:

- per-subject entitlement to a service

Columns:

- `subject_sub text not null references subjects(subject_sub) on delete cascade`
- `service_id text not null references service_catalog(service_id) on delete cascade`
- `source_group text not null`
- `granted_at timestamptz not null default now()`
- `last_synced_at timestamptz not null default now()`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

Primary key:

- `(subject_sub, service_id)`

### 1.4 `tenant_instances`

Purpose:

- desired and observed tenant runtime state for one `user x service`

Columns:

- `tenant_id uuid primary key default gen_random_uuid()`
- `subject_sub text not null references subjects(subject_sub) on delete cascade`
- `service_id text not null references service_catalog(service_id) on delete cascade`
- `subject_key text not null`
- `tenant_instance_name text not null unique`
- `internal_dns_name text not null`
- `desired_state text not null`
- `runtime_state text not null`
- `coolify_resource_id text`
- `coolify_application_id text`
- `upstream_url text`
- `secret_version text`
- `last_healthy_at timestamptz`
- `last_reconciled_at timestamptz`
- `last_error text`
- `metadata jsonb not null default '{}'::jsonb`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

Unique key:

- `(subject_sub, service_id)`

### 1.5 `oauth_clients`

Purpose:

- MCP client registrations at the shared edge

Columns:

- `client_id text primary key`
- `client_name text not null`
- `created_by_subject_sub text references subjects(subject_sub) on delete set null`
- `redirect_uris jsonb not null default '[]'::jsonb`
- `grant_types jsonb not null default '[]'::jsonb`
- `response_types jsonb not null default '[]'::jsonb`
- `scopes jsonb not null default '[]'::jsonb`
- `token_endpoint_auth_method text not null`
- `client_secret_hash text`
- `metadata jsonb not null default '{}'::jsonb`
- `disabled_at timestamptz`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

### 1.6 `oauth_sessions`

Purpose:

- authorization-session state for browser login and token exchange

Columns:

- `session_id uuid primary key default gen_random_uuid()`
- `subject_sub text references subjects(subject_sub) on delete set null`
- `client_id text not null references oauth_clients(client_id) on delete cascade`
- `service_id text references service_catalog(service_id) on delete set null`
- `redirect_uri text not null`
- `state text`
- `nonce text`
- `code_challenge text`
- `code_challenge_method text`
- `authorization_code_hash text`
- `access_token_hash text`
- `refresh_token_hash text`
- `expires_at timestamptz`
- `consumed_at timestamptz`
- `created_at timestamptz not null default now()`
- `updated_at timestamptz not null default now()`

### 1.7 `audit_events`

Purpose:

- structured platform audit trail

Columns:

- `event_id uuid primary key default gen_random_uuid()`
- `correlation_id text not null`
- `actor_subject_sub text references subjects(subject_sub) on delete set null`
- `service_id text references service_catalog(service_id) on delete set null`
- `tenant_id uuid references tenant_instances(tenant_id) on delete set null`
- `event_type text not null`
- `event_status text not null`
- `payload jsonb not null default '{}'::jsonb`
- `created_at timestamptz not null default now()`

### 1.8 `reconcile_runs`

Purpose:

- per-run reconciler execution history

Columns:

- `run_id uuid primary key default gen_random_uuid()`
- `tenant_id uuid references tenant_instances(tenant_id) on delete cascade`
- `desired_state text not null`
- `observed_state text`
- `action text not null`
- `status text not null`
- `details jsonb not null default '{}'::jsonb`
- `started_at timestamptz not null default now()`
- `finished_at timestamptz`

## 2. Required Indexes

- `idx_subjects_subject_key` on `subjects(subject_key)`
- `idx_service_grants_service_id` on `service_grants(service_id)`
- `idx_tenant_instances_runtime_state` on `tenant_instances(runtime_state)`
- `idx_tenant_instances_service_id` on `tenant_instances(service_id)`
- `idx_tenant_instances_subject_sub` on `tenant_instances(subject_sub)`
- `idx_oauth_sessions_client_id` on `oauth_sessions(client_id)`
- `idx_oauth_sessions_subject_sub` on `oauth_sessions(subject_sub)`
- `idx_audit_events_correlation_id` on `audit_events(correlation_id)`
- `idx_audit_events_created_at` on `audit_events(created_at desc)`
- `idx_reconcile_runs_tenant_id` on `reconcile_runs(tenant_id, started_at desc)`

## 3. Required State Constraints

- `service_catalog.transport_type` in `('streamable-http', 'sse')`
- `tenant_instances.desired_state` in `('enabled', 'disabled', 'deleted')`
- `tenant_instances.runtime_state` in `('provisioning', 'ready', 'degraded', 'disabled', 'deleting')`

## 4. Source of Truth Rules

- `subjects.subject_sub` is canonical identity.
- `service_catalog` is versioned platform configuration, not ad hoc runtime state.
- `service_grants` is the reconciler input from Authentik sync.
- `tenant_instances` is the control-plane desired-versus-actual state store.
- `oauth_clients` and `oauth_sessions` belong to `mcp-edge`.
- `audit_events` and `reconcile_runs` are append-oriented operational history.
