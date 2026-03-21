# Implementation Contracts

Status: Frozen for Batch 1
Date: 2026-03-21

This document defines the shared contracts that both `mcp-edge` and `mcp-control-plane` must consume.

It exists to prevent drift between:

- runtime configuration
- subject identity
- tenant naming
- secret-path construction
- tenant lifecycle state

## 1. Identity Model

### 1.1 Canonical Subject Identifier

The canonical identity key is the OIDC `sub` claim.

Rules:

- tenancy is keyed on `sub`
- authorization is keyed on `sub`
- database primary subject identity is keyed on `sub`
- routing must never key on username, email, alias, or display name

### 1.2 Subject Shape

Minimum subject contract:

- `subject_sub`: immutable OIDC `sub`
- `subject_key`: path-safe derived key used in names and secret paths
- `preferred_username`: optional display-only field
- `email`: optional display-only field
- `display_name`: optional display-only field

## 2. Subject Key and Tenant Naming

### 2.1 Subject Key Derivation

The path-safe subject key is derived as:

```text
subject_key = "u-" + hex(sha256(subject_sub))[0:16]
```

Example:

```text
subject_sub = "authentik|1234567890"
subject_key = "u-3f8d2a1c7e9014ab"
```

Rules:

- the derivation must be deterministic
- the same `sub` must always produce the same `subject_key`
- the key must be lowercase ASCII
- the key must be safe for Coolify resource names, Docker DNS labels, and secret paths

### 2.2 Tenant Instance Naming

Canonical tenant instance name:

```text
tenant_instance_name = "mcp-" + service_id + "-" + subject_key
```

Examples:

- `mcp-mealie-u-3f8d2a1c7e9014ab`
- `mcp-actualbudget-u-3f8d2a1c7e9014ab`
- `mcp-memory-u-3f8d2a1c7e9014ab`

Rules:

- `service_id` must already be normalized to lowercase ASCII with hyphens
- `tenant_instance_name` is the canonical name for Coolify tenant resources
- the internal upstream DNS hostname should be the same logical name wherever the runtime allows it

## 3. Secret Path Contract

### 3.1 Platform Secret Paths

Platform-scoped secrets live under:

```text
/platform/mcp-edge/*
/platform/mcp-control-plane/*
```

Minimum reserved paths:

- `/platform/mcp-edge/session-encryption-key`
- `/platform/mcp-edge/authentik-client-secret`
- `/platform/mcp-control-plane/authentik-client-secret`
- `/platform/mcp-control-plane/coolify-api-token`
- `/platform/mcp-control-plane/infisical-machine-client-secret`

### 3.2 Tenant Secret Paths

Tenant-scoped secrets live under:

```text
/subjects/<subject_key>/services/<service_id>/*
```

Examples:

- `/subjects/u-3f8d2a1c7e9014ab/services/mealie/api-token`
- `/subjects/u-3f8d2a1c7e9014ab/services/actualbudget/access-token`
- `/subjects/u-3f8d2a1c7e9014ab/services/memory/libsql-auth-token`

Rules:

- Infisical paths must use `subject_key`, not raw `sub`
- raw `sub` stays canonical in the database
- secret path names must be stable across reconciler runs
- service-specific secret keys are defined by the service catalog

## 4. Environment Configuration Contract

### 4.1 Shared Runtime

These environment variables are shared across binaries where relevant:

- `MCP_PLATFORM_ENV`
- `MCP_PLATFORM_LOG_LEVEL`
- `MCP_PLATFORM_DATABASE_URL`

### 4.2 Edge Runtime

`mcp-edge` configuration:

- `MCP_EDGE_HTTP_BIND_ADDR`
- `MCP_EDGE_PUBLIC_BASE_URL`
- `MCP_EDGE_AUTHENTIK_ISSUER_URL`
- `MCP_EDGE_AUTHENTIK_CLIENT_ID`
- `MCP_EDGE_AUTHENTIK_CLIENT_SECRET_PATH`
- `MCP_EDGE_SESSION_ENCRYPTION_KEY_PATH`
- `MCP_EDGE_COOKIE_SECURE`

### 4.3 Control Plane Runtime

`mcp-control-plane` configuration:

- `MCP_CONTROL_PLANE_HTTP_BIND_ADDR`
- `MCP_CONTROL_PLANE_RECONCILE_INTERVAL`
- `MCP_CONTROL_PLANE_HEALTHCHECK_INTERVAL`
- `MCP_CONTROL_PLANE_AUTHENTIK_ISSUER_URL`
- `MCP_CONTROL_PLANE_AUTHENTIK_CLIENT_ID`
- `MCP_CONTROL_PLANE_AUTHENTIK_CLIENT_SECRET_PATH`
- `MCP_CONTROL_PLANE_COOLIFY_API_BASE_URL`
- `MCP_CONTROL_PLANE_COOLIFY_API_TOKEN_PATH`
- `MCP_CONTROL_PLANE_COOLIFY_PROJECT_UUID`
- `MCP_CONTROL_PLANE_COOLIFY_ENVIRONMENT_NAME` or `MCP_CONTROL_PLANE_COOLIFY_ENVIRONMENT_UUID`
- `MCP_CONTROL_PLANE_COOLIFY_SERVER_UUID`
- `MCP_CONTROL_PLANE_COOLIFY_DESTINATION_UUID`
- `MCP_CONTROL_PLANE_INFISICAL_API_BASE_URL`
- `MCP_CONTROL_PLANE_INFISICAL_PROJECT_SLUG`
- `MCP_CONTROL_PLANE_INFISICAL_ENV_SLUG`
- `MCP_CONTROL_PLANE_INFISICAL_MACHINE_CLIENT_ID`
- `MCP_CONTROL_PLANE_INFISICAL_MACHINE_CLIENT_SECRET_PATH`
- `MCP_CONTROL_PLANE_MEALIE_BASE_URL`
- `MCP_CONTROL_PLANE_ACTUAL_SERVER_URL`
- `MCP_CONTROL_PLANE_TENANT_IMAGE_MEALIE` (optional override)
- `MCP_CONTROL_PLANE_TENANT_IMAGE_ACTUALBUDGET` (optional override)
- `MCP_CONTROL_PLANE_TENANT_IMAGE_MEMORY` (optional override)

Rules:

- secrets are never stored directly in env var values when a secret path contract exists
- env vars carry stable config and secret references
- secret material is resolved at runtime through Infisical
- if tenant runtime is enabled, the control plane must run on the shared `coolify` Docker network so internal tenant health probes can resolve `<tenant-instance-name>:<port>`
- if tenant runtime is enabled, service render prerequisites must be present before startup: `MCP_CONTROL_PLANE_MEALIE_BASE_URL` for Mealie tenants and `MCP_CONTROL_PLANE_ACTUAL_SERVER_URL` for Actual Budget tenants

## 5. Tenant State Model

### 5.1 Desired State

Desired state is a control-plane intent field:

- `enabled`
- `disabled`
- `deleted`

### 5.2 Runtime State

Runtime state is the reconciler-observed lifecycle field:

- `provisioning`
- `ready`
- `degraded`
- `disabled`
- `deleting`

### 5.3 Allowed Runtime Transitions

```text
provisioning -> ready
provisioning -> degraded
provisioning -> disabled
provisioning -> deleting
ready -> degraded
ready -> disabled
ready -> deleting
degraded -> ready
degraded -> disabled
degraded -> deleting
disabled -> provisioning
disabled -> deleting
deleting -> terminal removal
```

Rules:

- `disabled` means the tenant exists but is intentionally unavailable
- `degraded` means the tenant should exist but is unhealthy or drifted
- `deleting` is terminal and must only move to removal
- a missing tenant with desired state `enabled` is reconciled as `provisioning`

## 6. Non-Negotiable Implementation Rules

- Never route by username.
- Never derive tenant names from aliases or emails.
- Never store raw secrets in database rows.
- Never use raw `sub` directly as an Infisical path segment.
- Never expose tenant instance names publicly.
