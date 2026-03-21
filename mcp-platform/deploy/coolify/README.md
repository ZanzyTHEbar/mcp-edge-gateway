# Coolify Deployment Artifacts

This directory contains the deployment artifacts for the MCP platform core services:

- `mcp-platform-db`
- `mcp-control-plane`
- `mcp-edge`

## Files

- `../../docker-compose.yaml`
  - root convenience entrypoint for public-repo Coolify imports; mirrors the combined core stack
- `mcp-platform-core.compose.yaml`
  - preferred import path for a single Coolify-managed core stack
- `mcp-platform-db.compose.yaml`
  - database-only deployment definition
- `mcp-control-plane.compose.yaml`
  - control-plane-only deployment definition
- `mcp-edge.compose.yaml`
  - edge-only deployment definition
- `mcp-platform-core.image.compose.yaml`
  - registry-image variant of the combined core stack
- `mcp-control-plane.image.compose.yaml`
  - registry-image variant of the control-plane service
- `mcp-edge.image.compose.yaml`
  - registry-image variant of the edge service
## Recommended Import Mode

Prefer the repository-root `docker-compose.yaml` when importing this repository into Coolify as a public repo-backed application.

Use `mcp-platform-core.compose.yaml` when you want the explicit deployment artifact path instead of the root convenience file.

That keeps the platform database, control plane, and edge in one discoverable core stack while still allowing the control plane to create per-tenant Coolify services dynamically.

Use the per-service compose files only if you intentionally want separate Coolify applications for the core services.

## Source Modes

Two deployment source modes are supported:

### 1. Repo-backed build mode

Use:

- `mcp-platform-core.compose.yaml`
- `mcp-control-plane.compose.yaml`
- `mcp-edge.compose.yaml`

This mode requires Coolify to have repository access so it can build from the repo-relative Dockerfile contexts.

### 2. Registry-image mode

Use:

- `mcp-platform-core.image.compose.yaml`
- `mcp-control-plane.image.compose.yaml`
- `mcp-edge.image.compose.yaml`

This mode requires prebuilt images in a registry reachable by Coolify.

If the runtime source is not currently available to Coolify as a git repository, registry-image mode is the correct deployment path.

Keep environment-specific rollout procedures, live hostnames, and operational identifiers in a private operations repository instead of this public runtime source tree.

## Runtime Assumptions

- the shared external Docker network is named `coolify`
- `mcp-control-plane` is attached to that network so tenant DNS names resolve during health probes
- `mcp-platform-db` is internal-only and must not receive a public domain
- `mcp-control-plane` is internal-only and must not receive a public domain
- `mcp-edge` is the only core service that should receive the public MCP domain
- PostgreSQL schema migrations are applied by `mcp-control-plane` on startup

## Required Coolify Configuration

Use these files as the operator source templates for environment values:

- `../../edge.env.example`
- `../../control-plane.env.example`
- `../../platform-db.env.example`

### Required Secret Paths

These compose files intentionally do not hard-code host bind mounts for secrets.

These DragonServer deployment artifacts expect the materialized secret files to exist under `/data/coolify/mcp-platform-secrets` on the target resource server before the first real deploy.

`mcp-platform-db`

- `/data/coolify/mcp-platform-secrets/mcp-platform-db-password`

`mcp-control-plane`

- `/data/coolify/mcp-platform-secrets/mcp-control-plane-infisical-machine-client-secret`

`mcp-edge`

- `/data/coolify/mcp-platform-secrets/mcp-edge-authentik-client-secret`
- `/data/coolify/mcp-platform-secrets/mcp-edge-operator-token`
- `/data/coolify/mcp-platform-secrets/mcp-edge-session-encryption-key`

## Secret Source of Truth

Infisical remains the canonical secret store.

The control plane can resolve Infisical path references directly for its platform-scoped secrets.

`mcp-edge` currently expects file-backed secrets, so those edge secrets must be materialized into Coolify-managed file mounts from the canonical Infisical values before rollout.

## Database URL Note

`MCP_PLATFORM_DATABASE_URL` is still a direct runtime environment variable for `mcp-edge` and `mcp-control-plane`.

That means the database password must exist in two deployment surfaces:

- as the PostgreSQL password file mounted from `/data/coolify/mcp-platform-secrets/mcp-platform-db-password`
- as the password embedded inside `MCP_PLATFORM_DATABASE_URL` for the application services

Keep those values synchronized from the same source secret.

## Deployment Order

For separate service imports, deploy in this order:

1. `mcp-platform-db`
2. `mcp-control-plane`
3. `mcp-edge`

For the combined core stack, the compose file already models the database dependency order.

## Post-Deploy Validation

After Coolify reports the services healthy enough to stay running:

1. verify `mcp-platform-db` is reachable from `mcp-control-plane`
2. verify `mcp-control-plane` returns `200` on `/health/live`
3. verify `mcp-control-plane` exposes expected readiness state on `/health/ready`
4. verify `mcp-edge` returns `200` on `/health/live`
5. verify `mcp-edge` publishes OAuth metadata and protected-resource metadata from the public domain
6. verify no public domain is assigned to `mcp-platform-db` or `mcp-control-plane`
