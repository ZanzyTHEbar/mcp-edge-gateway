# Coolify Deployment Templates

This directory contains reusable Docker Compose templates for deploying the MCP Edge Gateway runtime on a Coolify-style Docker host.

The templates are intentionally generic. Configure hostnames, secrets, image names, project identifiers, and deployment policies through environment variables.

## Files

- `../../docker-compose.yaml` — root convenience entrypoint for the combined core stack.
- `mcp-platform-core.compose.yaml` — combined source-build stack.
- `mcp-control-plane.compose.yaml` — control-plane-only source-build service.
- `mcp-edge.compose.yaml` — edge-only source-build service.
- `mcp-platform-core.image.compose.yaml` — combined prebuilt-image stack.
- `mcp-control-plane.image.compose.yaml` — control-plane-only prebuilt-image service.
- `mcp-edge.image.compose.yaml` — edge-only prebuilt-image service.
- `validate-compose.sh` — local validation helper for the Coolify Compose templates.

## Source modes

### Source-build mode

Use the `*.compose.yaml` files when the deployment platform can build from this repository.

Coolify runs source-build templates with the repository root as the Compose project directory, so the root Dockerfiles and Go source tree are available to the build. Source-build templates set their build contexts to `.` and rely on that project directory; local validation should model Coolify with `--project-directory <repo-root>` rather than assuming `docker compose -f deploy/coolify/<file>.compose.yaml ...` alone is sufficient.

### Prebuilt-image mode

Use the `*.image.compose.yaml` files when images are built elsewhere and pulled by the deployment platform.

In this mode, set:

- `MCP_INFISICAL_BRIDGE_IMAGE`
- `MCP_CONTROL_PLANE_IMAGE`
- `MCP_EDGE_IMAGE`

## Validation

Before deploying or changing these templates, run:

```sh
deploy/coolify/validate-compose.sh
```

The script resolves the repository root from its own location, supplies non-secret dummy values for required Compose interpolation, and runs `docker compose --project-directory <repo-root> config --quiet` against all Coolify source-build and prebuilt-image templates. It also checks that every source-build service renders a repository-root build context with the expected root Dockerfile. This validation requires the Docker Compose CLI and `python3`; it does not start containers or require a live Docker daemon.

## Required configuration

Use these files as templates:

- `../../control-plane.env.example`
- `../../edge.env.example`

At minimum, configure:

- the public edge base URL,
- identity-provider issuer and client IDs,
- secret-store connection details,
- infrastructure API endpoint and project identifiers,
- tenant runtime image mode and image tags.

## Secret files

The Coolify templates mount runtime secrets from hard-coded bind sources under `/data/coolify/mcp-platform-secrets`, which is visible to Coolify's deployment build container on standard installations. `MCP_SECRETS_DIR` is still passed to service processes for runtime configuration, but changing it does not change these Coolify host bind sources. The root `docker-compose.yaml` remains configurable with `MCP_SECRETS_DIR` for non-Coolify deployments.

The templates pass `MCP_DOCKER_NETWORK` into service environment blocks. Some deployment platforms only expose variables to Compose interpolation when they appear in a service environment, even if the variables are also used elsewhere.

Expected files:

Place these files under `/data/coolify/mcp-platform-secrets` on the Coolify host.

- `mcp-control-plane-infisical-machine-client-secret`
- `mcp-edge-authentik-client-secret`
- `mcp-edge-operator-token`
- `mcp-edge-session-encryption-key`

Secret values must be supplied by your deployment process. Do not commit secret values or environment-specific secret paths to this repository.

## Database volume

`MCP_PLATFORM_DATABASE_URL` defaults to:

```text
file:/data/mcp-platform/mcp-platform.db
```

Both core services mount the shared `mcp-platform-data` volume at `/data/mcp-platform`. The edge-only templates bind-mount `/data/coolify/mcp-platform-data` so a separately deployed edge app can share the control-plane SQLite database without depending on deployment-platform volume renaming behavior.

Before deploying edge, verify `/data/coolify/mcp-platform-data` on the deployment host resolves to the live control-plane SQLite data directory, contains `mcp-platform.db`, and is owned or writable by the distroless nonroot UID/GID `65532` used by the runtime image. Safe host-side checks that do not print secrets:

```sh
CONTROL_PLANE_SQLITE_DATA_DIR=/path/to/live/control-plane/sqlite-dir
sudo test -d /data/coolify/mcp-platform-data
test "$(sudo realpath /data/coolify/mcp-platform-data)" = "$(sudo realpath "$CONTROL_PLANE_SQLITE_DATA_DIR")"
sudo test -f /data/coolify/mcp-platform-data/mcp-platform.db
sudo ls -ldn /data/coolify/mcp-platform-data
sudo stat -c '%u:%g %a %n' /data/coolify/mcp-platform-data /data/coolify/mcp-platform-data/mcp-platform.db
sudo -u '#65532' -g '#65532' test -r /data/coolify/mcp-platform-data/mcp-platform.db
sudo -u '#65532' -g '#65532' test -w /data/coolify/mcp-platform-data
```

If your platform preserves external named volumes across separate applications, you may adapt the template to use that volume, but verify both applications resolve to the same storage before deploying edge.

Set `MCP_DOCKER_NETWORK` if your external Docker network is not named `coolify`. The control plane also uses this value when it renders tenant workload compose files, so the core stack and tenant services stay on the same external network.

## Tenant image mode

`MCP_CONTROL_PLANE_TENANT_IMAGE_MODE` controls validation for tenant runtime images:

- `local` — image tags must already exist on the Docker host.
- `pinned` — image references must use immutable `@sha256:<64 hex>` digests.

Use `local` for host-local builds. Use `pinned` when images are published to a registry and you want digest enforcement.

For registry-backed production deployments, prefer `pinned`.

## Deployment order

For separate applications:

1. create or attach the shared database volume,
2. deploy `mcp-control-plane`,
3. verify migrations and readiness,
4. deploy `mcp-edge`,
5. verify public metadata and protected routing.

For the combined stack, the compose file models the edge dependency on a healthy control plane.

## Post-deploy checks

After the deployment platform reports healthy containers:

1. `mcp-control-plane` responds on `/health/live`.
2. `mcp-control-plane` reports readiness on `/health/ready`; readiness is the deploy gate.
3. The SQLite database file exists under `/data/mcp-platform`.
4. `mcp-edge` responds on `/health/live`.
5. `mcp-edge` reports readiness on `/health/ready`; readiness is the deploy gate.
6. `mcp-edge` publishes OAuth authorization-server metadata.
7. `mcp-edge` publishes OAuth protected-resource metadata.
8. Only the edge service is publicly exposed.

Keep live rollout procedures and environment identifiers in a private operations repository.
