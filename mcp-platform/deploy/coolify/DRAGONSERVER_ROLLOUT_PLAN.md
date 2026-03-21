# DragonServer MCP Platform Rollout Plan

This document is the controlled live-mutation plan for introducing the MCP platform core services on DragonServer.

It assumes the code, Dockerfiles, env examples, and Coolify compose definitions under this repository are the deployment source of truth.

## Scope

This rollout covers the core platform services only:

- `mcp-platform-db`
- `mcp-control-plane`
- `mcp-edge`

It does not include broad service-catalog expansion beyond the day-one services:

- `mealie`
- `actualbudget`
- `memory`

## Deployment Source Mode

Choose one source mode before the window:

1. repo-backed Coolify build mode using the `*.compose.yaml` files
2. registry-image mode using the `*.image.compose.yaml` files

If Coolify cannot access this runtime source as a git repository, registry-image mode is mandatory.

## Current Known Preconditions

These statements must be true before the mutation window starts:

- existing direct public MCP routes still exist and remain the rollback target
- `mcp-edge` is not yet live on the public MCP domain
- `mcp-control-plane` is not yet deployed
- Infisical is not yet deployed on `cool-res`
- Authentik remains the identity provider and entitlement source
- Coolify is the only allowed control surface for core platform deployment and tenant runtime placement

## Go / No-Go Gates

Do not proceed past a stage when its validation gate fails.

The rollout is intentionally staged so rollback is cheap before the public-domain cutover.

## Stage 0: Freeze Inputs

1. Freeze the commit SHA to deploy for `mcp-platform`.
2. Freeze the deployment source mode: repo-backed build or registry-image rollout.
3. If using registry-image mode, freeze the exact immutable image references for:
   - `mcp-edge`
   - `mcp-control-plane`
4. Freeze the final public MCP domain value for `mcp-edge`.
5. Freeze the Coolify target project, environment, server UUID, and destination UUID.
6. Record the existing public MCP routes that must remain available for rollback.

Validation gate:

- one exact repository SHA is chosen for the window
- one exact deployment source mode is chosen
- all required Coolify identifiers are known
- the old public routes are documented and reversible

## Stage 1: Secret and Identity Prerequisites

1. Deploy Infisical on DragonServer if it is still absent.
2. Create or verify the platform secret paths:
   - `/platform/mcp-edge/session-encryption-key`
   - `/platform/mcp-edge/authentik-client-secret`
   - `/platform/mcp-control-plane/authentik-client-secret`
   - `/platform/mcp-control-plane/coolify-api-token`
   - `/platform/mcp-control-plane/infisical-machine-client-secret`
3. Create or verify the Authentik applications/providers for:
   - `mcp-edge`
   - `mcp-control-plane`
4. Create or verify the Authentik entitlement groups that map to the day-one service catalog.
5. Materialize Coolify file mounts for secrets that are file-backed at runtime:
   - `mcp-platform-db` password file
   - `mcp-control-plane` Infisical machine client secret file
   - `mcp-edge` Authentik client secret file
   - `mcp-edge` operator token file
   - `mcp-edge` session encryption key file

Validation gate:

- Infisical is reachable from `cool-res`
- required platform secrets exist
- Authentik providers/apps/groups exist
- all required file mounts are prepared in Coolify or are ready to be attached during service creation

## Stage 2: Deploy `mcp-platform-db`

1. Import `deploy/coolify/mcp-platform-db.compose.yaml` or the combined core stack into Coolify.
2. Apply the database env values using `platform-db.env.example` as the template.
3. Attach the database password file mount at `/run/secrets/mcp-platform-db-password`.
4. Deploy the service on the shared `coolify` network.
5. Do not assign a public domain.

Validation gate:

- container stays running
- PostgreSQL healthcheck is healthy
- persistent volume is attached
- the service is reachable from the `coolify` network as `mcp-platform-db:5432`

Rollback:

- if deployment fails before health is green, remove the failed service and keep the volume only if the database was initialized successfully
- do not proceed to application deployment until the database is stable

## Stage 3: Deploy `mcp-control-plane` Internally

1. Import the control-plane service using the compose file that matches the chosen source mode.
2. Apply env values using `control-plane.env.example`.
3. Set `MCP_PLATFORM_DATABASE_URL` to the live database connection string.
4. Attach the Infisical machine client secret file mount at `/run/secrets/mcp-control-plane-infisical-machine-client-secret`.
5. Ensure the service is attached to the shared `coolify` network.
6. Do not assign a public domain.

Validation gate:

- the service stays running
- `/health/live` returns `200`
- `/health/ready` returns either `200` or an expected degraded response with actionable error detail
- startup logs show schema migration completion without lock contention failure
- the control plane can reach PostgreSQL, Authentik, Infisical, and Coolify

Rollback:

- if startup fails, remove the control-plane deployment and leave the database intact
- if degraded readiness is due to dependency misconfiguration, fix the dependency and redeploy before touching the edge

## Stage 4: Internal-Only Reconcile Validation

1. Confirm the control plane can list Authentik subjects/groups successfully.
2. Confirm the service catalog is seeded as expected.
3. Choose one canary user and one canary service grant.
4. Force or wait for a reconcile cycle.
5. Verify the expected `tenant_instances` row appears and reaches a sensible state.
6. If a canary tenant is created, verify the resulting Coolify private service lands on the correct environment/server/destination.

Validation gate:

- no wrong-tenant naming or routing data is observed
- canary tenant creation/disable/delete behavior matches the desired state model
- no unexpected tenants are created

Rollback:

- if lifecycle actions are incorrect, stop here
- remove only canary tenant resources created during this stage
- keep the old public MCP routes unchanged

## Stage 5: Deploy `mcp-edge` Without Public Cutover

1. Import the edge service using the compose file that matches the chosen source mode.
2. Apply env values using `edge.env.example`.
3. Set `MCP_PLATFORM_DATABASE_URL` to the live database connection string.
4. Attach the three required file mounts:
   - `/run/secrets/mcp-edge-authentik-client-secret`
   - `/run/secrets/mcp-edge-operator-token`
   - `/run/secrets/mcp-edge-session-encryption-key`
5. Keep the service internal-only for the first validation pass, or expose it only on an operator-only test route if an internal-only probe path is not practical.

Validation gate:

- `/health/live` returns `200`
- `/health/ready` returns `200`
- `/.well-known/oauth-authorization-server` returns `200`
- `/.well-known/oauth-protected-resource` returns `200`
- unauthenticated access to a protected MCP service path is denied

Rollback:

- if edge startup or auth metadata is broken, remove the edge deployment and keep control-plane + DB intact
- do not cut over the public domain until edge validation is clean

## Stage 6: End-to-End Canary Flow

1. Use the canary user with one enabled service grant.
2. Exercise the browser login flow through `mcp-edge`.
3. Verify the edge obtains tokens and resolves the canary tenant via the database-backed resolver.
4. Verify service-specific transport behavior:
   - `actualbudget`: upstream `/http` translation works
   - `memory`: SSE endpoint normalization works
5. Confirm the control plane and edge logs agree on the same subject key and tenant identity.

Validation gate:

- browser auth succeeds
- the token exchange succeeds
- the canary user reaches only the expected tenant
- the selected service behaves correctly through the shared edge

Rollback:

- if canary flow fails, keep the public domain on the legacy direct routes
- remove or disable only the newly deployed edge if needed

## Stage 7: Public Domain Cutover

1. Point the canonical public MCP domain at `mcp-edge`.
2. Keep legacy direct routes available but not preferred during the observation window.
3. Re-run the canary flow over the real public domain.
4. Run one smoke test for each day-one service path:
   - `/mealie/mcp`
   - `/actualbudget/mcp`
   - `/memory/mcp`

Validation gate:

- public MCP domain resolves to `mcp-edge`
- OAuth metadata is reachable on the canonical public domain
- canary auth and service access still succeed after cutover
- no direct tenant endpoints are publicly exposed as part of the cutover

Rollback:

- revert the public domain routing to the old direct MCP routes
- leave the new core services deployed internally for investigation
- do not delete the platform database during rollback

## Stage 8: Post-Cutover Stabilization

1. Monitor control-plane reconcile results and tenant health transitions.
2. Monitor edge auth errors, token failures, and tenant resolution errors.
3. Confirm no unexpected tenant churn occurs.
4. After the observation window, retire the direct public MCP routes.

Validation gate:

- no severity-1 wrong-tenant behavior
- no reconcile loop thrash
- no dependency-auth failures against Authentik, Infisical, or Coolify

## Minimum Smoke Test Set

Run these checks during the window:

1. `mcp-control-plane` `GET /health/live`
2. `mcp-control-plane` `GET /health/ready`
3. `mcp-edge` `GET /health/live`
4. `mcp-edge` `GET /health/ready`
5. `mcp-edge` `GET /.well-known/oauth-authorization-server`
6. `mcp-edge` `GET /.well-known/oauth-protected-resource`
7. unauthenticated request to one protected MCP route returns denial
8. authenticated canary flow reaches exactly one intended tenant
9. one `actualbudget` request through the edge
10. one `memory` request through the edge

## Rollback Principles

- rollback should prefer route reversion before destructive service deletion
- keep the old public MCP routes available until the new edge is proven
- keep the platform database volume unless there is a confirmed need to discard initialization
- do not bulk-delete tenant resources during first-window rollback; remove only known canary artifacts unless a broader cleanup is explicitly required
- treat wrong-tenant routing as an immediate stop-and-revert condition

## Remaining Explicit Blockers Before Scheduling the Window

- Infisical deployment on `cool-res`
- final confirmation of Authentik provider/app/group configuration
- final collection of live Coolify project/environment/server/destination identifiers
- if Coolify cannot build from source, registry publication of the immutable `mcp-edge` and `mcp-control-plane` images
- operator decision on whether first-edge validation is internal-only or uses a temporary operator-only route
