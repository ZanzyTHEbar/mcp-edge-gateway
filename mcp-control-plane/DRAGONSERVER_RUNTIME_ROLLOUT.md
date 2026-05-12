# DragonServer Runtime Rollout

This document stays private.

It is the DragonServer-specific companion to the public MCP runtime repository and captures the live rollout inputs that should not be published with the runtime source tree.

Public runtime repository:

- `https://github.com/ZanzyTHEbar/dragonserver-mcp-platform-runtime`

## Frozen Deployment Targets

- Coolify project UUID: `ooc0csccwws48ko04cck0cso` (`Personal`)
- Coolify environment UUID: `dcsck44k4skgg0400sosk0ok` (`production`)
- Coolify server UUID: `okos4c4o088k4kwo08sgowwo` (`coolifyresources`)
- Coolify destination UUID: `x80wcckgggsw8gg80ck40kg0` (`coolify`)
- Shared Docker network: `coolify`

## Runtime Source Mode

Use the public repo-backed Coolify pattern already proven by existing public applications:

- `build_pack`: `dockercompose`
- `base_directory`: `/`
- `git_commit_sha`: `HEAD` during initial rollout, then freeze to a specific SHA before cutover
- preferred import path in the standalone public runtime repo: `/docker-compose.yaml`
- equivalent repo-relative path in this parent repository checkout: `mcp-platform/docker-compose.yaml`
- explicit artifact path in the standalone public runtime repo: `/deploy/coolify/mcp-platform-core.compose.yaml`
- equivalent repo-relative explicit artifact path in this parent repository checkout: `mcp-platform/deploy/coolify/mcp-platform-core.compose.yaml`

Use separate compose files only when intentionally splitting the core stack into distinct Coolify applications.

## Secret Material Status

Completed:

- Infisical is deployed and reachable
- Infisical project slug `dragonserver` exists
- platform secret paths were created and seeded
- the `mcp-control-plane` machine identity has Universal Auth configured
- Coolify file-backed runtime secrets were materialized on `cool-res`

Current file-backed secret directory on `cool-res`:

- `/data/coolify/mcp-platform-secrets`

Mounted runtime files:

- `/run/secrets/mcp-control-plane-infisical-machine-client-secret`
- `/run/secrets/mcp-edge-authentik-client-secret`
- `/run/secrets/mcp-edge-operator-token`
- `/run/secrets/mcp-edge-session-encryption-key`

## Authentik Notes

- Providers/apps exist for `mcp-edge` and `mcp-control-plane`
- the control-plane client must request `goauthentik.io/api`
- the Authentik service-account user is in `authentik Read-only`
- provider token validity values were repaired to Authentik's expected duration format

## Remaining Execution Order

Completed:

1. Public runtime repository was created and published at `ZanzyTHEbar/dragonserver-mcp-platform-runtime`.
2. The platform persistence layer is SQLite/libSQL and is mounted as a shared core-service volume.
3. `mcp-control-plane` rollout was completed and hardened:
   - native healthchecks are in place
   - the stable internal `infisical-bridge` path is in use
   - internal readiness is verified on the shared `coolify` network

Remaining:

1. Publish the pre-deployment hardening build that includes singleton control-plane leadership and strict readiness signals.
2. Verify `mcp-control-plane` readiness returns `ready` only when `leader=true`, `dependencies_configured=true`, and `tenant_runtime_configured=true`.
3. Seed one canary Authentik service grant and verify control-plane reconcile end to end.
4. Deploy and validate `mcp-edge` live.
5. Validate OAuth metadata, protected-resource metadata, and protected routing through `mcp-edge`.
6. Cut over the public MCP domain only after end-to-end canary validation succeeds.

## Pre-Deployment Safety Contracts

- Run exactly one live `mcp-control-plane` instance. SQLite/libSQL is configured for the single-writer core deployment model.
- Treat `/health/live` as process liveness only.
- Treat `/health/ready` as the deployment gate. The control plane is not ready unless the database is reachable, singleton leadership is held, external dependencies are configured, tenant runtime configuration is complete, and the last reconcile state is healthy.
- Deploy order is `mcp-control-plane` -> `mcp-edge`. `mcp-edge` loads enabled service catalog entries from the SQLite/libSQL database, so the control plane must migrate and seed the catalog before edge startup.
- `memory` remains an SSE upstream internally, but the public edge implements SSE-to-streamable-HTTP bridging.
