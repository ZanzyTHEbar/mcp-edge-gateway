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
- `docker_compose_location`: `/deploy/coolify/mcp-platform-core.compose.yaml` for the core stack

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

- `/run/secrets/mcp-platform-db-password`
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

1. Create and push the public runtime-only repository.
2. Point the new Coolify core stack at that public repository.
3. Deploy `mcp-platform-db`.
4. Deploy `mcp-control-plane` and validate migrations plus canary reconcile behavior.
5. Deploy `mcp-edge` and validate OAuth metadata plus protected routing.
6. Cut over the public MCP domain only after end-to-end canary validation succeeds.
