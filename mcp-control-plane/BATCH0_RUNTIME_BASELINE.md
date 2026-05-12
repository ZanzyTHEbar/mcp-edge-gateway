# Batch 0 Runtime Baseline

Status: Verified runtime baseline
Date: 2026-03-21
Owner: DragonServer MCP control-plane implementation

This document freezes the live runtime facts collected before implementation work begins.

It converts design-time unknowns into either:

- verified runtime facts, or
- explicit implementation deltas that must be addressed in later batches

This file is an execution artifact for Batch 0 of the implementation handoff.

## 1. Verified MCP Runtime Inventory

| Service | Coolify Resource | Container | Public Host | Local Runtime Contract | Verified Transport | Current Public Exposure | Current Auth Posture | Notes |
|---|---|---|---|---|---|---|---|---|
| `actualbudget` | `actualbudget-mcp` | `mcp-server-prod-s80o4ckcsccwkc4goggcoooc-190217443925` | `actualmcp.dragonnet.lan` | `http://127.0.0.1:3000/http` | Streamable HTTP-style MCP endpoint on `/http` | Public via Traefik on HTTP and HTTPS | No Authentik middleware on MCP router | `GET /http` returns `400` JSON-RPC error `No session id`, proving a live MCP endpoint |
| `mealie` | `mealie-mcp` | `zgogokg008kkggkcowsgks40-191609175511` | `mealie-mcp.dragonnet.lan` | `http://127.0.0.1:3031/mcp` | Streamable HTTP | Public via Traefik on HTTP and HTTPS | No Authentik middleware on MCP router | `GET /mcp` returns discovery JSON and still advertises `X-Mealie-Token` per-user override behavior |
| `memory` | `memory` | `memory-lssgw004scwgss8sg4ogwgs8-180539385299` | `memory.dragonnet.lan` | `http://127.0.0.1:8090/sse` | SSE | Public on HTTP today; HTTPS path behavior is not equivalent | No Authentik middleware on MCP router | `GET /sse` returns `200` with `text/event-stream` and an SSE endpoint event |

## 2. Verified Route and Proxy Behavior

### 2.1 Actual Budget MCP

- Traefik router rule: `Host(\`actualmcp.dragonnet.lan\`) && PathPrefix(\`/\`)`
- Traefik upstream port: `3000`
- HTTP router redirects to HTTPS
- HTTPS router enables gzip middleware
- Public `GET http://actualmcp.dragonnet.lan/http` returns `302` to HTTPS
- Public `GET https://actualmcp.dragonnet.lan/http` reaches the MCP endpoint and returns `400` `No session id`

### 2.2 Mealie MCP

- Traefik router rule: `Host(\`mealie-mcp.dragonnet.lan\`) && PathPrefix(\`/\`)`
- Traefik upstream port: `3031`
- HTTP router redirects to HTTPS
- HTTPS router enables gzip middleware
- Public `GET http://mealie-mcp.dragonnet.lan/mcp` returns `302` to HTTPS
- Public `GET https://mealie-mcp.dragonnet.lan/mcp` returns MCP discovery JSON

### 2.3 Memory MCP

- Traefik router rule: `Host(\`memory.dragonnet.lan\`) && PathPrefix(\`/\`)`
- Traefik upstream port: `8090`
- Current labels show an HTTP router with gzip middleware
- Current labels do not show the same HTTPS redirect/TLS pattern used by `actualbudget` and `mealie`
- Public `GET http://memory.dragonnet.lan/sse` returns a live SSE stream
- Public `HEAD http://memory.dragonnet.lan/sse` returns `405 Method Not Allowed`
- Public `GET https://memory.dragonnet.lan/sse` did not behave as a valid edge contract during audit and must not be treated as the future canonical public model

### 2.4 Shared Proxy Observations

- `coolify-proxy` is Traefik `v3.6.7`
- Proxy config is file-backed under `/data/coolify/proxy/`
- File provider directory exists at `/data/coolify/proxy/dynamic/`
- Current top-level proxy compose does not include streaming-specific route exceptions
- Existing public MCP routes currently use gzip on streaming-relevant routers, which is unsafe for the target shared edge

## 3. Verified MCP-Specific Technical Constraints

### 3.1 Actual Budget

- Public MCP path is `/http`, not `/mcp`
- The runtime image is `actual-mcp-server:latest`
- The image does not expose OCI source labels, so the audited deployment cannot be traced back to a repo from image metadata alone
- The current service is directly exposed on host port `3000`
- **Source lineage (post-audit, 2026-03-21):** `docker exec` on the live container shows `/app/package.json` matches upstream [ZanzyTHEbar/actual-mcp-server](https://github.com/ZanzyTHEbar/actual-mcp-server) at `actual-mcp-server@0.4.8` with `@actual-app/api@26.3.0`. Host image tags include `actual-mcp-server:api-26.3.0-20260321`. Image ID `sha256:eb2df3f47f730784b349197f87d98432172a18407d4e0a196e6bb9971a19e889`. Full evidence and re-verify commands: [ACTUAL_MCP_SOURCE_AUDIT.md](./ACTUAL_MCP_SOURCE_AUDIT.md)

### 3.2 Mealie

- Public MCP path is `/mcp`
- The server returns discovery JSON with:
  - `transport: streamable-http`
  - `endpoint: /mcp`
  - `perUserTokenHeader: X-Mealie-Token`
- Current multi-user model is still shared-server plus per-request token override
- The current service is directly exposed on host port `3031`

### 3.3 Memory

- Public MCP path is `/sse`
- Local `GET /sse` returns:
  - `200 OK`
  - `Content-Type: text/event-stream`
  - `X-Accel-Buffering: no`
  - `event: endpoint`
- `/` and `/health` return `404`
- The image source is `https://github.com/ZanzyTHEbar/mcp-memory-libsql-go`
- The current service is directly exposed on host port `8090`

## 4. Verified Authentik Surface

### 4.1 Applications Present

The following relevant human-facing OIDC applications already exist:

- `actual-budget`
- `mealie`
- `openwebui`
- `coder`
- `opencode`
- `opencloud`
- `joplinsync`
- `ntfy`
- `affine`

### 4.2 Groups Present

Relevant current groups include:

- `budget-admins`
- `budget-services`
- `budget-viewers`
- `mealie-admins`
- `mealie-users`
- `openwebui-users`

### 4.3 Missing MCP Control Plane Auth Constructs

The following target-state groups are not present today:

- `mcp-users`
- `mcp-service-mealie`
- `mcp-service-actualbudget`
- `mcp-service-memory`
- `mcp-admin`

### 4.4 OIDC Provider Posture

- Existing human-facing OAuth2 providers use the default implicit-consent authorization flow
- Existing providers are app-specific and not MCP-edge-specific
- There is no `mcp-edge` Authentik application or provider yet
- There is no evidence that current public MCP routes are protected by Authentik middleware at the Traefik router layer

## 5. Verified Coolify and Host Control Surfaces

### 5.1 What is Present on `cool-res`

- `coolify-proxy` is present and healthy
- `coolify-sentinel` is present and healthy
- `/data/coolify/` contains:
  - `applications/`
  - `proxy/`
  - `sentinel/`
  - `services/`
  - `ssl/`

### 5.2 What is Not Present on `cool-res`

- No Infisical container is deployed
- No Infisical image is present
- No `coolify` CLI binary is installed in the host shell
- No obvious local Coolify application container is present in `docker ps -a`

### 5.3 Operational Consequence

The resource host clearly contains the Coolify-managed deployment filesystem and proxy layer, but the main Coolify control-plane API surface is not locally obvious from the audited shell.

That means:

- live runtime state is hosted and managed through Coolify artifacts
- direct API-base discovery and authenticated API mutation are still unresolved from the host shell alone

This is now an explicit implementation delta, not an untracked unknown.

## 6. Batch 0 Implementation Deltas

These deltas are now frozen and must be addressed explicitly in later batches.

### Delta 1: Shared Edge Route Must Replace Heterogeneous Public MCP Routes

Current state:

- `actualbudget` is public at `/http`
- `mealie` is public at `/mcp`
- `memory` is public at `/sse`

Target state:

- `https://mcp.zacariahheim.com/actualbudget/mcp`
- `https://mcp.zacariahheim.com/mealie/mcp`
- `https://mcp.zacariahheim.com/memory/mcp`

Required response:

- `mcp-edge` must normalize all three services behind the shared public path contract

### Delta 2: Memory Requires Transport Normalization

Current state:

- `memory` is SSE-only on `/sse`

Required response:

- Batch 4 must implement a real normalization strategy for `memory`
- The shared edge must present a uniform MCP-facing contract even if the upstream tenant remains SSE internally

### Delta 3: Actual Budget Requires Path Translation

Current state:

- upstream MCP path is `/http`

Required response:

- the service catalog must record `/http` as the current upstream path
- `mcp-edge` must expose `/actualbudget/mcp` publicly and translate appropriately

### Delta 4: Gzip Must Be Removed from Streaming-Sensitive MCP Routes

Current state:

- `actualbudget`, `mealie`, and current `memory` routes use gzip-related middleware or equivalent compression behavior at the proxy layer

Required response:

- the new shared edge routes must not inherit unsafe streaming compression defaults
- Batch 5 route retirement must remove the old public MCP routes once the new shared edge is validated

### Delta 5: Authentik RBAC Model Must Be Extended for MCP

Current state:

- there are app-specific groups for existing services
- there are no MCP control-plane groups

Required response:

- Batch 3 must introduce MCP-specific grant groups or an equivalent durable entitlement model
- `mcp-control-plane` must sync grant state keyed by `sub`

### Delta 6: Infisical Must Be Introduced Before Secret-Backed Tenant Cutover

Current state:

- Infisical is not deployed on `cool-res`

Required response:

- Batch 3 cannot complete live secret-backed tenant flows until Infisical exists and machine-auth is defined

### Delta 7: Coolify API Access Is Not Yet Operationally Verified

Current state:

- the host filesystem proves Coolify-managed deployment state
- the proxy and sentinel are present
- the CLI is absent
- authenticated API usage was not verified during Batch 0

Required response:

- Batch 3 must validate the live Coolify API endpoint, auth model, and service mutation workflow before tenant reconciliation can be promoted beyond scaffolding

### Delta 8: Mealie Must Move from Shared Header Override to Isolated Tenant Secret Model

Current state:

- `mealie-mcp` still advertises `X-Mealie-Token` as the multi-user override path

Required response:

- Batch 4 must replace that shared-server pattern for production control-plane use with one private backend per `user x service`

## 7. Implementation Directive Resolution

The attached execution handoff contains a conflict:

- one section says to default to TypeScript/Node
- a later binding line states: `Strictly written in Golang following golang best practices.`

This is now resolved for execution as follows:

- New `mcp-edge` and `mcp-control-plane` runtime code must be written in Go
- Existing TypeScript code such as `mealie-mcp` remains reference material and integration surface, not the implementation language for the new platform components

## 8. Batch 0 Review Outcome

### Verified

- The current public MCP estate is heterogeneous and directly exposed
- The current public MCP estate is not centrally protected by Authentik middleware
- `actualbudget` and `mealie` are already live HTTP MCP surfaces
- `memory` is still an SSE surface and is not yet compatible with the target public contract
- Infisical is absent from the current runtime

### Approved to Proceed

Proceed to Batch 1 with the following constraints:

1. Treat this file as the frozen runtime baseline.
2. Scaffold shared contracts against the normalized target contract, not the current public routes.
3. Preserve the upstream deltas in the service catalog instead of hiding them in ad hoc code.
4. Implement new platform code in Go.

### Not Approved Yet for Live Cutover

The following remain blocked for later live-mutation batches:

1. verified Coolify API auth and mutation workflow
2. deployed Infisical instance and machine-auth contract
3. final Pangolin/public route implementation for `mcp.zacariahheim.com`
