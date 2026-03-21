# Actual Budget MCP — source lineage audit

Status: Closed (verified 2026-03-21)  
Scope: `actualbudget-mcp` on `cool-res`, image `actual-mcp-server`

## Canonical upstream

- **Repository:** https://github.com/ZanzyTHEbar/actual-mcp-server  
- **npm package:** `actual-mcp-server` (see upstream `package.json`)  
- **Pinned Actual API:** `@actual-app/api@26.3.0` (matches live container and upstream `main` at time of audit)

## Verified facts (cool-res)

| Item | Value |
|------|--------|
| Coolify resource (label) | `actualbudget-mcp` |
| Container name | `mcp-server-prod-s80o4ckcsccwkc4goggcoooc-190217443925` |
| Image reference | `actual-mcp-server:latest` |
| Additional local tag | `actual-mcp-server:api-26.3.0-20260321` |
| Image ID | `sha256:eb2df3f47f730784b349197f87d98432172a18407d4e0a196e6bb9971a19e889` |
| `RepoDigests` | *(empty on host — image not tied to a registry digest in local metadata)* |
| OCI source labels | *None* (only `coolify.resourceName` observed) |
| Container `/app/package.json` | `name: actual-mcp-server`, `version: 0.4.8`, `@actual-app/api: 26.3.0` |
| Entrypoint / command | `docker-entrypoint.sh` → `node dist/src/index.js ${MCP_TRANSPORT_MODE:---http}` |
| Working directory | `/app` |

## Distinguish from `actual-http-api`

The stack in `dragonserver/actual-budget-ux/docker-compose.yml` uses **`jhonderson/actual-http-api:26.3.0`**. That is a **separate** REST bridge for sync/UX, not the MCP server. The **`26.3.0`** version aligns with the same Actual ecosystem line as `@actual-app/api@26.3.0` but the **images and roles differ**.

## Suggested location in version control

- **Primary:** Track and build from **`ZanzyTHEbar/actual-mcp-server`** (same pattern as `ZanzyTHEbar/mealie-mcp`).  
- **Optional monorepo mirror:** If vendoring alongside DragonServer, mirror the Mealie layout with something like **`actualbudget/actual-mcp`** at the dragonserver project root (no subtree exists in this repo yet).

## Registry contract (control plane)

Example image reference used in platform docs: `ghcr.io/zanzythebar/actual-mcp-server:latest` (`mcp-platform/control-plane.env.example`). Ensure Coolify/build pipelines push **immutable tags or digests** and add **OCI annotations** (`org.opencontainers.image.source`, `revision`) on the next image build so future audits do not require `docker exec`.

## Re-verification commands (read-only)

```bash
# Container and image
ssh -o BatchMode=yes cool-res \
  "docker ps -a --format '{{.Names}}\t{{.Image}}' | grep -i mcp-server-prod"

ssh -o BatchMode=yes cool-res \
  "docker inspect mcp-server-prod-s80o4ckcsccwkc4goggcoooc-190217443925 --format '{{.Image}}'"

ssh -o BatchMode=yes cool-res \
  "docker image inspect actual-mcp-server:latest --format '{{.Id}}'"

# Package versions inside runtime
ssh -o BatchMode=yes cool-res \
  'docker exec mcp-server-prod-s80o4ckcsccwkc4goggcoooc-190217443925 \
    node -e "const p=require(\"/app/package.json\"); console.log(p.version, p.dependencies[\"@actual-app/api\"])"'

# Public edge behavior (expect 400 JSON-RPC without session)
curl -skS -o /dev/null -w "%{http_code}\n" "https://actualmcp.dragonnet.lan/http"
```

## Regression result (2026-03-21)

- `GET https://actualmcp.dragonnet.lan/http` returned **400** from the audit environment (consistent with live MCP endpoint, not a connection failure).
