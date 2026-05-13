# MCP Registration, Client Use, and RBAC

This document describes the current MCP Edge Gateway operating contract. It is deployment-neutral; replace example domains, client IDs, and tokens with values from your own environment.

## Registering MCP Services

MCP services are registered in the shared `service_catalog` table. The control plane seeds builtin services from `internal/catalog/service.go`, and operators can add or update dynamic services through the control-plane admin API.

Each `ServiceCatalogEntry` defines the service ID, public edge path, upstream container shape, transport behavior, health path, adapter requirement, and required secrets.

Current builtin services:

| Service ID | Public MCP URL | Scope | Upstream path |
|---|---|---|---|
| `mealie` | `https://<edge-domain>/mealie/mcp` | `mcp:mealie` | `/mcp` |
| `actualbudget` | `https://<edge-domain>/actualbudget/mcp` | `mcp:actualbudget` | `/http` |
| `memory` | `https://<edge-domain>/memory/mcp` | `mcp:memory` | `/sse` |

Operator workflow for adding a dynamic MCP service:

1. Configure `MCP_CONTROL_PLANE_ADMIN_TOKEN_PATH` on `mcp-control-plane` with a local file containing the admin bearer token. Leave it unset to disable the admin API.
2. Call `PUT /v1/services/<serviceID>` on the internal control-plane service with `Authorization: Bearer <admin-token>`.
3. Add Authentik group grants for users that should receive the service. The grant group remains `mcp-service-<serviceID>`.
4. Let the control plane reconcile grants into `tenant_instances` and provision ready upstreams when tenant runtime support exists for that service.
5. Wait for `mcp-edge` catalog refresh, or restart `mcp-edge`, then verify the service path and scope are published.

Example admin service registration request:

```sh
curl -fsS http://mcp-control-plane:8081/v1/services/example \
  -X PUT \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "display_name": "Example MCP",
    "upstream_service_name": "example-mcp",
    "transport_type": "streamable-http",
    "internal_port": 8080,
    "public_path": "/example/mcp",
    "internal_upstream_path": "/mcp",
    "health_path": "/health",
    "health_probe_expectation": "GET returns OK",
    "resource_profile": "small",
    "persistence_policy": "stateless",
    "adapter_requirement": "none",
    "secret_contract": [{"Key":"api-token","Required":true}]
  }'
```

Admin API endpoints:

| Method | Path | Effect |
|---|---|---|
| `GET` | `/v1/services` | Lists catalog entries. |
| `PUT` | `/v1/services/<serviceID>` | Creates or replaces one admin-managed service catalog entry. |
| `DELETE` | `/v1/services/<serviceID>` | Disables one catalog entry without deleting historical data. |

Operator workflow for adding or changing a builtin MCP service:

1. Add a `ServiceCatalogEntry` in `internal/catalog/service.go`.
2. Add tenant runtime support in `internal/controlplane/tenant_runtime.go` if the service needs per-subject provisioning.
3. Add required secret contract entries so the control plane can resolve runtime secrets.
4. Deploy or restart `mcp-control-plane`; startup seeds `service_catalog` through `Store.SeedServiceCatalog`.
5. Add Authentik group grants for users that should receive the service.
6. Let the control plane reconcile grants into `tenant_instances` and provision ready upstreams.
7. Deploy or restart `mcp-edge`, or wait for catalog refresh, then verify the service path and scope are published.

Catalog lifecycle details:

- `service_catalog.service_id` is the durable service key.
- `service_catalog.public_path` is unique and becomes the edge route prefix.
- Startup upserts builtin entries and disables stale builtin rows missing from `DefaultCatalogV1()`.
- Admin-registered rows are not disabled by builtin catalog seeding and survive control-plane restarts.
- Removing a builtin service from code disables it; deleting an admin service through the API disables it. Neither path hard-deletes historical data.
- The control-plane admin API is internal-only by deployment convention. Do not expose `mcp-control-plane` publicly.

## Using MCPs From Clients

Clients connect to MCP service URLs on the edge, not to internal tenant containers.

Use the edge OAuth metadata endpoints for discovery:

- `GET https://<edge-domain>/`
- `GET https://<edge-domain>/.well-known/oauth-authorization-server`
- `GET https://<edge-domain>/.well-known/openid-configuration`
- `GET https://<edge-domain>/.well-known/oauth-protected-resource`
- `GET https://<edge-domain>/.well-known/oauth-protected-resource/<serviceID>`

The root endpoint returns a small JSON index with service paths, scopes, health URLs, and OAuth endpoint links. MCP clients should still use the per-service MCP URLs, not `/`.

Client setup flow:

1. Register the client with `POST /oauth/register` using the edge operator bearer token, or enable public DCR with `MCP_EDGE_DCR_ENABLED=true` for unmanaged MCP clients.
2. Store the returned `client_id` and optional `client_secret`.
3. Start authorization-code + PKCE (`S256`) against `/oauth/authorize`.
4. Request exactly one service scope, such as `mcp:mealie`, and include the matching RFC 8707 `resource`, such as `https://<edge-domain>/mealie/mcp`.
5. Exchange the authorization code at `/oauth/token` with the same `resource` value.
6. Call the MCP service URL with `Authorization: Bearer <edge-issued-access-token>`.

If `MCP_EDGE_CIMD_ENABLED=true`, the edge also accepts HTTPS Client ID Metadata Document URLs as `client_id` values and registers the public client metadata on first authorization.

CORS is disabled unless `MCP_EDGE_CORS_ALLOWED_ORIGINS` is set. Use a comma-separated allowlist for browser-based clients, or `*` only when bearer-token exposure to any browser origin is acceptable for your deployment.

Example dynamic client registration request:

```sh
curl -fsS https://<edge-domain>/oauth/register \
  -H 'Authorization: Bearer <operator-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "example-mcp-client",
    "redirect_uris": ["http://127.0.0.1:33418/oauth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "scope": "mcp:mealie"
  }'
```

Example authorize URL parameters include:

```text
response_type=code
client_id=<client-id>
redirect_uri=<registered-redirect-uri>
scope=mcp:mealie
resource=https://<edge-domain>/mealie/mcp
code_challenge=<S256-challenge>
code_challenge_method=S256
```

Example MCP client server entry after OAuth is complete:

```json
{
  "mcpServers": {
    "mealie": {
      "url": "https://<edge-domain>/mealie/mcp",
      "headers": {
        "Authorization": "Bearer <edge-issued-access-token>"
      }
    }
  }
}
```

Important client-auth facts:

- The edge issues local opaque OAuth tokens for MCP service access.
- Edge-issued tokens are bound to one canonical MCP resource URL and cannot be replayed across service paths.
- Upgrading from pre-resource-binding releases requires clients to complete OAuth again; old tokens intentionally do not gain a compatibility fallback.
- Authentik is used for browser login and group synchronization, but Authentik access JWTs are not accepted directly at MCP service paths.
- The edge strips `Authorization` and `Cookie` before proxying to tenant MCP services.
- Upstream MCP services do not receive end-user claims or Authentik tokens by default.

## Authentik RBAC

RBAC is currently group-name based and persisted as service grants in SQLite.

Control-plane Authentik sync maps groups to service grants:

| Authentik group | Effect |
|---|---|
| `mcp-admin` | Grants every supported MCP service. |
| `mcp-service-<serviceID>` | Grants one service. |

Examples:

- `mcp-service-mealie` grants `mealie`.
- `mcp-service-actualbudget` grants `actualbudget`.
- `mcp-service-memory` grants `memory`.

Authorization at the edge requires all of the following:

1. The bearer token is valid and edge-issued.
2. The token scope includes the target service scope, for example `mcp:mealie`.
3. `service_grants` currently grants the token subject that service.
4. The subject's tenant instance for that service is enabled, ready, and has an upstream URL.

Arbitrary Authentik claims are not evaluated live today. If claim-driven policy is needed later, prefer a small configurable group mapping first; do not add a full policy language until there is a concrete operational requirement.

## Subject Identity Alignment

The control plane and edge must agree on `subject_sub`.

- Edge login uses the OIDC ID token `sub` claim.
- Control-plane Authentik sync prefers `user.attributes.sub`, then `user.uid`, then `authentik|<pk>`.

For reliable RBAC, configure Authentik API users so `attributes.sub` matches the OIDC `sub` seen by the edge. If these values differ, grants can be written for one subject while the logged-in user receives tokens for another subject, causing authorization failures.

## Useful Verification

After deployment, verify public metadata and readiness:

```sh
curl -fsS https://<edge-domain>/
curl -fsS https://<edge-domain>/health/ready
curl -fsS https://<edge-domain>/.well-known/oauth-authorization-server
curl -fsS https://<edge-domain>/.well-known/openid-configuration
curl -fsS https://<edge-domain>/.well-known/oauth-protected-resource
curl -fsS https://<edge-domain>/.well-known/oauth-protected-resource/mealie
```

For RBAC validation:

1. Add a test user to `mcp-service-mealie` only.
2. Run or wait for control-plane reconciliation.
3. Complete OAuth login and request `mcp:mealie`.
4. Confirm `/mealie/mcp` is allowed after the tenant is ready.
5. Confirm `/actualbudget/mcp` is denied unless the user also has that grant.
