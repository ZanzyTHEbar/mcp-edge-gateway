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
| `GET` | `/v1/subjects/<subjectSub>/grants` | Lists effective grants for a subject. |
| `PUT` | `/v1/subjects/<subjectSub>/grants/<serviceID>` | Adds a manual grant source for a subject and service. |
| `DELETE` | `/v1/subjects/<subjectSub>/grants/<serviceID>` | Removes only the manual grant source; Authentik-derived grants remain. |
| `PUT` | `/v1/subjects/<subjectSub>/services/<serviceID>/upstream` | Binds a granted subject/service to an already-running static upstream URL after a health check. |

Static upstream binding is the supported path for self-hosted MCP services that are already running outside the control plane's Coolify provisioning templates. The subject must already have an effective grant for the service, either from Authentik sync or from the manual grants API. The control plane validates that `upstream_url` is `http` or `https`, has no embedded user info, is not a blocked literal or resolved IP address, and returns the expected healthy response at the registered service `health_path` before it marks the tenant `ready`.

`upstream_url` identifies the upstream origin: scheme, host, and port. Catalog paths remain authoritative for routing: health checks use `health_path`, and proxied MCP traffic uses `internal_upstream_path`. Do not rely on a path in `upstream_url` to change where MCP requests are sent.

The static upstream API is an admin-trusted egress capability. It is intended for operator-managed LAN, Docker-network, or otherwise trusted self-hosted MCP targets. Keep `mcp-control-plane` internal-only, protect the admin token, and do not delegate this API to untrusted users. Health checks do not follow redirects. The edge revalidates static upstream hostnames when resolving a tenant, but proxy dialing still performs its own DNS lookup; use literal IP upstream URLs when strict DNS-rebinding resistance is required.

Example static upstream binding request:

```sh
curl -fsS http://mcp-control-plane:8081/v1/subjects/<subjectSub>/services/example/upstream \
  -X PUT \
  -H 'Authorization: Bearer <admin-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "upstream_url": "http://example-mcp:8080"
  }'
```

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

The root endpoint returns a small JSON index with service paths, full MCP URLs, OAuth resource URLs, per-service protected-resource metadata URLs, health URLs, and OAuth endpoint links. MCP clients should still use the per-service MCP URLs, not `/`.

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

### opencode Client Setup

opencode supports remote MCP servers in `opencode.json` under the top-level `mcp` object. For OAuth-capable clients, prefer an OAuth configuration so opencode can discover Protected Resource Metadata, register or use a client, complete PKCE in the browser, and store tokens locally.

Default production constraint: public dynamic client registration is disabled unless `MCP_EDGE_DCR_ENABLED=true`. A no-header OAuth client config works only when public DCR is intentionally enabled or when the client is already registered and the opencode version can use the pre-registered OAuth client metadata. Otherwise, use operator-token DCR outside the client first, then configure the client with its supported static OAuth fields, or use the static-token fallback for troubleshooting.

OAuth-first opencode example:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mealie": {
      "type": "remote",
      "url": "https://<edge-domain>/mealie/mcp",
      "enabled": true
    }
  }
}
```

If automatic OAuth is not available in the installed opencode version, use an operator-issued OAuth token as a temporary static header. Keep this token out of source control and rotate it after testing.

Static-token opencode fallback:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mealie": {
      "type": "remote",
      "url": "https://<edge-domain>/mealie/mcp",
      "enabled": true,
      "oauth": false,
      "headers": {
        "Authorization": "Bearer <edge-issued-access-token>"
      }
    }
  }
}
```

opencode validation checklist:

1. Confirm `GET https://<edge-domain>/mealie/mcp` without a token returns `401` and a `WWW-Authenticate` header with `resource_metadata="https://<edge-domain>/.well-known/oauth-protected-resource/mealie"`.
2. Add the remote server URL to `opencode.json`.
3. Run opencode's MCP auth/connect flow for the server.
4. Confirm the browser login uses Authentik and requests exactly the service scope, for example `mcp:mealie`.
5. Confirm opencode can list tools after the edge token is issued.

### Cursor Client Setup

Cursor uses `mcp.json` with `mcpServers`. For OAuth-capable Cursor versions, configure only the remote service URL and let Cursor use the MCP OAuth discovery flow.

Default production constraint: public dynamic client registration is disabled unless `MCP_EDGE_DCR_ENABLED=true`. The minimal URL-only Cursor config works only when public DCR is intentionally enabled or when Cursor is configured with a pre-registered client.

OAuth-first Cursor example:

```json
{
  "mcpServers": {
    "mealie": {
      "url": "https://<edge-domain>/mealie/mcp"
    }
  }
}
```

If OAuth is not available or needs to be isolated during troubleshooting, use a static bearer token header. Prefer environment interpolation where your Cursor version supports it; otherwise paste only a short-lived test token and rotate it immediately afterward.

Static-token Cursor fallback:

```json
{
  "mcpServers": {
    "mealie": {
      "url": "https://<edge-domain>/mealie/mcp",
      "headers": {
        "Authorization": "Bearer ${env:MCP_EDGE_MEALIE_TOKEN}"
      }
    }
  }
}
```

Pre-registered Cursor OAuth example:

```json
{
  "mcpServers": {
    "mealie": {
      "url": "https://<edge-domain>/mealie/mcp",
      "auth": {
        "CLIENT_ID": "<pre-registered-client-id>",
        "CLIENT_SECRET": "<optional-client-secret>",
        "scopes": ["mcp:mealie"]
      }
    }
  }
}
```

Cursor validation checklist:

1. Add the service URL to `mcp.json`.
2. Open Cursor MCP settings and connect the server.
3. Confirm Cursor opens the browser to the edge authorization flow and Authentik login.
4. Confirm the token exchange includes the same `resource` as the service URL.
5. Confirm the MCP tools become available without adding a raw bearer token to `mcp.json`.

### Desktop OAuth Smoke Flow

Use this flow to test clients that use loopback redirects and PKCE, which is the common desktop-client pattern.

1. Discover the service entry from `GET https://<edge-domain>/` and record `services[].url`, `services[].resource`, `services[].scope`, and `services[].protected_resource_metadata_url`.
2. Register a public client with redirect URI `http://127.0.0.1:<random-port>/oauth/callback` and `token_endpoint_auth_method=none`. In default production, this request must include the edge operator bearer token unless `MCP_EDGE_DCR_ENABLED=true` was intentionally enabled.
3. Start `/oauth/authorize` with `response_type=code`, the registered `client_id`, the loopback `redirect_uri`, service `scope`, matching `resource`, and PKCE `S256` challenge.
4. Complete Authentik login and copy the authorization code from the loopback redirect.
5. Exchange the code at `/oauth/token` with the same `resource`, the same `redirect_uri`, and the PKCE verifier.
6. Call `/oauth/introspect` with the edge operator token and confirm `active=true`, `scope=<service-scope>`, and `resource=<service-url>`.
7. Call the MCP URL with `Authorization: Bearer <access-token>`.

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

## Production Onboarding Runbook

Use this runbook for a new self-hosted MCP service that already runs on a trusted LAN, Docker network, or internal host.

1. Choose a stable `serviceID`, public path, internal upstream path, health path, and transport type.
2. Register the catalog entry with `PUT /v1/services/<serviceID>` on `mcp-control-plane`.
3. Verify `GET /v1/services/<serviceID>` returns `source=admin_api`, `enabled=true`, and the expected paths.
4. Grant the subject through Authentik group `mcp-service-<serviceID>` or `PUT /v1/subjects/<subjectSub>/grants/<serviceID>`.
5. Verify `GET /v1/subjects/<subjectSub>/grants` contains the service.
6. Bind the static upstream with `PUT /v1/subjects/<subjectSub>/services/<serviceID>/upstream`.
7. Verify `mcp-control-plane` reports the tenant as ready and the edge shares the same database state.
8. Verify `GET https://<edge-domain>/` lists the service with `url`, `resource`, and `protected_resource_metadata_url`.
9. Verify `GET https://<edge-domain>/.well-known/oauth-protected-resource/<serviceID>` returns the expected resource URL and scope.
10. Register or connect the opencode/Cursor client using the per-service MCP URL.
11. Complete OAuth and verify the token is bound to the same service `resource`.
12. Confirm the client can list and call tools through the edge.

Production guardrails:

- Keep `mcp-control-plane` internal-only; only `mcp-edge` should have a public domain.
- Use admin API tokens only from operator machines or deployment automation.
- Prefer literal IP static upstream URLs if DNS rebinding resistance matters more than operational readability.
- Keep public DCR disabled unless you intentionally support unmanaged clients and have abuse controls in place.
- Rotate edge-issued test tokens after static-header troubleshooting.
- Back up the shared platform database before migration-heavy deployments.

## Troubleshooting Matrix

| Symptom | Likely cause | Check | Fix |
|---|---|---|---|
| `service_not_found` from admin API | Catalog row is missing or disabled. | `GET /v1/services/<serviceID>` | Register the service or re-enable the row. |
| `builtin_service_locked` | Attempted to mutate a code-owned builtin service through the admin API. | `GET /v1/services/<serviceID>` and inspect `source`. | Change code for builtin services or use a different dynamic service ID. |
| `public_path_conflict` | New public path exactly or prefix-overlaps an enabled service. | `GET /v1/services` | Pick a non-overlapping path. |
| `service_not_granted` during upstream binding | Subject lacks an effective grant for the service. | `GET /v1/subjects/<subjectSub>/grants` | Add Authentik group or manual grant first. |
| `upstream_healthcheck_failed` | Static upstream failed the registered health check. | Curl the upstream from the control-plane network. | Fix service health, health path, network routing, or catalog health contract. |
| `tenant_not_ready` at edge | Tenant row is not ready or has no upstream URL. | Control-plane readiness and tenant row status. | Re-run static upstream bind or reconcile runtime. |
| `invalid_resource` or `invalid_token` | Token was issued for a different MCP resource URL. | Introspect token and compare `resource` to service URL. | Re-auth using the exact service `resource`. |
| `insufficient_scope` | Token scope does not include target service scope. | Introspect token `scope`. | Re-auth requesting exactly the target service scope. |
| Browser client CORS failure | Browser origin is not allowed. | `MCP_EDGE_CORS_ALLOWED_ORIGINS` | Add a narrow origin allowlist or use a non-browser client. |
| Client sees no OAuth flow | Client did not read PRM/AS metadata or public DCR is disabled. | `WWW-Authenticate` and well-known endpoints. | Use operator-token DCR/static OAuth config or enable public DCR intentionally. |

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
