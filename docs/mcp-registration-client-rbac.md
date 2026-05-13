# MCP Registration, Client Use, and RBAC

This document describes the current MCP Edge Gateway operating contract. It is deployment-neutral; replace example domains, client IDs, and tokens with values from your own environment.

## Registering MCP Services

MCP services are registered as builtin catalog entries in code. There is no dynamic service-registration API today.

The source of truth is `internal/catalog/service.go` in `DefaultCatalogV1()`. Each `ServiceCatalogEntry` defines the service ID, public edge path, upstream container shape, transport behavior, health path, adapter requirement, and required secrets.

Current builtin services:

| Service ID | Public MCP URL | Scope | Upstream path |
|---|---|---|---|
| `mealie` | `https://<edge-domain>/mealie/mcp` | `mcp:mealie` | `/mcp` |
| `actualbudget` | `https://<edge-domain>/actualbudget/mcp` | `mcp:actualbudget` | `/http` |
| `memory` | `https://<edge-domain>/memory/mcp` | `mcp:memory` | `/sse` |

Operator workflow for adding a builtin MCP service:

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
- Startup upserts builtin entries and disables catalog rows missing from `DefaultCatalogV1()`.
- Removing a builtin service from code disables it; it does not hard-delete historical data.

## Using MCPs From Clients

Clients connect to MCP service URLs on the edge, not to internal tenant containers.

Use the edge OAuth metadata endpoints for discovery:

- `GET https://<edge-domain>/`
- `GET https://<edge-domain>/.well-known/oauth-authorization-server`
- `GET https://<edge-domain>/.well-known/oauth-protected-resource`

The root endpoint returns a small JSON index with service paths, scopes, health URLs, and OAuth endpoint links. MCP clients should still use the per-service MCP URLs, not `/`.

Client setup flow:

1. Register the client with `POST /oauth/register` using the edge operator bearer token.
2. Store the returned `client_id` and optional `client_secret`.
3. Start authorization-code + PKCE (`S256`) against `/oauth/authorize`.
4. Request one or more service scopes, such as `mcp:mealie`.
5. Exchange the authorization code at `/oauth/token`.
6. Call the MCP service URL with `Authorization: Bearer <edge-issued-access-token>`.

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
    "scope": "mcp:mealie mcp:memory"
  }'
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
curl -fsS https://<edge-domain>/.well-known/oauth-protected-resource
```

For RBAC validation:

1. Add a test user to `mcp-service-mealie` only.
2. Run or wait for control-plane reconciliation.
3. Complete OAuth login and request `mcp:mealie`.
4. Confirm `/mealie/mcp` is allowed after the tenant is ready.
5. Confirm `/actualbudget/mcp` is denied unless the user also has that grant.
