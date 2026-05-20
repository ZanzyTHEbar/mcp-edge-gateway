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
    "secret_contract": [{"Key":"api-token","Required":true}],
    "identity_context": {"mode":"none"}
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

### App Account Binding

Some MCP services need to operate as the app account that corresponds to the authenticated MCP subject, rather than as one static app token. For those services, set the catalog `identity_context` to `{"mode":"signed-headers"}`. Services that do not need app-account awareness should keep `{"mode":"none"}` or omit the field.

When signed identity context is enabled, `mcp-edge` strips any inbound `X-MCP-Identity-*` and `X-MCP-Subject-*` headers, then injects trusted headers after OAuth token validation, service grant checks, resource binding checks, and tenant resolution. Configure `MCP_EDGE_IDENTITY_HEADER_SECRET_PATH` on `mcp-edge` with a shared HMAC secret and mount the same secret into app-account-aware MCP services. Configure `MCP_EDGE_ACCOUNT_BINDING_CLAIM` to the stable Authentik claim shared with downstream apps, for example `dragonserver_user_id` or `authentik_user_uuid`.

Injected headers:

| Header | Purpose |
|---|---|
| `X-MCP-Identity-Version` | Signature contract version, currently `v1`. |
| `X-MCP-Identity-Service-ID` | Catalog service ID receiving the request. |
| `X-MCP-Identity-Session-ID` | Edge OAuth session ID for audit correlation. |
| `X-MCP-Identity-Issued-At` | Unix timestamp when the headers were produced. |
| `X-MCP-Identity-Signature` | `v1=<base64url-hmac-sha256>` over the canonical header payload. |
| `X-MCP-Subject-Sub` | MCP Edge/Auth subject `sub`. |
| `X-MCP-Subject-Key` | Stable edge subject key used for tenant naming. |
| `X-MCP-Subject-Email` | Email claim, for display or fallback only. |
| `X-MCP-Subject-Preferred-Username` | Preferred username claim. |
| `X-MCP-Subject-Display-Name` | Display name claim. |
| `X-MCP-Subject-Account-Binding-ID` | Stable cross-app binding claim value, if present. |
| `X-MCP-Subject-Account-Binding-Claim` | Claim name used for the binding ID. |

The signature payload is the newline-joined sequence `version`, `service_id`, `session_id`, `issued_at`, `subject_sub`, `subject_key`, `email`, `preferred_username`, `display_name`, `account_binding_id`, and `account_binding_claim`. Account-aware MCP services must verify the signature, reject stale `issued_at` values, require the expected `service_id`, and bind to their app account using `X-MCP-Subject-Account-Binding-ID` instead of email whenever possible.

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
6. Let the client call the MCP service URL with the access token it manages internally.

If `MCP_EDGE_CIMD_ENABLED=true`, the edge also accepts HTTPS Client ID Metadata Document URLs as `client_id` values and registers the public client metadata on first authorization.

CORS is disabled unless `MCP_EDGE_CORS_ALLOWED_ORIGINS` is set. Use a comma-separated allowlist for browser-based clients, or `*` only when bearer-token exposure to any browser origin is acceptable for your deployment.

### Headless Client Authentication

The edge supports two production-safe headless modes. Both modes issue normal edge opaque bearer tokens. MCP service routes still enforce token validity, exact service scope, exact resource binding, current subject grant, and tenant readiness.

Use OAuth Device Authorization Grant for CLIs or headless agents that can ask a human to approve access in a browser. Use operator-issued tokens only for trusted automation where an operator intentionally mints a scoped token for a subject that already has the service grant.

Do not send Authentik access tokens directly to MCP service paths. The edge only accepts edge-issued opaque tokens at MCP routes.

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

Example device-only client registration request:

```sh
curl -fsS https://<edge-domain>/oauth/register \
  -H 'Authorization: Bearer <operator-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "example-headless-cli",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": [],
    "token_endpoint_auth_method": "none",
    "scope": "mcp:mealie"
  }'
```

Example device authorization request:

```sh
curl -fsS https://<edge-domain>/oauth/device_authorization \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'client_id=<client-id>' \
  --data-urlencode 'scope=mcp:mealie' \
  --data-urlencode 'resource=https://<edge-domain>/mealie/mcp'
```

The response contains `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, and `interval`. Show the `user_code` and verification URL to the user. The verification page redirects to Authentik when no browser session exists, then shows the service, scope, resource, client, and user code before approval or denial.

Example device token polling request:

```sh
curl -fsS https://<edge-domain>/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode 'client_id=<client-id>' \
  --data-urlencode 'device_code=<device-code>'
```

Device polling outcomes:

- `authorization_pending`: user has not approved yet; wait at least `interval` seconds.
- `slow_down`: polling was too fast; increase the wait interval before retrying.
- `access_denied`: user denied the request.
- `expired_token`: the device code expired; restart the device authorization request.
- success: response includes an edge-issued access token, the service `scope`, the service `resource`, and a refresh token only when the client was registered for `refresh_token`.

Example operator-issued token request:

```sh
curl -fsS https://<edge-domain>/oauth/operator-tokens \
  -H 'Authorization: Bearer <operator-token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "subject_sub": "<subject-sub>",
    "scope": "mcp:mealie",
    "resource": "https://<edge-domain>/mealie/mcp",
    "expires_in_seconds": 3600,
    "reason": "short operational task"
  }'
```

The operator token response includes `access_token`, `token_type`, `expires_in`, `scope`, `resource`, `session_id`, and `issued_via=operator`. Store only the token in the automation secret store. Keep `session_id` for revocation and audit correlation. `expires_in_seconds` defaults to one hour and is capped at 30 days; `reason` is optional and capped at 1024 characters.

Example operator-issued token revocation:

```sh
curl -fsS https://<edge-domain>/oauth/operator-tokens/<session-id> \
  -X DELETE \
  -H 'Authorization: Bearer <operator-token>'
```

Revocation is scoped to sessions issued through `/oauth/operator-tokens`; it does not revoke browser OAuth or device-flow sessions. Operators can introspect any edge-issued token with `/oauth/introspect`; active responses include `session_id`, `client_id`, `sub`, `scope`, `resource`, `issued_via`, `iat`, and `exp`.

### opencode Client Setup

opencode supports remote MCP servers in `opencode.json` under the top-level `mcp` object. Configure opencode with its first-class `oauth` block so opencode owns the OAuth flow and token storage. Do not configure edge access tokens in `headers`, environment variables, shell wrappers, or project files.

Default production constraint: public dynamic client registration is disabled unless `MCP_EDGE_DCR_ENABLED=true`. For production, pre-register the opencode client with the edge operator token, then put only the returned `client_id` in opencode config. The operator token is used by the operator during registration only; it is not an opencode runtime credential.

Native OAuth opencode example with a pre-registered client:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mealie": {
      "type": "remote",
      "url": "https://<edge-domain>/mealie/mcp",
      "enabled": true,
      "oauth": {
        "clientId": "<pre-registered-client-id>",
        "scope": "mcp:mealie"
      }
    }
  }
}
```

Native OAuth opencode example with public DCR intentionally enabled:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mealie": {
      "type": "remote",
      "url": "https://<edge-domain>/mealie/mcp",
      "enabled": true,
      "oauth": {
        "scope": "mcp:mealie"
      }
    }
  }
}
```

Device-flow behavior is client-owned. When opencode runs in a headless context and the edge authorization metadata advertises `urn:ietf:params:oauth:grant-type:device_code`, opencode should use device authorization, show the verification URL/user code, and store the issued tokens in its own credential store. The `opencode.json` shape stays the same; do not manually copy the returned device-flow access token into `headers`.

Operator-issued tokens are not a direct `opencode.json` static-header configuration. They are for trusted automation clients that have a secure credential integration. If opencode needs this mode, use a credential-managed opencode plugin or local MCP bridge that mints/refreshes/revokes operator-issued scoped tokens outside project config and injects credentials at runtime without exposing them in config, logs, or environment. Do not use this mode as a bearer token pasted into `opencode.json`.

Credential-managed bridge shape, if you provide one locally:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "mealie": {
      "type": "local",
      "command": ["mcp-edge-credential-bridge", "--service", "mealie"],
      "enabled": true
    }
  }
}
```

opencode validation checklist:

1. Confirm `GET https://<edge-domain>/mealie/mcp` without a token returns `401` and a `WWW-Authenticate` header with `resource_metadata="https://<edge-domain>/.well-known/oauth-protected-resource/mealie"`.
2. Add the remote server URL to `opencode.json`.
3. Run opencode's MCP auth/connect flow for the server.
4. Confirm opencode uses either loopback PKCE or device authorization from the edge OAuth metadata, not a static bearer header.
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
