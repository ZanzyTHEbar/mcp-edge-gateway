# Product Requirements Document

Document: MCP Control Plane PRD  
Status: Baseline design  
Date: 2026-03-20  
Owner: DragonServer platform

## 1. Summary

DragonServer needs a production-grade MCP platform that gives users the same high-quality experience offered by providers such as Linear:

- a stable public MCP endpoint
- browser-based login on the same machine as the client
- no per-user URL configuration
- no manual per-MCP OAuth customization

At the same time, the platform must preserve DragonServer-specific requirements:

- per-user backend isolation
- Coolify-native lifecycle management
- Authentik-based RBAC
- dedicated secret management from day one
- compatibility with largely unmodified MCP servers

This product is the control plane that makes those requirements coexist.

## 2. Problem Statement

The current MCP estate has four structural problems:

1. MCP services are exposed inconsistently.
2. User identity and authorization are handled per service instead of centrally.
3. Multi-user behavior depends on service-specific workarounds such as header injection or static bearer tokens.
4. The current public and internal routing model is difficult to reason about, audit, and harden.

The result is a platform that works for isolated services, but does not scale cleanly to:

- multiple users
- multiple MCP clients
- multiple MCP services
- centralized RBAC and lifecycle control

## 3. Product Vision

Provide a self-hosted MCP platform where:

- users configure a stable service endpoint once
- the client performs browser-based OAuth
- the platform enforces authorization centrally
- each user is served by an isolated backend instance for that MCP service
- the platform remains visible and operable through Coolify
- secrets are managed centrally and rotated safely

## 4. Goals

### 4.1 Primary Goals

1. Replace service-specific MCP auth patterns with one shared platform pattern.
2. Deliver Linear-style remote MCP UX using a shared public edge.
3. Preserve one backend instance per `user x service`.
4. Keep all tenant workloads discoverable and manageable in Coolify.
5. Introduce a dedicated secret store as the canonical secret source.
6. Support multi-user, multi-client operation without modifying the client UX per user.

### 4.2 Secondary Goals

1. Standardize audit logging and observability.
2. Make onboarding new MCP services a catalog operation instead of bespoke engineering.
3. Eliminate direct internal-container MCP references from upstream clients such as Open WebUI.

## 5. Non-Goals

The following are explicitly out of scope for this product:

1. Converting upstream MCP servers into shared multi-tenant applications.
2. Exposing per-user public MCP hostnames or aliases in the client UX.
3. Managing tenant backends outside Coolify.
4. Treating Coolify as the source of truth for user secrets.
5. Introducing a commercial gateway as the foundation of the platform.

## 6. Users and Jobs To Be Done

### 6.1 End Users

End users connect MCP-capable clients such as Cursor, Claude, Codex, Open WebUI, or custom agent frontends.

Jobs:

- add a stable MCP endpoint
- authenticate in the browser
- use the service without knowing internal routing or tenant topology

### 6.2 Platform Operators

Platform operators manage the DragonServer platform through Authentik, Coolify, and the control plane.

Jobs:

- grant or revoke MCP access
- inspect tenant health and lifecycle state
- rotate secrets safely
- add new MCP services without inventing new deployment patterns

### 6.3 Security and Identity Admins

Security admins own group design, service entitlement, and user access policy.

Jobs:

- control which users may access which MCP services
- enforce least privilege
- audit who accessed which service and when

## 7. Product Principles

1. **One public experience, many private tenants.**
2. **Identity is token-based, not hostname-based.**
3. **Coolify is the tenant runtime control surface.**
4. **Infisical is the secret source of truth.**
5. **Upstream MCP servers should remain as close to vanilla as practical.**
6. **No direct public tenant exposure.**

## 8. Canonical User Experience

The canonical user flow is:

1. The user configures a stable service endpoint such as `https://mcp.zacariahheim.com/mealie/mcp`.
2. The MCP client connects and receives the MCP/OAuth authorization challenge.
3. The client opens the browser on the same machine.
4. The user authenticates through the platform flow, which delegates human login to Authentik.
5. The client stores its access and refresh tokens locally.
6. Subsequent calls to the same endpoint just work.

Important nuance:

- the user experience is shared-domain and service-path based
- the backend execution model remains per-user and isolated
- each client stores its own tokens, even if the same browser session makes login feel seamless

## 9. Functional Requirements

### Public Interface

- **FR-001**: The platform MUST expose a single shared public MCP domain.
- **FR-002**: The platform MUST expose separate service endpoints under that domain.
- **FR-003**: The platform MUST support browser-based OAuth for remote MCP clients.
- **FR-004**: The platform MUST support standard MCP authorization discovery for HTTP-based transports.

### Identity and Authorization

- **FR-005**: The platform MUST use Authentik as the human identity provider.
- **FR-006**: The platform MUST enforce service authorization from Authentik-managed RBAC.
- **FR-007**: The platform MUST key users by immutable subject identity, not mutable usernames.
- **FR-008**: The platform MUST support multi-user and multi-client access concurrently.

### Isolation and Tenancy

- **FR-009**: Each supported MCP service MUST run as an isolated backend per user.
- **FR-010**: Tenant MCP backends MUST remain private and unreachable from the public internet.
- **FR-011**: The public edge MUST resolve the authenticated user to the correct private tenant backend.
- **FR-012**: The platform MUST support the baseline service catalog on day one: `mealie`, `actualbudget`, and `memory`.

### Coolify and Runtime Management

- **FR-013**: Tenant backends MUST be created as real Coolify-managed resources so they are visible in the Coolify UI.
- **FR-014**: All platform services and tenant backends MUST operate on the `coolify` Docker network.
- **FR-015**: The platform MUST create, update, redeploy, disable, and delete tenant resources through the Coolify API.

### Secrets

- **FR-016**: The platform MUST use a dedicated secret store from day one.
- **FR-017**: The secret store MUST be the canonical source of truth for user and platform secrets.
- **FR-018**: The platform MUST support secret rotation without redesigning the deployment model.
- **FR-019**: The platform MUST supply secrets to vanilla MCP backends without requiring those backends to implement native secret-store clients.

### Operability

- **FR-020**: The platform MUST emit audit records for authentication, authorization, provisioning, and request routing decisions.
- **FR-021**: The platform MUST expose health and readiness state for the edge, control plane, and tenants.
- **FR-022**: The platform MUST support deterministic migration away from current direct MCP routes.

## 10. Non-Functional Requirements

### Security

- **NFR-001**: All public auth and MCP traffic MUST use HTTPS.
- **NFR-002**: No public route may exist to a tenant backend.
- **NFR-003**: Tokens MUST be validated for issuer, audience/resource, expiry, and scope.
- **NFR-004**: Secrets MUST never be logged in plaintext.
- **NFR-005**: Audit events MUST preserve subject, service, decision, and correlation information.

### Reliability

- **NFR-006**: The public edge MUST be independently restartable without requiring tenant recreation.
- **NFR-007**: Tenant reconciliation MUST converge deterministically after restarts.
- **NFR-008**: Revoking a user or service grant MUST stop access before or at the same time as tenant teardown.

### Performance

- **NFR-009**: The platform SHOULD add minimal proxy overhead relative to direct service access.
- **NFR-010**: Access to a granted service SHOULD not depend on ad hoc manual provisioning.

### Operations

- **NFR-011**: The platform MUST remain understandable from the Coolify UI.
- **NFR-012**: Adding a new MCP service SHOULD be a service-catalog addition, not a bespoke platform redesign.

## 11. Success Criteria

The platform will be considered successful when all of the following are true:

1. All supported MCP clients point at the shared edge domain, not at raw tenant containers.
2. Browser-based login works without per-user public URLs.
3. All tenant backends appear as managed resources in Coolify.
4. Direct public MCP routes for legacy services are retired or redirected to the shared edge service paths.
5. Each authorized user can access only their own backend instance for a given service.
6. Secret rotation is performed through the secret store and propagated through the control plane.
7. Open WebUI and similar consumers no longer require direct internal container URLs for MCP access.

## 12. Initial Production Scope

### Included

- Shared MCP edge domain
- Auth broker and resource server
- Control plane and reconciliation loop
- Infisical secret management
- Coolify-native tenant services
- Supported services:
  - `mealie`
  - `actualbudget`
  - `memory`

### Excluded from Initial Production Scope

- Generic support for arbitrary third-party MCP services without catalog onboarding
- Public per-user aliases
- Unmanaged local-only MCP services

## 13. Risks and Product Constraints

1. Authentik does not appear to provide a straightforward fit for MCP-style dynamic client registration, so the platform cannot rely on Authentik alone for the MCP-facing OAuth experience.
2. Some upstream MCP servers only accept secrets through environment variables or files, which means the control plane must handle compatibility injection carefully.
3. The `memory` service currently differs from the preferred transport model and may require an adapter layer behind the shared edge.
4. Coolify must remain operationally reliable under an increased tenant-resource count.

## 14. Acceptance Statement

This PRD defines the required product shape for the DragonServer MCP control plane.

It is not a demo plan, a pilot brief, or an exploration note.
It is the baseline product requirement set for a production implementation.
