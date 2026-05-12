# MCP Control Plane

Status: Production design plus implementation contract for the active Go runtime

This directory captures the agreed production design for reorganizing DragonServer MCP deployments into a hardened, centralized control plane, plus the runtime contracts the current Go implementation is expected to satisfy.

The design intentionally replaces the current mix of:

- direct public MCP endpoints
- internal-network trust between clients and MCP containers
- per-MCP bespoke authentication workarounds
- service-local secret handling

with a single, consistent platform model:

- one shared public MCP edge domain
- one standards-compliant browser-based OAuth flow
- one private tenant backend per `user x service`
- one Coolify-native lifecycle controller
- one dedicated secret store

## Document Map

- `PRD.md`
  - Product requirements, goals, scope, users, functional requirements, and success criteria.
- `EDD.md`
  - Engineering design, component responsibilities, runtime flows, data model, and rollout plan.
- `ARD.md`
  - Final architecture record, key decisions, rejected alternatives, and consequences.
- `IMPLEMENTATION_CONTRACTS.md`
  - Canonical naming, secret-path, env-surface, and rollout-contract rules for the live runtime.
- `BATCH0_RUNTIME_BASELINE.md`
  - Frozen live-runtime facts gathered before implementation.
- `ACTUAL_MCP_SOURCE_AUDIT.md`
  - Verified upstream and runtime lineage for `actualbudget-mcp` / `actual-mcp-server` (Coolify on `cool-res`).
- `DRAGONSERVER_RUNTIME_ROLLOUT.md`
  - Private live rollout inputs, fixed Coolify identifiers, secret-mount state, and the remaining execution order.
- `REFACTOR_EXECUTION_PLAN.md`
  - Execution-grade batch plan for the approved runtime cleanup and refactor program.

## Final Design Snapshot

- Canonical public MCP domain: `https://mcp.zacariahheim.com`
- Canonical public service endpoints:
  - `https://mcp.zacariahheim.com/mealie/mcp`
  - `https://mcp.zacariahheim.com/actualbudget/mcp`
  - `https://mcp.zacariahheim.com/memory/mcp`
- Human identity provider: Authentik
- MCP-facing OAuth broker and resource server: `mcp-edge`
- Tenant lifecycle manager: `mcp-control-plane`
- Secret source of truth: Infisical
- Tenant execution model: private Coolify-managed resources on the `coolify` Docker network
- Isolation boundary: one backend instance per `user x service`

## Current Implementation Snapshot

The Go runtime under `../mcp-platform/` now implements the core production skeleton:

- `mcp-edge`
  - shared service paths
  - MCP-facing OAuth flows
  - durable OAuth/session/client persistence in SQLite/libSQL
  - DB-backed subject-aware tenant resolution
  - service adapters for `actualbudget` path translation and `memory` SSE normalization
- `mcp-control-plane`
  - embedded SQL migrations
  - Authentik snapshot ingestion
  - Infisical secret resolution
  - Coolify tenant lifecycle reconciliation
  - degraded startup when initial reconcile fails
  - cluster-safe migration locking

This means the main remaining work is no longer architectural discovery. It is packaging, deployment definition, and controlled rollout validation.

## Non-Negotiable Constraints Captured Here

- No direct public access to tenant MCP backends
- No raw Docker orchestration outside Coolify for tenant workloads
- No dependency on modifying upstream MCP servers to become multi-tenant
- No per-user public aliases in the client UX
- No service-local ad hoc secret storage as the system of record

## Scope of the Initial Platform

The baseline production rollout documented here covers these services:

- `mealie`
- `actualbudget`
- `memory`

Additional MCP services should be added through the service catalog model described in `EDD.md`, not by introducing one-off deployment patterns.

## Batch 18 Rollout Requirements

Before live DragonServer mutation work begins, the runtime contract now assumes:

1. `mcp-control-plane` is attached to the shared `coolify` Docker network so internal tenant health probes can resolve tenant DNS names directly.
2. The platform database is deployed first and reachable by both `mcp-edge` and `mcp-control-plane`.
3. Infisical is deployed and holds the platform secret paths defined in `IMPLEMENTATION_CONTRACTS.md`.
4. Authentik has the MCP control-plane provider/app configuration plus the MCP entitlement groups.
5. The env examples in `../mcp-platform/*.env.example` are the source templates for deployment configuration.
6. Coolify deployment definitions now exist in the public runtime repository at `https://github.com/ZanzyTHEbar/dragonserver-mcp-platform-runtime` under `deploy/coolify/`, but the final live cutover plan still needs to be executed from the private operator docs before any mutation window.
