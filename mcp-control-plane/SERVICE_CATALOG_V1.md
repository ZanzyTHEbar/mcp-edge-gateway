# Service Catalog V1

Status: Frozen for Batch 1
Date: 2026-03-21

This document defines the day-one service catalog for the shared MCP platform.

## 1. Catalog Fields

Each service catalog entry defines:

- `service_id`
- `display_name`
- `upstream_service_name`
- `transport_type`
- `internal_port`
- `public_path`
- `internal_upstream_path`
- `health_path`
- `health_probe_expectation`
- `resource_profile`
- `persistence_policy`
- `adapter_requirement`
- `secret_contract`

## 2. Day-One Services

| service_id | display_name | upstream_service_name | transport_type | internal_port | public_path | internal_upstream_path | health_path | health_probe_expectation | resource_profile | persistence_policy | adapter_requirement |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `mealie` | `Mealie` | `mealie-mcp` | `streamable-http` | `3031` | `/mealie/mcp` | `/mcp` | `/mcp` | `GET` returns discovery JSON with `transport=streamable-http` | `small` | `stateless` | `none` |
| `actualbudget` | `Actual Budget` | `actualbudget-mcp` | `streamable-http` | `3000` | `/actualbudget/mcp` | `/http` | `/http` | `GET` returns a live MCP JSON-RPC error rather than connection failure | `small` | `stateless` | `path-translation` |
| `memory` | `Memory` | `memory` | `sse` | `8090` | `/memory/mcp` | `/sse` | `/sse` | `GET` returns `text/event-stream` and an endpoint event | `medium` | `stateful-libsql` | `sse-to-http-normalization` |

## 3. Secret Contracts

### 3.1 Mealie

Logical secret contract:

- `api-token`

Behavior:

- one per-user Mealie API token
- injected into the private tenant runtime
- must eliminate the need for public client-side `X-Mealie-Token` overrides

### 3.2 Actual Budget

Logical secret contract:

- `actual-api-key`
- `budget-sync-id`
- `actual-budget-encryption-password`

Non-secret runtime config:

- `actual-api-base-url`

Behavior:

- the public edge normalizes `/actualbudget/mcp`
- the tenant runtime still talks to the internal Actual HTTP API contract
- the exact runtime image remains an integration concern, but the upstream path contract is frozen at `/http`

### 3.3 Memory

Logical secret contract:

- `libsql-url`
- `libsql-auth-token`

Behavior:

- the upstream runtime remains SSE today
- the edge or adapter layer must present a streamable MCP-facing contract at `/memory/mcp`

## 4. Adapter Rules

### 4.1 Mealie

- no transport adapter at the edge
- tenant template work is secret-delivery and isolation work

### 4.2 Actual Budget

- no protocol translation
- public-path translation is required from `/actualbudget/mcp` to upstream `/http`

### 4.3 Memory

- explicit transport normalization required
- no client may depend on the raw `/sse` public route after cutover

## 5. Operational Rules

- Every service entry must be path-normalized behind `https://mcp.zacariahheim.com/<service>/mcp`.
- Every service entry must route to one backend per `user x service`.
- Every service entry must resolve secrets from Infisical, not Coolify env as source of truth.
- Every service entry must define a deterministic health probe expectation before onboarding.
