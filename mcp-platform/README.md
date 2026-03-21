# MCP Platform Runtime

This repository contains the production Go runtime for a shared MCP edge and control plane deployment.

Product strategy, architecture decision records, and environment-specific operator runbooks are intentionally kept outside this public runtime repository.

## Current Runtime Surface

The module currently produces two binaries:

- `mcp-edge`
- `mcp-control-plane`

Implemented runtime capabilities now include:

- shared MCP edge service paths for `mealie`, `actualbudget`, and `memory`
- MCP-facing OAuth metadata, authorization, token, refresh, registration, and introspection flows
- durable edge persistence for OAuth clients, tokens, browser sessions, and pending logins
- DB-backed subject-aware tenant resolution at the edge
- control-plane persistence, migration execution, Authentik sync, Infisical secret retrieval, and Coolify tenant reconciliation
- transport/path normalization for the day-one service catalog:
  - `/actualbudget/mcp` -> upstream `/http`
  - `/memory/mcp` -> upstream SSE endpoint normalization

## Repository Layout

```text
.
├── cmd/
│   ├── mcp-edge/
│   └── mcp-control-plane/
├── db/
│   └── migrations/
├── deploy/
│   └── coolify/
├── internal/
│   ├── catalog/
│   ├── contracts/
│   ├── controlplane/
│   ├── domain/
│   └── edge/
├── control-plane.env.example
├── edge.env.example
├── platform-db.env.example
├── go.mod
└── README.md
```

## Runtime Contracts

The most important public runtime contract sources are:

- `edge.env.example`
- `control-plane.env.example`
- `platform-db.env.example`
- `deploy/coolify/README.md`
- `deploy/coolify/*.compose.yaml`
- `deploy/coolify/*.image.compose.yaml`

Environment-specific rollout plans, live identifiers, and private service audits should live in a separate private operations repository.

## Validation

The current validation loop for this module is:

```sh
go test -buildvcs=false ./...
go build -buildvcs=false ./...
```

## Batch 18 Status

Completed hardening in this module now includes:

- fail-closed edge auth mode outside explicit fixture mode
- operator-gated sensitive OAuth endpoints
- restart-safe multi-instance edge state handling
- cluster-safe migration locking for the control plane
- degraded-startup behavior when the initial reconcile fails
- softer Authentik snapshot ingestion for malformed rows and unknown service-group mappings
- improved reconcile summary accounting and better upstream HTTP error detail for Authentik, Infisical, and Coolify failures

Remaining rollout work is now packaging-oriented:

- local artifact validation
- deployment-readiness review against target dependencies
- environment-specific rollout execution

## Implementation Directive

New runtime code in this module is written in Go.

Existing TypeScript services such as `mealie-mcp` remain integration surfaces and reference implementations, not the implementation language for the new platform components.
