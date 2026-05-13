# MCP Platform Runtime

This repository contains the production Go runtime for a shared MCP edge and control plane deployment.

Product strategy, architecture decision records, and environment-specific operator runbooks are intentionally kept outside this public runtime repository.

## Current Runtime Surface

The module currently produces two binaries:

- `mcp-edge`
- `mcp-control-plane`

Implemented runtime capabilities now include:

- shared MCP edge service paths for MCP Server
- MCP-facing OAuth metadata, authorization, token, refresh, registration, and introspection flows
- durable SQLite/libSQL edge persistence for OAuth clients, tokens, browser sessions, and pending logins
- durable edge audit-event persistence for OAuth, browser-login, and protected service access decisions
- DB-backed subject-aware tenant resolution at the edge
- control-plane persistence, goose migration execution, Authentik sync, Infisical secret retrieval, and Coolify tenant reconciliation
- transport/path normalization for the day-one service catalog:
  - `mcp` -> upstream `/http`
  - `mcp` -> targeted SSE-to-streamable-HTTP request bridge supported services

## Repository Layout

```text
.
├── cmd/
│   ├── mcp-edge/
│   └── mcp-control-plane/
├── db/
│   ├── migrations/
│   └── queries/
├── deploy/
│   └── coolify/
├── internal/
│   ├── catalog/
│   ├── contracts/
│   ├── controlplane/
│   ├── domain/
│   ├── edge/
│   ├── ids/
│   └── platform/sqlite/
├── control-plane.env.example
├── docker-compose.yaml
├── edge.env.example
├── go.mod
├── sqlc.yaml
└── README.md
```

## Runtime Contracts

The most important public runtime contract sources are:

- `edge.env.example`
- `control-plane.env.example`
- `docker-compose.yaml`
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

SQLite/libSQL is the default persistence layer. sqlc code must be regenerated when `db/queries` or `db/migrations` changes:

```sh
sqlc generate
go test -buildvcs=false ./...
go build -buildvcs=false ./...
```
