# MCP Edge Gateway

MCP Edge Gateway is a Go runtime for operating a shared MCP edge and control plane. It provides authenticated public MCP entrypoints, tenant-aware routing, durable state, and a control plane that can reconcile tenant services through external infrastructure APIs.

This repository is deployment-neutral. It does not include private rollout notes, live hostnames, organization-specific runbooks, incident history, or environment identifiers.

## What it includes

- `mcp-edge`: the public HTTP edge for MCP clients.
- `mcp-control-plane`: the internal control plane for catalog, tenant, secret, and runtime reconciliation.
- SQLite/libSQL persistence with goose migrations and sqlc-generated data access.
- OAuth metadata, registration, authorization, token, refresh, and introspection endpoints.
- Subject-aware tenant routing and audit-event persistence.
- Deployment templates for Docker Compose and Coolify-style environments.

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

## Configuration

Start from the example files:

- `control-plane.env.example`
- `edge.env.example`

These examples use placeholders and safe defaults. Replace them with values for your own identity provider, secret store, infrastructure API, public edge URL, and tenant image strategy.

Tenant images support two modes:

- `local`: image tags must already exist on the Docker host.
- `pinned`: image references must use `@sha256:<64 hex>` digests.

Keep environment-specific values outside this repository. That includes live hostnames, user identifiers, production UUIDs, access tokens, secret values, incident notes, and one-off migration plans.

## Deployment templates

The `deploy/coolify/` directory contains compose templates for:

- a combined core stack,
- a control-plane-only service,
- an edge-only service,
- registry-image variants of those services.

The root `docker-compose.yaml` is a convenience entrypoint for the combined stack.

## Development

Run the standard validation loop before committing changes:

```sh
sqlc generate
go test -buildvcs=false ./...
go build -buildvcs=false ./...
```

If you change SQL queries or migrations, regenerate sqlc output before running tests.

