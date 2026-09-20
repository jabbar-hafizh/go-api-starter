# go-api-starter

Go backend API: password and SSO auth for web and mobile clients.

One binary, one database, many feature packages inside it. The per-feature
layout keeps splitting into separate services cheap if that day comes, but that
is not done now because nothing forces it yet.

## Running locally

```bash
cp .env.example .env
make db-up      # Postgres via docker compose, waits until healthy
make run        # migrations run at boot
```

```bash
curl localhost:8080/healthz   # {"status":"ok"}
curl localhost:8080/readyz    # 200 when every dependency is ready, 503 otherwise
```

`make help` lists every command.

## Before pushing

```bash
make verify     # the same gates CI runs
```

## Layout

```
cmd/api            entrypoint
docs/openapi.yaml  API contract, source of truth, written before handlers
internal/
  app              dependency wiring and server lifecycle
  config           read env, validate, fail fast
  db               connection, migrations, SQL queries, generated code
  openapi          generated from docs/openapi.yaml
  health           liveness and readiness
  httperr          the only place errors become HTTP responses
```

## Tooling

`sqlc`, `oapi-codegen` and `goose` are pinned in `go.mod` via tool directives,
so `go tool <name>` runs identical versions everywhere with no global install.
Only `golangci-lint` is installed separately (`brew install golangci-lint`),
because pinning it the same way drags hundreds of linter dependencies into
`go.mod`.

## How we work here

See [CONTRIBUTING.md](CONTRIBUTING.md). Short version: package per feature not
per layer, file names say what is in them, the contract is written before the
handler, and `/v1` is additive only because old mobile builds cannot be forced
to update.
