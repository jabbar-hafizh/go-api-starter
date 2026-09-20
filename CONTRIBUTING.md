# How we work here

Rules come in two kinds: **machine-enforced** (CI fails) and **kept at review**.
If a rule can move to the first group, move it.

## Machine-enforced

| Gate | Command |
|---|---|
| Compiles | `go build ./...` |
| Generated code in sync | `go tool sqlc diff`, regenerate OpenAPI then `git diff --exit-code` |
| Linter | `golangci-lint run` |
| Tests | `go test -race ./...` |
| Spec is valid | `redocly lint docs/openapi.yaml` |
| Spec is not breaking | `oasdiff breaking` against `main` |

Run all of it locally with `make verify`.

There is no line limit per file. What is limited is complexity per function
(`funlen`, `gocognit`, `cyclop`), because that is where comprehension actually
breaks and a machine can measure it.

## Kept at review

### Structure

One package per feature, not per layer. `internal/auth` holds its own domain,
store and handler.

The reason is specific to Go: the package is the only visibility boundary there
is. Split service and repository into separate packages and everything crossing
that line must be exported, so the repository's entire surface becomes public to
the whole program. One package per feature means only the feature's API is
public and the rest is genuinely closed.

### File names

- Name the file after the concept someone will look for, not the layer.
- **Banned:** `utils.go`, `helpers.go`, `common.go`, `misc.go`, `service.go`,
  `model.go`, `base.go`. A name that promises nothing attracts everything.
- Several implementations of one concept: `<concept>_<impl>.go`
  (`store_postgres.go`, `provider_google.go`).
- **Never** use a GOOS/GOARCH word as a suffix (`_windows`, `_darwin`, `_js`,
  `_linux`, `_arm64`). The file silently drops out of the build.

Split by use case, never by step within a use case. `login.go` holds the whole
login flow. If a small feature touches more than two files, the split is wrong.

### Comments

Write them in English, keep them short, and only where they earn their place.
Explain why, not what. If the code already says it, delete the comment.

### Interfaces

The consumer defines the interface, not the implementation. `internal/auth`
declares a `userStore` with only the methods it actually calls; the
implementation never mentions that interface.

### Errors

- The store translates database errors into domain errors. `pgx.ErrNoRows`
  never escapes the store.
- Handlers do not map errors to status codes. Return the domain error and
  `internal/httperr` maps it, in one place.
- Unrecognised errors become a logged 500 and never reach the client.

### Database

sqlc by default. Hand-written queries only for three cases: table or column
names decided at runtime, more than three optional filters, or a dynamic
`ORDER BY`. Put them in a separate file so they are easy to audit.

In hand-written queries two things are non-negotiable:

1. **Never write placeholder numbers by hand.** Use a helper that appends the
   argument and returns its number. Writing `$3` by hand and building `args`
   separately is the most common way a tenant filter quietly points at the wrong
   column, with the query still running and returning rows.
2. **Column names only from a whitelist.** Values always go through
   placeholders.

### API contract

`docs/openapi.yaml` is the source of truth and is **written first**, before the
handler. Handlers are generated from it, so anything that does not match will
not compile.

`/v1` is additive only. The `code` value on an error is a public contract: once
released, it never changes.

## Commits

Conventional commits, in English: `feat:`, `fix:`, `refactor:`, `test:`,
`chore:`, `docs:`.
