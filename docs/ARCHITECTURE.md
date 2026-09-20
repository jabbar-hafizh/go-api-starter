# Architecture and why

Every decision below has a reason, and where that reason comes from someone
else it is cited. Where it does not, it says so. If you disagree with one,
argue with the reason rather than the result.

Three kinds of source appear here, and they do not carry equal weight:

| Weight | What |
|---|---|
| **Normative** | IETF RFCs and OWASP. Security behaviour is measured against these |
| **Official** | The Go team and Google's published Go guidance |
| **Community** | Well-argued writing by individuals. Useful, not binding |
| **Ours** | No external source. Our judgement, with the reasoning written down |

---

## Sources

### Official Go and Google

- [Google Go Style Guide](https://google.github.io/styleguide/go/) — Google's
  internal Go guidance, published. See especially
  [Best Practices](https://google.github.io/styleguide/go/best-practices) and
  [Style Decisions](https://google.github.io/styleguide/go/decisions).
- [Go blog: Package names](https://go.dev/blog/package-names) — the closest
  thing to official guidance on structure.
- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)
- [Go Proverbs](https://go-proverbs.github.io/) — Rob Pike, 2015.
- [Go at Google: Language Design in the Service of Software Engineering](https://go.dev/talks/2012/splash.article)
  — Rob Pike, 2012. Why the language is shaped the way it is.
- [Go 1.24 release notes](https://go.dev/doc/go1.24) — `tool` directives in
  `go.mod`, `testing.T.Context`.
- The standard library itself. Where guidance is ambiguous, `net/http` and
  `crypto/tls` are the worked examples.

### Not official, despite the name

- [golang-standards/project-layout](https://github.com/golang-standards/project-layout).
  Its own README says: *"This is NOT an official standard defined by the core
  Go dev team."* On `/pkg` it adds: *"it's not universally accepted and some in
  the Go community don't recommend it."* The Go repository itself has no
  `src/pkg`. **We do not follow it.**

### Security

- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700)
  (BCP 240, January 2025). The single most load-bearing source for the auth
  design here.
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Google Identity: OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [CWE-601: Open Redirect](https://cwe.mitre.org/data/definitions/601.html)

### Community

- [How I Write HTTP Services in Go after 13 Years](https://grafana.com/blog/2024/02/09/how-i-write-http-services-in-go-after-13-years/)
  — Mat Ryer, 2024. Where `main`/`run` and handler closures come from.

### Tools

[sqlc](https://docs.sqlc.dev) ·
[oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) ·
[goose](https://github.com/pressly/goose) ·
[pgx](https://github.com/jackc/pgx) ·
[go-oidc](https://github.com/coreos/go-oidc) ·
[golangci-lint](https://golangci-lint.run) ·
[testcontainers-go](https://golang.testcontainers.org) ·
[distroless](https://github.com/GoogleContainerTools/distroless)

---

## Structure

### One package per feature, not per layer

`internal/auth` holds its own domain, store and handler. There is no
`internal/service` or `internal/repositories`.

**Why.** The package is the only visibility boundary Go has. There is no
`private` or `protected` per member. Split service and repository into separate
packages and everything crossing that line must be exported, so the
repository's entire surface becomes public to the whole program. One package
per feature spends that single boundary on separating features, which do need
protecting from each other, instead of on separating layers, which do not.

Three further costs of layer-first, measured in a real codebase of ours:

- Package names collide. `service/auth`, `repositories/auth` and `cache/auth`
  are all `package auth`, so files that touch more than one need import
  aliases. One file there had 13. Google's style guide says
  [avoid renaming imports](https://google.github.io/styleguide/go/decisions#import-renaming);
  layer-first forces it.
- Zero encapsulation. One `repositories/user` package there had 36 exported
  methods and no unexported ones. Not a choice: everything had to cross a
  package boundary.
- One concept spreads. "User" lived in seven places, so adding a field touched
  four directories.

*Weight: ours, reasoning from Go's visibility model.*

### No `pkg/`

Everything is under `internal/`.

**Why.** `pkg/` announces "safe to import from outside". There is no outside
here. The Go repository has no `src/pkg`, and the convention comes from
[a repo that says it is not a standard](https://github.com/golang-standards/project-layout).

*Weight: official, by the Go repository's own layout.*

### Package names are simple nouns

`auth`, `token`, `calculator`, `ratelimit`. Never `util`, `common`, `helpers`,
`types`, `api`, `misc`.

**Why.** Go blog, Package names: *"Avoid meaningless package names. Packages
named `util`, `common`, or `misc` provide clients with no sense of what the
package contains."* And: *"Don't use a single package for all your APIs."*
Google's style guide agrees: *"Naming a package just `util`, `helper`, `common`
or similar is usually a poor choice."*

A package with no theme cannot have a boundary. We have watched a `pkg/util`
elsewhere collect pointer helpers, token validation and MCP protocol
constructors in one file, because nothing in the name could refuse them.

*Weight: official.*

### No line limit per file; complexity is gated per function

`funlen` 80 lines, `gocognit` 20, `cyclop` 15, all enforced in CI. No file size
rule at all.

**Why.** In Go a file has no semantic meaning: every file in a package shares
one scope, so splitting one changes nothing the compiler sees. Google's style
guide says exactly this: *"Go style is flexible about file size, because
maintainers can move code within a package from one file to another without
affecting callers."*

The numbers back it. In the Go standard library (6,186 non-test files):
median 89 lines, p90 733, p99 3,458. `net/http/server.go` is 4,292 lines.
A 300-line rule would flag the Go team's own code.

What the style guide asks for instead is two properties, neither of which is a
number: files *"focused enough that a maintainer can tell which file contains
something, and small enough that it will be easy to find once there."*

Cognitive complexity rather than cyclomatic, because cyclomatic counts branches
and so treats a flat 20-case `switch` as dangerous, while cognitive complexity
penalises nesting, which is what actually loses a reader.

*Weight: official for the principle; the specific thresholds are ours.*

### File naming

Name a file after the concept someone will look for. Banned: `utils.go`,
`helpers.go`, `common.go`, `service.go`, `model.go`, `base.go`.

**Why.** Go has no official file naming convention beyond two compiler rules:
`_test.go`, and GOOS/GOARCH suffixes. That second one is a live trap — a file
named `store_windows.go` silently drops out of the build. The full list:

```
386 aix amd64 android arm arm64 darwin dragonfly freebsd illumos ios js linux
loong64 mips mips64 mips64le mipsle netbsd openbsd plan9 ppc64 ppc64le riscv64
s390x solaris wasip1 wasm windows
```

The de facto convention is the standard library's: files named after the
concept they hold. `net/http` contains `client.go`, `cookie.go`, `request.go`,
`server.go`, `transport.go` — and not one file named `service.go` or `model.go`.

The multi-provider case makes the point. OIDC code was first written as
`google.go`, which was wrong: the flow in it is identical for every provider,
so the name invited copy-paste when a second one arrived. Split by axis of
change instead: `oidc.go` changes when the protocol does, `provider_google.go`
changes when Google does.

*Weight: official for the compiler rules and the stdlib precedent; extending
the package-name principle to file names is ours.*

---

## Go idioms

### The consumer defines the interface

`internal/auth` declares the `store` interface it needs. `PostgresStore`
implements it without naming it. `internal/health` declares a one-method
`pinger` rather than taking `*pgxpool.Pool`.

**Why.** Interface satisfaction in Go is implicit, which makes this possible at
all. The result is interfaces containing only what the consumer calls, so a new
method on an implementation does not ripple through mocks that never wanted it.

Go Proverbs: *"The bigger the interface, the weaker the abstraction"* and
*"Don't design with interfaces, discover them."*

*Weight: official.*

### `main` is thin, `run` returns an error

```go
func main() {
	if err := run(); err != nil { ...; os.Exit(1) }
}
```

**Why.** `os.Exit` skips deferred functions, so anything with a `defer` has to
live where it can return instead. It also makes the startup path testable.
`gocritic`'s `exitAfterDefer` caught this in our own first draft.

Pattern from Mat Ryer, *How I Write HTTP Services in Go after 13 Years*:
*"func main() only calls run()"*, which *"takes in operating system
fundamentals as arguments, and returns an error."*

*Weight: community, plus a compiler-adjacent lint rule that agrees.*

### Dependencies are wired by hand

All of it in `app.buildServer`. No `wire`, no `fx`.

**Why.** Compile-time, no reflection, and the whole dependency graph reads top
to bottom in one function. `fx` moves wiring errors to runtime, which is a step
backwards in a language that would have caught them.

*Weight: ours.*

### Validation is a method, not a struct tag

`validateRegistration` rather than `validate:"required,email,min=12"`.

**Why.** A tag is a string checked by reflection at runtime; a typo in a
validator name fails silently. A method is checked by the compiler, is
trivially testable, and does not force a rule like "password must not equal the
email" into a DSL inside a string literal.

*Weight: ours.*

---

## Tooling

### Tools pinned in `go.mod`

`sqlc`, `oapi-codegen` and `goose` are `tool` directives, run with
`go tool <name>`.

**Why.** Go 1.24 release notes: *"Go modules can now track executable
dependencies using `tool` directives in go.mod."* Everyone who clones gets
identical versions with no global install and no `PATH` changes. "It works on
my machine" stops being possible for codegen.

`golangci-lint` is deliberately not pinned this way: it would drag hundreds of
linter dependencies into `go.mod` and invite version conflicts. It is installed
separately and pinned by version in CI.

*Weight: official.*

### Generated code is committed, and CI proves it is current

`go tool sqlc diff` and a regenerate-then-`git diff --exit-code` for OpenAPI.

**Why.** Committed output means a clone builds without any generator
installed. The CI gate is what stops "forgot to run `make generate`" reaching
`main`.

*Weight: ours.*

---

## Database

### sqlc, not an ORM

**Why.** The direction of generation is the whole point:

```
ORM   you write Go   → it writes SQL at runtime → you cannot see what ran
sqlc  you write SQL  → it writes Go at build time → what runs is exactly yours
```

The generated file carries your SQL verbatim as a constant, so every query the
application can possibly run is greppable in one folder.

The concrete payoff: rename a column in a migration and forget a query, and
`make generate` fails with `internal/db/queries/_probe.sql:2:12: column
"emaill" does not exist`. Before the commit, not in production.

**Where it does not apply.** sqlc needs the shape of the query at generate
time. Where the table or column names are decided at runtime, it cannot help at
all, and a purpose-built query builder is correct. The deciding factor is not
how complex a query is — sqlc gets *more* valuable as static complexity rises,
because typing a fifteen-column join with nullable columns is exactly where
people make mistakes.

*Weight: ours.*

### Never write placeholder numbers by hand

In any hand-written SQL, a helper appends the argument and returns its number.

**Why.** We found this in a production repository:

```go
whereAndClauses = append(whereAndClauses, "s.organization_id = $3")
args = append(args, req.Longitude, req.Latitude, organizationID, userID)
nextArg := 5
```

Three couplings that no compiler and no test checks. Insert one argument
earlier and `$3` silently points at a longitude. The query still runs, still
returns rows, and returns *another tenant's* rows. Nothing errors.

*Weight: ours, from a real near-miss.*

### `citext` for email, and the unique index decides

`users.email` is `citext UNIQUE`. Duplicate registration is detected from the
SQLSTATE `23505`, not from a prior `SELECT`.

**Why.** A check-then-insert has a race: two simultaneous registrations both
see nothing and both proceed. The index cannot be raced.

*Weight: ours.*

### UUIDv7

**Why.** Time-ordered, so a B-tree index does not fragment the way random v4
does, and it does not leak row counts the way a sequence does.

*Weight: ours.*

---

## API contract

### Spec first, and the compiler enforces it

`docs/openapi.yaml` is the source of truth. `oapi-codegen -generate
strict-server` produces typed handlers, so an implementation that does not
match the contract **does not compile**.

**Why.** Frontend and mobile are written by other people. A contract that can
drift from the implementation is a contract in name only. Writing the spec
first also forces the API to be designed before it is coded.

We chose this over `swaggo`-style comment annotations for the same reason we
rejected struct-tag validation: a DSL inside a comment is unchecked and drifts.

*Weight: ours.*

### `/v1` is additive only

Removing a field, changing a type or making a field required is breaking. CI
enforces it with `oasdiff`.

**Why.** Mobile builds live on devices for months and cannot be forced to
update. `/v1/app/config` exists so a build can be told it has fallen behind,
and `X-Client-Version` is recorded on every request so there is evidence for
when an endpoint is safe to remove.

*Weight: ours.*

### Error `code` values are a permanent public contract

`message` is for humans and may change. `code` never does once released.

*Weight: ours.*

### The spec is enforced at runtime in development

`VALIDATE_SPEC=true` checks every request against the OpenAPI document. Config
validation refuses to let it run in production.

**Why.** The generated types constrain shape but not required fields, enum
membership or formats. This closes that gap, so a contract violation fails a
test rather than reaching a client. A path the document does not describe is
also rejected, which catches a route that exists but was never written down;
the few routes served deliberately outside the contract are listed explicitly.

Responses are not checked, because the strict server derives those types from
the same document and cannot drift from it.

*Weight: ours.*

### Validation failures are one shape

One `422` carrying every offending field. This is why the request schemas do
**not** use `format: email`: the generated type rejects a bad address while
decoding, which produced a `400` with no field detail for email and a `422`
with detail for password. Two shapes for one concept is worse than a slightly
weaker generated type.

*Weight: ours.*

---

## Authentication

### argon2id, parameters carried in the hash

`m=19456 (19 MiB), t=2, p=1`, stored as a PHC string.

**Why.** Exactly the OWASP Password Storage Cheat Sheet configuration. Carrying
the parameters in the hash means the cost can be raised later without
invalidating anything already stored, and verification reads the stored
parameters rather than the current constants. There is a test proving a hash
written under weaker parameters still verifies.

Not bcrypt: OWASP notes it *"has a maximum length input length of 72 bytes for
most implementations"*, so a long passphrase silently loses entropy.

*Weight: normative.*

### Minimum length, no composition rules

Twelve characters. No required uppercase, digit or symbol.

**Why.** Composition rules push people towards predictable substitutions
without adding real entropy. OWASP Authentication Cheat Sheet takes the same
position.

*Weight: normative.*

### Access token JWT, refresh token opaque

Access: JWT, 15 minutes, HS256, with `kid` in the header and the algorithm
pinned on verify. Refresh: 32 random bytes, stored only as SHA-256.

**Why HS256 and not RS256.** RS256 exists so a *second service* can verify
without a shared secret. There is one service. The migration later is cheap
precisely because refresh tokens are opaque rather than JWTs: issue new access
tokens under a new `kid`, accept both for fifteen minutes, done. No forced
logout. `kid` is present from the first token issued so that path stays open.

**Why pin the algorithm.** Not pinning is how `alg: none` and
"RS256 public key used as an HMAC secret" attacks work. There are tests for
both, and for a token signed with an unknown `kid`.

**Why claims are minimal.** A JWT cannot be revoked, so every claim in it is
stale data until it expires. `sub`, `iat`, `exp`, `jti`, `typ` and nothing else.

*Weight: ours, informed by RFC 9700 §4.14 on token handling.*

### Refresh token rotation with reuse detection

Every refresh spends the old token and mints a new one in the same chain.
Presenting an already-spent token revokes the entire chain.

**Why.** RFC 9700 §2.2.2: *"Refresh tokens for public clients MUST be
sender-constrained or use refresh token rotation."* §4.14 treats reuse
detection as the mechanism that makes rotation meaningful.

When one token appears twice, two parties hold it and there is no way to tell
which is the owner. Ending the session for both is the only safe answer. The
legitimate user is signed out too; that is the intended cost, and there is a
test asserting exactly it.

Expiry is **not** evidence of theft, so an aged-out token does not take the
chain down. Also tested.

Spending a token is a single conditional `UPDATE`, so concurrent requests
cannot both win. A read-then-write would let both see it unused. There is a
test racing eight goroutines for one token, against a real Postgres.

*Weight: normative.*

### Refresh token delivery differs by client

`X-Client-Platform: web` gets an httpOnly, `SameSite=Lax` cookie scoped to
`/v1/auth` and **nothing** in the response body. Native clients get it in the
body and no cookie.

**Why.** A token a script can read is a token XSS can steal. The browser flow's
callback also puts no access token in the URL, where it would land in browser
history and `Referer` headers; the app calls `/v1/auth/refresh` instead.

*Weight: ours, standard practice.*

### Authorization Code with PKCE, never implicit

**Why.** RFC 9700 §2.1.1: public clients *"MUST use PKCE"*, and for confidential
clients *"the use of PKCE is RECOMMENDED"*. It adds, explicitly: *"Although
PKCE was designed as a mechanism to protect native apps, this advice applies to
all kinds of OAuth clients, including web applications."* We apply it
everywhere, which costs one parameter.

Implicit flow is out: RFC 9700 §2.1.2 says clients *"MUST NOT use the implicit
grant"*.

*Weight: normative.*

### OAuth state is server-side and single use

Stored in Postgres, deleted as it is read.

**Why.** A cookie alone gives no replay protection. Without server-side
single-use state, a captured callback URL can be replayed, and a forged
callback lets an attacker attach their provider account to a victim's session.

In Postgres rather than Redis because one small table is not worth another
process to run, monitor and back up, and it has to survive a restart in the
middle of a login, which an in-memory map does not.

*Weight: normative for the requirement; the storage choice is ours.*

### Aged-out records are swept

A background loop deletes expired `oauth_states` and `verification_tokens`, and
`refresh_tokens` past a 30-day grace period.

**Why.** Every abandoned sign-in leaves an `oauth_states` row behind. Without a
sweep the table grows forever, and an attacker can drive that by repeatedly
starting a sign-in they never finish. The generated delete query existed from
the start and nothing called it, which is how the leak went unnoticed until a
stale row turned up while checking something else.

Refresh tokens get a grace period rather than being deleted on the day they
expire: a spent token replayed shortly after expiry should still be recognised
as reuse and take its chain down. Once it is long dead the row is worthless.

*Weight: ours.*

### Provider identity is the provider's stable subject, not the email

`auth_identities(provider, provider_user_id)` with a unique index.

**Why.** An email is not an identity: a Workspace admin can change it. Google's
`sub` is stable for the life of the account.

**Microsoft is different and this is the trap.** Entra ID's `sub` is unique per
*(user, application)* pair, so registering a second application gives the same
person a different `sub`. The stable identity there is `tid` + `oid`. This is
why `Provider` is an interface with its own subject mapping rather than a
shared `claims.Sub`.

*Weight: ours, from provider documentation.*

### The audience allowlist is checked by hand

`go-oidc` runs with `SkipClientIDCheck`, and the `aud` claim is checked against
a configured allowlist.

**Why.** Without an audience check, an ID token Google issued for *some other
application* would sign its holder in here. A list rather than one value
because a native client passing the web client ID as its server client ID
produces tokens whose `aud` is the web client ID on every platform, with `azp`
naming the app. One allowlist covers all of them.

*Weight: normative (OpenID Connect Core §3.1.3.7 ID token validation).*

### Account linking is automatic only against a verified address

| Condition | Action |
|---|---|
| Identity already exists | Sign in |
| Address not registered | Create account and identity, already verified |
| Registered, local address **verified** | Link |
| Registered, local address **not verified** | Refuse |
| Provider says the address is unverified | Refuse |

**Why the fourth row.** An attacker registers with an address they do not own
and never verifies it. The real owner later signs in with the provider.
Automatic linking would hand the attacker's account — whose password they know
— to the victim, along with everything the victim then puts in it.

The consequence runs backwards through the whole design: **email verification
is a prerequisite for safe SSO, not a separate nicety.** It is why registration
issues no session, and why it was built in phase 1 rather than left for later.

There is a test that plays out this exact takeover.

*Weight: ours, standard account-linking guidance.*

### The last way to sign in can never be removed

**Why.** Someone who signed up with a provider and never set a password would
otherwise unlink it and lose the account permanently.

*Weight: ours.*

### Failed sign-in answers are indistinguishable

Unknown email, wrong password, and an SSO-only account all return the same
`401` body, and a dummy argon2 hash runs on the miss so the timing matches too.

**Why.** Otherwise the endpoint is a user enumeration oracle: unknown emails
answer in milliseconds while wrong passwords take tens of them.

*Weight: normative (OWASP Authentication Cheat Sheet).*

### Login is limited per email, not per address

**Why.** Per-address limiting is defeated by rotating IPs. The check runs
*before* the argon2 hash, so a flood of guesses costs a map lookup rather than
19 MiB and a few milliseconds each.

*Weight: ours.*

---

## Email

### SMTP, not a provider SDK

**Why.** The same code talks to Mailpit, Gmail, Resend or SES with nothing but
environment variables changing. Binding to one provider's HTTP API would buy
webhooks and delivery reporting at the cost of a rewrite to move. That is the
same reasoning as `Provider` for identity providers.

Sending is separated from rendering so a message can be built and asserted on
without an SMTP server, which is what the tests do: they parse the MIME output
and decode each part the way a mail client would.

*Weight: ours.*

### The link points at the front end, never at this API

`APP_BASE_URL/verify-email?token=...`, and that page POSTs to the API.

**Why.** A link in an email is fetched before anyone clicks it. Mail scanners,
antivirus and link previews in chat apps all do it. Verification tokens are
single use, so an API endpoint that consumed one on GET would be burned by a
scanner, and the recipient would be told their link was already used. A front
end page is safe to prefetch: it only loads, and the POST happens when a person
actually acts.

This is also why there is no `GET /v1/auth/verify-email`, however convenient it
would be while there is no front end.

*Weight: ours, standard practice.*

## HTTP

### CORS is an exact allowlist

**Why.** Reflecting whatever `Origin` arrives, combined with
`Allow-Credentials`, lets any site on the internet make authenticated calls on
a signed-in user's behalf. `Vary: Origin` is set so caches cannot hand one
origin's response to another.

*Weight: ours, standard practice.*

### `X-Forwarded-For` is ignored unless a proxy is declared

`HTTP_TRUSTED_PROXY_HOPS` defaults to 0. When set, the entry that many places
from the **right** is used.

**Why.** The header is appended to, so everything left of what your own proxy
wrote is caller-supplied. Trusting it unguarded lets anyone rotate their
apparent address straight through every rate limit.

*Weight: ours, standard practice.*

### `redirect_to` must be a single-slash path

**Why.** [CWE-601](https://cwe.mitre.org/data/definitions/601.html). `//evil.com`
is a protocol-relative URL that browsers treat as an external host, which is
why rejecting only `http://` and `https://` is not enough.

*Weight: normative.*

### Two security headers, not a copied list

`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

**Why.** CSP and `X-Frame-Options` are aimed at HTML. On a response that is
always `application/json` they protect nothing, and their presence only
suggests the list was copied rather than chosen.

*Weight: ours.*

### Explicit HTTP timeouts

**Why.** Go ships no default read, write or idle timeout, so without them one
slow client can hold a connection indefinitely.

*Weight: official (`net/http.Server` documentation).*

### Authentication fails closed

A route needs a token unless it is listed in `publicPaths` or matches a
`publicPatterns` entry, where `{provider}` matches exactly one segment.

**Why.** A new route is protected the moment it exists, and opening one is a
deliberate edit in a single visible place. An earlier draft used a
`/v1/auth/` prefix, which would have silently opened every future route under
it; there is now a test asserting `/v1/auth/google/start/extra` still requires
a token.

*Weight: ours.*

---

## Containers

### Distroless runtime, alpine builder

**Why.** [Distroless](https://github.com/GoogleContainerTools/distroless) static
carries CA certificates, which the Google OIDC calls need and which `scratch`
does not have; the failure there is a confusing TLS error. It also runs as
nonroot and ships no shell, so a compromised image offers nothing to exec into.
Confirmed: `docker exec ... sh` fails. Image size 22.7 MB.

`CGO_ENABLED=0` for a static binary, `-trimpath` for reproducibility, `-s -w`
to drop the symbol table.

*Weight: ours, standard practice.*

### The binary probes itself

`docker compose` health check runs `/api -health`.

**Why.** There is no shell in the image, so the usual `CMD-SHELL curl` cannot
work. Skipping the check is worse than it sounds: without one,
`docker compose up --wait` reported a **crash-looping container as healthy**.
That happened here, and the app was restarting on a missing `JWT_SECRET` while
the command claimed success.

Kubernetes does not need this, since kubelet performs HTTP probes itself.

*Weight: ours, from a real false signal.*

### Compose reads `.env` and overrides only what must differ

`env_file: .env`, with `POSTGRES_DSN` overridden because inside the network
Postgres answers to its service name.

**Why.** The earlier version listed environment variables by hand and fell out
of date the moment a new one was required, which is how the crash-loop above
happened. One source of configuration, one documented exception.

*Weight: ours, from the same incident.*

### Probe paths are not logged

**Why.** An orchestrator calls `/healthz` every few seconds forever. Logging
each one buries everything else; the logs here were 100% health checks before
this.

*Weight: ours.*

## Testing

### Store tests run against a real Postgres

`testcontainers-go`, skipped by `-short`.

**Why.** Mocking SQL tests the mock. A typo in a column name, a constraint that
never fires, and a CTE that is not actually atomic all survive a fake store and
none survive a real database. The eight-goroutine race on one refresh token is
only meaningful against the real thing.

*Weight: ours.*

### Tests derive their context from the test

`t.Context()` rather than `context.Background()`.

**Why.** Go 1.24: *"The new `T.Context` and `B.Context` methods return a
context that's canceled after the test completes and before test cleanup
functions run."* It also resolves the conflict between "`ctx` comes first" and
"`t` comes first in a test helper" by removing the parameter.

*Weight: official.*

---

## Deliberately not here

| Not used | Why |
|---|---|
| gRPC, GraphQL | No consumer. Two transports maintained for nobody is real cost |
| Hexagonal ports and adapters throughout | Boilerplate-to-logic ratio is poor at this size. An interface at the store boundary gives most of the benefit |
| DDD aggregates, value objects, domain events | No invariant here needs an aggregate root |
| `wire`, `fx` | Manual wiring is explicit and compile-time |
| ORM | Hides the SQL that actually runs |
| `pkg/` | The Go repository does not have one |
| Struct-tag validation | Reflection over a stringly-typed DSL |
| A line limit per file | Replaced by per-function complexity gates |
| RS256 and JWKS *for now* | No second service needs to verify. `kid` is present so the migration stays cheap |
| Redis *for now* | Single instance. `ratelimit.Limiter` is the seam |
| Microservices | No scaling or release-cadence problem forces it. The per-feature layout keeps the option cheap |
| OpenTelemetry *for now* | Nowhere to send traces yet. `X-Request-Id` gives most of the debugging value meanwhile |

Each "for now" has a stated trigger. When the trigger fires, revisit; until
then, the cost is not paid.
