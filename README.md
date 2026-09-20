# go-api-starter

Go backend API: password and Google sign-in for web and mobile clients.

One binary, one database, one package per feature inside it. The per-feature
layout keeps splitting into separate services cheap if that day comes, but it
is not done now because nothing forces it.

Every architectural decision, and the source it came from, is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). How to work in the repo is in
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Run it

Both paths need Docker running.

### Everything in Docker

```bash
cp .env.example .env
make up          # builds the image, starts Postgres, waits until healthy
make logs        # follow the app
make down        # stop, keep the data
```

The app container reaches Postgres by service name, so `POSTGRES_DSN` is set in
`docker-compose.yml` and overrides whatever is in `.env`.

### Postgres in Docker, app on the host

Faster to iterate on, because there is no image rebuild.

```bash
cp .env.example .env
make db-up       # Postgres only, waits until healthy
make run         # migrations run at boot
```

### Check it

```bash
curl localhost:8080/healthz   # {"status":"ok"}
curl localhost:8080/readyz    # 200 when every dependency is ready, 503 if not
open  localhost:8080/docs     # rendered API reference, from the embedded spec
```

`make help` lists every command.

---

## Configuration

Everything comes from the environment, is read once at boot, validated, and
reported **all at once** so a broken `.env` is fixed in one pass rather than one
deploy per mistake. See [.env.example](.env.example) for the full list with
comments.

The ones worth knowing:

| Variable | Default | Notes |
|---|---|---|
| `JWT_SECRET` | — | Required, at least 32 characters. `openssl rand -base64 48` |
| `APP_BASE_URL` | `http://localhost:3000` | Where the browser goes after a provider sign-in |
| `HTTP_ALLOWED_ORIGINS` | — | Exact CORS allowlist, comma separated. Empty means no browser may call the API |
| `HTTP_TRUSTED_PROXY_HOPS` | `0` | Proxies in front. 0 ignores `X-Forwarded-For` entirely |
| `ACCESS_TOKEN_TTL` | `15m` | |
| `REFRESH_TOKEN_TTL_WEB` | `168h` | 7 days |
| `REFRESH_TOKEN_TTL_MOBILE` | `720h` | 30 days |
| `RATE_LIMIT_*` | on | In-process, so per replica |
| `VALIDATE_SPEC` | `true` locally | Checks every request against the spec. Refused in production |
| `GOOGLE_CLIENT_ID` etc. | — | Optional. Empty means the Google endpoints answer 501 and everything else works |
| `MIN_CLIENT_VERSION_IOS` / `_ANDROID` | — | Empty disables the force-upgrade check |

`.env` is gitignored and excluded from the Docker build context, so secrets
never reach an image layer.

### Google sign-in

Optional. To turn it on, in Google Cloud Console create an **OAuth client ID**
of type **Web application** with this exact redirect URI:

```
http://localhost:8080/v1/auth/google/callback
```

Scopes are `openid`, `email`, `profile`, all non-sensitive, so no Google
verification review is needed. Put the client ID, secret and redirect URL in
`.env`. On boot the log says `google sso enabled` once discovery succeeds.

#### Trying it

The paths in the contract are written with a `{provider}` placeholder. For
Google, substitute `google`:

```
GET  /v1/auth/{provider}/start   →  /v1/auth/google/start
GET  /v1/auth/{provider}/callback → /v1/auth/google/callback
POST /v1/auth/{provider}/token  →  /v1/auth/google/token
```

**Open the browser flow in a browser, not from `/docs`.** The Try-it button
there issues an XHR, and this endpoint answers with a redirect to Google, which
an XHR cannot follow. Paste the URL into the address bar instead:

```
http://localhost:8080/v1/auth/google/start
```

You land back on `APP_BASE_URL`, and the refresh token arrives as an httpOnly
cookie. **No access token appears in the URL**, deliberately: it would end up in
browser history and `Referer` headers. The app calls `/v1/auth/refresh` to get
one, which works straight from the cookie the browser now holds.

`redirect_to` is appended to `APP_BASE_URL` and must be a path beginning with a
single slash, so `?redirect_to=/dashboard` lands on `APP_BASE_URL/dashboard`.
While there is no frontend, either omit it or point `APP_BASE_URL` at something
that exists.

To check it worked:

```bash
docker exec go-api-starter-postgres psql -U app -d app \
  -c "SELECT u.email, i.provider FROM users u JOIN auth_identities i ON i.user_id = u.id;"
```

The native path is different and needs no browser: a mobile app gets an ID
token from the Google SDK and posts it to `/v1/auth/google/token`.

---

## Endpoints

The contract is [docs/openapi.yaml](docs/openapi.yaml) and it is the source of
truth: handlers are generated from it, so an implementation that does not match
will not compile.

```
POST   /v1/auth/register                   email and password
POST   /v1/auth/login
POST   /v1/auth/refresh                    rotates the token
POST   /v1/auth/logout                     revokes the whole chain
POST   /v1/auth/verify-email
GET    /v1/auth/providers                  which sign-in buttons to render
GET    /v1/auth/{provider}/start           browser flow
GET    /v1/auth/{provider}/callback
POST   /v1/auth/{provider}/token           native flow, an ID token from the SDK

GET    /v1/me                              [auth]
GET    /v1/me/identities                   [auth]
POST   /v1/me/identities/{provider}        [auth] link
POST   /v1/me/identities/{id}/unlink       [auth]

POST   /v1/calculations                    [auth]
GET    /v1/app/config                      force-upgrade check

GET    /healthz   /readyz   /docs   /openapi.json
```

Two headers matter on every request: `X-Client-Platform` (`web` puts the
refresh token in an httpOnly cookie instead of the body) and `X-Client-Version`
(recorded, so there is evidence for when an old build has stopped calling an
endpoint you want to remove).

Registration deliberately issues no session. The email is verified first,
because that is what makes linking a Google account to it safe later. In local
development no mail is sent: the token is written to the log at warn level.

---

## Layout

```
cmd/api                  entrypoint
docs/openapi.yaml        the contract, written before the handlers
docs/ARCHITECTURE.md     every decision and where it came from

internal/
  app                    dependency wiring and server lifecycle
  config                 read env, validate, fail fast
  db                     connection, migrations, SQL, generated code
  openapi                generated from docs/openapi.yaml
  auth                   accounts, passwords, sessions, providers
  calculator             arithmetic
  appversion             whether a client build may still run
  token                  issue and verify access tokens
  ratelimit              how often a caller may act
  middleware             request id, logging, recover, CORS, limits, auth
  mailer                 transactional email
  health                 liveness and readiness
  httperr                the only place errors become HTTP responses
```

Only `internal/db/gen` and `internal/openapi` are generated. Everything else,
including the SQL and the spec, is written by hand.

---

## Tooling

`sqlc`, `oapi-codegen` and `goose` are pinned in `go.mod` as
[tool directives](https://go.dev/doc/go1.24), so `go tool <name>` runs identical
versions everywhere with no global install and no `PATH` changes.

`golangci-lint` is installed separately (`brew install golangci-lint`) and
pinned by version in CI, because pinning it the same way would drag hundreds of
linter dependencies into `go.mod`.

```bash
make generate    # sqlc + oapi-codegen
make verify      # the same gates CI runs
make test-short  # skip the tests that need Docker
make cover       # coverage, excluding generated code
```

---

## Known gaps

Written down rather than discovered later:

- **Setting and changing a password** is not implemented. An account created
  through Google has no password and currently no way to add one, so it is tied
  to Google. `verification_tokens.purpose` already allows `set_password`.
- **`provider_google.go` has no automated test.** The browser flow has been run
  end to end by hand and works: an account was created already verified, with a
  Google identity and a 7-day web session. But signature, issuer, audience and
  expiry checks have no automated coverage. Every other part of the auth design
  is tested, including the account-takeover case.
- **No email is actually sent.** `mailer.Log` writes the token to the log. The
  interface is in place for a real sender.
- **Rate limits are in-process**, so they are enforced per replica. Two replicas
  means twice the real ceiling. `ratelimit.Limiter` is the seam for a shared
  store.
- **Migrations run at boot.** Safe for one instance. Behaviour with several
  replicas deploying at once has not been verified.
