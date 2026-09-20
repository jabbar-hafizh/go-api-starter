-- name: EnabledProviders :many
SELECT code, display_name
FROM auth_providers
WHERE enabled
ORDER BY display_name;

-- name: IdentityByProviderSubject :one
SELECT id, user_id, provider, provider_user_id, email
FROM auth_identities
WHERE provider = $1
  AND provider_user_id = $2;

-- name: IdentitiesByUser :many
SELECT id, user_id, provider, provider_user_id, email
FROM auth_identities
WHERE user_id = $1
ORDER BY created_at;

-- name: CreateIdentity :one
INSERT INTO auth_identities (id, user_id, provider, provider_user_id, email)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, provider, provider_user_id, email;

-- name: DeleteIdentity :one
DELETE FROM auth_identities
WHERE id = $1
  AND user_id = $2
RETURNING id;

-- name: CountAuthMethods :one
-- The number of ways this account can sign in. Removing the last one would
-- lock the owner out permanently, so nothing may drop this to zero.
SELECT
    (SELECT count(*) FROM auth_identities WHERE user_id = $1)
    + (SELECT count(*) FROM users WHERE id = $1 AND password_hash IS NOT NULL)
    AS methods;

-- name: CreateUserWithIdentity :one
-- One statement, because a user created without its identity would be an
-- account nobody can sign in to.
WITH new_user AS (
    INSERT INTO users (id, email, email_verified_at)
    VALUES ($1, $2, now())
    RETURNING id, email, email_verified_at, password_hash, created_at, updated_at
), new_identity AS (
    INSERT INTO auth_identities (id, user_id, provider, provider_user_id, email)
    SELECT $3, new_user.id, $4, $5, $6 FROM new_user
)
SELECT id, email, email_verified_at, password_hash, created_at, updated_at
FROM new_user;
