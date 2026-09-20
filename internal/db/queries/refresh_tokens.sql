-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, client_platform, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: UseRefreshToken :one
-- Spending a token is a single conditional UPDATE, so two requests racing with
-- the same token cannot both win: exactly one updates a row, the other sees
-- none and is treated as reuse.
UPDATE refresh_tokens
SET used_at = now()
WHERE token_hash = $1
  AND used_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > now()
RETURNING id, user_id, family_id;

-- name: RefreshTokenByHash :one
-- Only read after UseRefreshToken found nothing, to tell a replayed token
-- apart from one that merely expired.
SELECT user_id, family_id, used_at, revoked_at, expires_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: RevokeRefreshFamily :exec
UPDATE refresh_tokens
SET revoked_at = now()
WHERE family_id = $1
  AND revoked_at IS NULL;
