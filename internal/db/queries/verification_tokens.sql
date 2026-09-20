-- name: CreateVerificationToken :exec
INSERT INTO verification_tokens (id, user_id, purpose, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5);

-- name: ConsumeEmailVerification :one
-- Burning the token and marking the email verified must not be separable: if
-- the second half failed the token would be spent and the user still
-- unverified. One statement makes that impossible without a transaction.
WITH consumed AS (
    UPDATE verification_tokens
    SET used_at = now()
    WHERE token_hash = $1
      AND purpose = 'email_verify'
      AND used_at IS NULL
      AND expires_at > now()
    RETURNING user_id
)
UPDATE users
SET email_verified_at = COALESCE(users.email_verified_at, now())
FROM consumed
WHERE users.id = consumed.user_id
RETURNING users.id;

-- name: DeleteExpiredVerificationTokens :exec
DELETE FROM verification_tokens WHERE expires_at <= now();
