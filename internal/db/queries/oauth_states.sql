-- name: CreateOAuthState :exec
INSERT INTO oauth_states (state, nonce, code_verifier, provider, redirect_to, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: ConsumeOAuthState :one
-- Deleting as it is read makes the state single use, which is what stops a
-- captured callback URL from being replayed.
DELETE FROM oauth_states
WHERE state = $1
  AND expires_at > now()
RETURNING nonce, code_verifier, provider, redirect_to;

-- name: DeleteExpiredOAuthStates :exec
DELETE FROM oauth_states WHERE expires_at <= now();
