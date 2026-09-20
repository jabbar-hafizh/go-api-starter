-- name: CreateUser :one
INSERT INTO users (id, email, password_hash)
VALUES ($1, $2, $3)
RETURNING id, email, email_verified_at, password_hash, created_at, updated_at;

-- name: UserByEmail :one
SELECT id, email, email_verified_at, password_hash, created_at, updated_at
FROM users
WHERE email = $1;

-- name: UserByID :one
SELECT id, email, email_verified_at, password_hash, created_at, updated_at
FROM users
WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified_at = now() WHERE id = $1;

-- name: SetPasswordHash :exec
UPDATE users SET password_hash = $2 WHERE id = $1;
