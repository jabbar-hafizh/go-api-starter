-- +goose Up
-- +goose StatementBegin
CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- SHA-256, never the raw token. The token already carries 256 bits of
    -- entropy, so there is nothing for a slow password hash to protect.
    token_hash bytea       NOT NULL UNIQUE,
    -- Every token minted by rotating an earlier one keeps the same family_id.
    -- Presenting a token that was already spent means two parties hold it, so
    -- the whole family is revoked rather than just that one token.
    family_id  uuid        NOT NULL,
    -- Web sessions are shorter than mobile ones: a phone user will not accept
    -- signing in again every week.
    client_platform text,
    used_at    timestamptz,
    revoked_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS refresh_tokens;
-- +goose StatementEnd
