-- +goose Up
-- +goose StatementBegin
-- A lookup table rather than free text or an enum. Free text lets 'Google' and
-- 'google' become two providers nobody notices; an enum makes adding one a
-- schema migration. This way a new provider is an INSERT, and the client can
-- read the list to decide which buttons to render.
CREATE TABLE auth_providers (
    code         text PRIMARY KEY,
    display_name text    NOT NULL,
    enabled      boolean NOT NULL DEFAULT true
);

INSERT INTO auth_providers (code, display_name) VALUES ('google', 'Google');

CREATE TABLE auth_identities (
    id       uuid PRIMARY KEY,
    user_id  uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider text NOT NULL REFERENCES auth_providers (code),
    -- The provider's stable subject, which is not the same claim everywhere.
    -- Google's sub is stable forever. Microsoft's sub is unique per user AND
    -- application, so registering a second app gives the same person a new
    -- one; there the stable identity is tid + oid. Each provider decides.
    provider_user_id text NOT NULL,
    -- The address as the provider reported it, which can differ from
    -- users.email. Kept for audit and for re-linking.
    email      text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_user_id)
);

CREATE INDEX auth_identities_user_id_idx ON auth_identities (user_id);

-- Short lived, single use, and in Postgres rather than Redis: one small table
-- is not worth another process to run, monitor and back up. It also has to
-- survive a restart in the middle of a login, which an in-memory map does not.
CREATE TABLE oauth_states (
    state         text PRIMARY KEY,
    nonce         text        NOT NULL,
    code_verifier text        NOT NULL,
    provider      text        NOT NULL REFERENCES auth_providers (code),
    redirect_to   text,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX oauth_states_expires_at_idx ON oauth_states (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_states;
DROP TABLE IF EXISTS auth_identities;
DROP TABLE IF EXISTS auth_providers;
-- +goose StatementEnd
