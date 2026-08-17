-- +goose Up

-- Addresses we must not send to again.
--
-- The address is stored hashed as well as in clear: the hash is what lookups
-- use, so a future release can drop the clear column for deployments that want
-- suppression without holding recipient data.
CREATE TABLE suppressions (
    id           BIGSERIAL PRIMARY KEY,
    address      TEXT        NOT NULL,
    address_hash BYTEA       NOT NULL UNIQUE,
    reason       TEXT        NOT NULL
        CHECK (reason IN ('hard_bounce', 'complaint', 'manual', 'unsubscribe', 'spam_trap')),
    detail       TEXT,
    message_id   TEXT        REFERENCES messages (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX suppressions_created_idx ON suppressions (created_at DESC);
CREATE INDEX suppressions_reason_idx ON suppressions (reason);

-- +goose Down
DROP TABLE IF EXISTS suppressions;
