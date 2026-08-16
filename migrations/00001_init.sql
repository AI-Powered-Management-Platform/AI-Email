-- +goose Up

-- Sending domains. Proof state and last-check time are separate because
-- verification is re-checked continuously: a domain that stops proving
-- ownership must stop sending, even though it verified once.
CREATE TABLE domains (
    id                 BIGSERIAL PRIMARY KEY,
    name               TEXT        NOT NULL UNIQUE,
    verification_token TEXT        NOT NULL,
    status             TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'suspended')),
    verified_at        TIMESTAMPTZ,
    last_checked_at    TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX domains_status_checked_idx ON domains (status, last_checked_at);

-- API keys are bearer credentials, so only a hash is stored: a database read
-- must never yield a usable key. The prefix is kept in clear for display and
-- for public secret scanners.
CREATE TABLE api_keys (
    id             BIGSERIAL PRIMARY KEY,
    name           TEXT        NOT NULL,
    prefix         TEXT        NOT NULL,
    secret_hash    BYTEA       NOT NULL UNIQUE,
    scopes         TEXT[]      NOT NULL DEFAULT '{}',
    quota_per_hour INTEGER     NOT NULL DEFAULT 0 CHECK (quota_per_hour >= 0),
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    last_used_ip   INET,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX api_keys_active_idx ON api_keys (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE messages (
    id           TEXT        PRIMARY KEY,
    api_key_id   BIGINT      REFERENCES api_keys (id) ON DELETE SET NULL,
    domain_id    BIGINT      NOT NULL REFERENCES domains (id) ON DELETE RESTRICT,
    status       TEXT        NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'sending', 'sent', 'delivered', 'deferred', 'bounced', 'failed', 'cancelled')),
    from_address TEXT        NOT NULL,
    recipients   TEXT[]      NOT NULL,
    subject      TEXT        NOT NULL,
    body_html    TEXT,
    body_text    TEXT,
    headers      JSONB       NOT NULL DEFAULT '{}',
    tags         JSONB       NOT NULL DEFAULT '{}',
    attempts     INTEGER     NOT NULL DEFAULT 0,
    scheduled_at TIMESTAMPTZ,
    locked_until TIMESTAMPTZ,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The claim query orders by scheduled work that is not locked; this index is
-- what keeps the queue from scanning the whole table under load.
CREATE INDEX messages_claimable_idx
    ON messages (status, scheduled_at, locked_until)
    WHERE status IN ('queued', 'deferred');

CREATE INDEX messages_created_idx ON messages (created_at DESC);

CREATE TABLE message_events (
    id          BIGSERIAL PRIMARY KEY,
    message_id  TEXT        NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    type        TEXT        NOT NULL,
    detail      JSONB       NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX message_events_message_idx ON message_events (message_id, occurred_at);

-- Idempotency is scoped to the key that issued the request so one tenant can
-- never observe or collide with another's keys. The request hash detects the
-- same key being reused with a different body.
CREATE TABLE idempotency_records (
    api_key_id   BIGINT      NOT NULL REFERENCES api_keys (id) ON DELETE CASCADE,
    key          TEXT        NOT NULL,
    request_hash BYTEA       NOT NULL,
    message_id   TEXT        REFERENCES messages (id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (api_key_id, key)
);

CREATE INDEX idempotency_expiry_idx ON idempotency_records (expires_at);

-- +goose Down
DROP TABLE IF EXISTS idempotency_records;
DROP TABLE IF EXISTS message_events;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS domains;
