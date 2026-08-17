-- +goose Up

CREATE TABLE webhook_endpoints (
    id         BIGSERIAL PRIMARY KEY,
    url        TEXT        NOT NULL,
    secret     BYTEA       NOT NULL,
    active     BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webhook_endpoints_active_idx ON webhook_endpoints (active) WHERE active;

-- Deliveries are queued rather than sent inline so a slow or hostile endpoint
-- cannot stall message delivery, and so a failed POST is retried rather than
-- lost. The event payload is frozen at enqueue time: a replay must resend what
-- happened, not what is true now.
CREATE TABLE webhook_deliveries (
    id           BIGSERIAL PRIMARY KEY,
    endpoint_id  BIGINT      NOT NULL REFERENCES webhook_endpoints (id) ON DELETE CASCADE,
    event_id     TEXT        NOT NULL,
    message_id   TEXT        REFERENCES messages (id) ON DELETE SET NULL,
    payload      JSONB       NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivering', 'delivered', 'failed')),
    attempts     INTEGER     NOT NULL DEFAULT 0,
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ,
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (endpoint_id, event_id)
);

CREATE INDEX webhook_deliveries_claimable_idx
    ON webhook_deliveries (status, next_attempt, locked_until)
    WHERE status = 'pending';

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
