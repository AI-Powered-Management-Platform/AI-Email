-- +goose Up

-- Signing keys are stored wrapped, never in clear. There is deliberately no
-- column holding usable key material: reading this table yields ciphertext
-- that is worthless without the master key held outside the database.
CREATE TABLE dkim_keys (
    id             BIGSERIAL PRIMARY KEY,
    domain_id      BIGINT      NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    selector       TEXT        NOT NULL,
    algorithm      TEXT        NOT NULL CHECK (algorithm IN ('ed25519', 'rsa')),
    wrapped_secret BYTEA       NOT NULL,
    public_record  TEXT        NOT NULL,
    active         BOOLEAN     NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at     TIMESTAMPTZ,
    UNIQUE (domain_id, selector)
);

-- Two keys may be active at once so rotation does not require downtime: the
-- new public record is published, both sign, then the old one retires.
CREATE INDEX dkim_keys_active_idx ON dkim_keys (domain_id) WHERE active;

-- Counts signatures per message so a replayed signature is visible. A single
-- message that keeps being signed, or a signature seen far more often than it
-- was issued, is the replay signature described in the threat model.
ALTER TABLE messages ADD COLUMN signed_at TIMESTAMPTZ;

-- +goose Down
ALTER TABLE messages DROP COLUMN IF EXISTS signed_at;
DROP TABLE IF EXISTS dkim_keys;
