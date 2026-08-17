-- +goose Up

-- Recipient addresses are the personal data in this system. Storing them in
-- clear means a leaked backup, replica, or query log is a leaked contact list.
--
-- The encrypted column is added alongside the existing one rather than
-- replacing it in place: the application writes ciphertext from now on and
-- reads whichever column is populated, so an existing deployment keeps working
-- while old rows age out under its retention window.
ALTER TABLE messages ADD COLUMN recipients_encrypted BYTEA;

-- The hash is what any lookup uses, so queries never need the plaintext back.
ALTER TABLE messages ADD COLUMN recipients_hash BYTEA[];

CREATE INDEX messages_recipients_hash_idx ON messages USING gin (recipients_hash);

-- New rows leave the cleartext column empty, so it can no longer be required.
ALTER TABLE messages ALTER COLUMN recipients DROP NOT NULL;

-- Existing rows keep their clear column until retention removes them. New rows
-- must not add to the pile, which the application enforces by always writing
-- the encrypted form.
COMMENT ON COLUMN messages.recipients IS
    'Deprecated: cleartext recipients from before encryption. New rows leave this null.';

-- +goose Down
DROP INDEX IF EXISTS messages_recipients_hash_idx;
ALTER TABLE messages DROP COLUMN IF EXISTS recipients_hash;
ALTER TABLE messages DROP COLUMN IF EXISTS recipients_encrypted;
