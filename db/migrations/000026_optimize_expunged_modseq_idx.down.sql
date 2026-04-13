-- Revert to the partial index

DROP INDEX IF EXISTS idx_messages_expunged_modseq;

CREATE INDEX IF NOT EXISTS idx_messages_expunged_modseq
    ON messages (mailbox_id, expunged_modseq)
    WHERE expunged_modseq IS NOT NULL;
