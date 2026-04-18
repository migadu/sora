-- Down migration: Restore duplicate and redundant indexes
-- (If we ever need to roll back this cleanup)

CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_expunged_modseq ON messages (mailbox_id, expunged_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_expunge_lookup ON messages (mailbox_id, uid) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_expunged_at_is_null ON messages (mailbox_id) WHERE expunged_at IS NULL;
