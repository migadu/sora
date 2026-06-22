-- Index message_state.mailbox_id so the FK ON DELETE CASCADE can find rows by mailbox.
--
-- message_state has `mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE`
-- (migration 000022), but its only mailbox_id-leading indexes are PARTIAL
-- (idx_message_state_mailbox_id_updated_modseq WHERE updated_modseq IS NOT NULL, and
-- idx_message_state_first_unseen WHERE (flags & 1) = 0). Neither can satisfy the
-- referential-action query `DELETE FROM message_state WHERE mailbox_id = $1`, so every
-- mailbox delete (IMAP DELETE, account/domain purge, HardDeleteAccounts) sequentially
-- scanned the entire message_state table.
--
-- Observed in production: deleting a mailbox with 5 state rows scanned 76.9M rows / ~5.5GB
-- and took 9.4s, with cost scaling to the GLOBAL table size rather than the mailbox's.
-- A plain b-tree on mailbox_id turns the cascade into an index scan.
--
-- NOTE: this CREATE INDEX takes a SHARE lock that blocks writes to message_state while the
-- index builds. On a large table, pre-build it out-of-band first so this no-ops:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_message_state_mailbox_id
--     ON message_state (mailbox_id);
CREATE INDEX IF NOT EXISTS idx_message_state_mailbox_id
ON message_state (mailbox_id);
