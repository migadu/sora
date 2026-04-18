-- Up migration: Drop exact duplicates and 100% redundant indexes

-- 1. Exact Duplicate: (mailbox_id, expunged_modseq) (overlaps with idx_messages_expunged_modseq)
DROP INDEX IF EXISTS idx_messages_expunged_modseq;

-- 2. Exact Duplicate: (mailbox_id, uid) WHERE expunged_at IS NULL (overlaps with idx_messages_mailbox_uid_active)
DROP INDEX IF EXISTS idx_messages_expunge_lookup;

-- 3. Redundant Prefix: (mailbox_id) WHERE expunged_at IS NULL (fully covered by (mailbox_id, uid) WHERE expunged_at IS NULL)
DROP INDEX IF EXISTS idx_messages_mailbox_id_expunged_at_is_null;
