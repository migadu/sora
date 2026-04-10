-- Drop the message sequence triggers
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_insert ON messages;
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_update ON messages;
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_delete ON messages;

-- Drop the associated maintenance function
DROP FUNCTION IF EXISTS maintain_message_sequences();

-- Drop the message_sequences cache table cascade
DROP TABLE IF EXISTS message_sequences CASCADE;

-- Add a partial covering index for efficient dynamic sequence number computation.
-- This replaces the dropped message_sequences table with a much lighter alternative.
-- Enables index-only scans for COUNT(*) queries used in the offset+range seqnum pattern
-- (e.g., counting non-expunged messages before a UID to compute sequence position).
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_uid_active
    ON messages (mailbox_id, uid) WHERE expunged_at IS NULL;

-- Add a partial index to instantly resolve the first unseen message UID in O(1) time.
-- This prevents full-table heap scans during Poll and IMAP SELECT operations
-- when computing the FirstUnseenSeqNum for mailboxes with massive archives.
CREATE INDEX IF NOT EXISTS idx_messages_first_unseen
    ON messages (mailbox_id, uid) WHERE (flags & 1) = 0 AND expunged_at IS NULL;
