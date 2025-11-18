-- Add indexes to optimize PollMailbox query performance
-- These indexes support efficient filtering by modseq values

-- Index for filtering messages by modseq changes
-- Supports queries like: WHERE mailbox_id = X AND updated_modseq > Y
CREATE INDEX IF NOT EXISTS idx_messages_updated_modseq
    ON messages (mailbox_id, updated_modseq)
    WHERE updated_modseq IS NOT NULL;

-- Index for filtering messages by created_modseq
-- Supports queries like: WHERE mailbox_id = X AND created_modseq > Y
CREATE INDEX IF NOT EXISTS idx_messages_created_modseq
    ON messages (mailbox_id, created_modseq);

-- Index for filtering messages by expunged_modseq
-- Supports queries like: WHERE mailbox_id = X AND expunged_modseq > Y
CREATE INDEX IF NOT EXISTS idx_messages_expunged_modseq
    ON messages (mailbox_id, expunged_modseq)
    WHERE expunged_modseq IS NOT NULL;

-- Composite index to support the combined modseq filter in PollMailbox
-- This helps PostgreSQL efficiently identify changed messages
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_modseqs
    ON messages (mailbox_id, created_modseq, updated_modseq, expunged_modseq);
