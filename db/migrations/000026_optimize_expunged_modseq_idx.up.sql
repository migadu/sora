-- Replace partial index with a covering one to support "IS NULL OR > X" queries efficiently

-- We must drop the existing one first because it has a WHERE clause
DROP INDEX IF EXISTS idx_messages_expunged_modseq;

-- Create the new covering index
CREATE INDEX IF NOT EXISTS idx_messages_expunged_modseq 
    ON messages (mailbox_id, expunged_modseq);
