-- Migration: Add covering partial index for expunge lookups
-- This directly optimizes the UPDATE ... WHERE m.mailbox_id = $1 AND m.uid = t.uid AND m.expunged_at IS NULL

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_expunge_lookup 
ON messages (mailbox_id, uid) 
WHERE expunged_at IS NULL;
