-- Migration 000005 rollback: Restore original unique constraint
--
-- WARNING: This rollback will fail if the database contains any messages where
-- both an active and expunged message exist with the same (message_id, mailbox_id).
--
-- To safely rollback:
-- 1. Ensure background cleaner has run to remove old expunged messages
-- 2. Or manually delete expunged messages: DELETE FROM messages WHERE expunged_at IS NOT NULL;
-- 3. Then apply this migration

-- Drop the partial unique index
DROP INDEX IF EXISTS messages_message_id_mailbox_id_active_idx;

-- Restore the original unique constraint
-- This will fail if there are any duplicate (message_id, mailbox_id) pairs,
-- even if some are expunged
ALTER TABLE messages
    ADD CONSTRAINT messages_message_id_mailbox_id_key
    UNIQUE (message_id, mailbox_id);

-- Note: After rollback, same-mailbox MOVE operations will fail again.
