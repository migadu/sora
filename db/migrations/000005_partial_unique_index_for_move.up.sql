-- Migration 000005: Convert unique constraint to partial unique index
--
-- This migration enables same-mailbox MOVE operations (RFC 6851) by allowing
-- temporarily having duplicate (message_id, mailbox_id) pairs when one is expunged.
--
-- The partial unique index still prevents duplicate active messages (the important case)
-- while allowing active + expunged duplicates during move operations.
--
-- Performance benefits:
-- - Smaller index size (excludes expunged rows, typically 10-30% reduction)
-- - Faster queries on active messages
-- - Faster INSERT operations
-- - Consistent with existing partial index patterns in schema

-- Drop the old unique constraint
ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_message_id_mailbox_id_key;

-- Create partial unique index that only covers active messages
-- This allows multiple rows with same (message_id, mailbox_id) as long as all but one are expunged
CREATE UNIQUE INDEX messages_message_id_mailbox_id_active_idx
    ON messages (message_id, mailbox_id)
    WHERE expunged_at IS NULL;

-- Note: No data migration needed. All existing data remains valid.
-- The new index is strictly more permissive than the old constraint.
