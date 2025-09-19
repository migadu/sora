-- Drop objects in the reverse order of creation.

-- 1. Drop the triggers from the messages table
DROP TRIGGER IF EXISTS trigger_messages_stats_update ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_delete ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_insert ON messages;

-- 2. Drop the trigger function
DROP FUNCTION IF EXISTS maintain_mailbox_stats();

-- 3. Drop the caching table
DROP TABLE IF EXISTS mailbox_stats;