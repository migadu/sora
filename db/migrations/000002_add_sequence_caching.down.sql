-- Drop objects in the reverse order of creation.

-- 1. Drop the triggers from the messages table
DROP TRIGGER IF EXISTS trigger_messages_update_sequence ON messages;
DROP TRIGGER IF EXISTS trigger_messages_delete_sequence ON messages;
DROP TRIGGER IF EXISTS trigger_messages_insert_sequence ON messages;

-- 2. Drop the trigger function
DROP FUNCTION IF EXISTS maintain_message_sequences();

-- 3. Drop the caching table
DROP TABLE IF EXISTS message_sequences;