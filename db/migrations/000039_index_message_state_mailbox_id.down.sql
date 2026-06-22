-- Rollback the message_state.mailbox_id FK-cascade index.
DROP INDEX IF EXISTS idx_message_state_mailbox_id;
