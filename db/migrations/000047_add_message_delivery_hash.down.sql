-- Rollback the delivery-identity column and its lookup index.
DROP INDEX IF EXISTS idx_messages_mailbox_delivery_hash;
ALTER TABLE messages DROP COLUMN IF EXISTS delivery_hash;
