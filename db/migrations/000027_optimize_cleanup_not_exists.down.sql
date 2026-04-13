-- Rollback migration 000027
DROP INDEX IF EXISTS idx_messages_account_hash_expunged;
DROP INDEX IF EXISTS idx_messages_account_hash_active;
