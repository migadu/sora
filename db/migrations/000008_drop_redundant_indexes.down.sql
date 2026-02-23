-- Restore the indexes that were dropped as redundant.
CREATE INDEX IF NOT EXISTS idx_messages_content_hash ON messages (content_hash);
CREATE INDEX IF NOT EXISTS idx_messages_account_id ON messages (account_id);

-- Drop the headers pruning index added in the up migration.
DROP INDEX IF EXISTS idx_message_contents_headers_not_null;
