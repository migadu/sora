-- Drop redundant indexes on messages table to reclaim ~810 MB of disk space.
--
-- idx_messages_content_hash: (content_hash) is a leading prefix of
-- idx_messages_content_hash_account_id (content_hash, account_id), so PostgreSQL
-- can use the composite index for content_hash-only lookups.
DROP INDEX IF EXISTS idx_messages_content_hash;

-- idx_messages_account_id: (account_id) is a leading prefix of
-- idx_messages_account_mailbox_hash (account_id, mailbox_id, content_hash), so
-- PostgreSQL can use the composite index for account_id-only lookups.
DROP INDEX IF EXISTS idx_messages_account_id;

-- Add partial index for headers pruning in the cleaner.
-- The existing idx_message_contents_text_body_not_null only covers text_body IS NOT NULL.
-- After text_body is pruned, the cleaner needs to efficiently find rows where headers
-- still needs pruning.
--
-- NOTE: This uses regular CREATE INDEX (not CONCURRENTLY) because golang-migrate
-- wraps migrations in a transaction. This takes a SHARE lock on message_contents,
-- blocking writes for the duration of index creation.
-- For zero-downtime deployments on large databases, create the index manually first:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_message_contents_headers_not_null
--       ON message_contents (content_hash) WHERE headers IS NOT NULL;
-- Then this migration becomes a no-op due to IF NOT EXISTS.
CREATE INDEX IF NOT EXISTS idx_message_contents_headers_not_null
    ON message_contents (content_hash) WHERE headers IS NOT NULL;
