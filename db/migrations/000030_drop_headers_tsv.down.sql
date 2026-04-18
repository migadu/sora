-- Rollback migration 000030: Re-create headers_tsv index and headers column
--
-- WARNING: This rollback will NOT restore the old data! The headers and headers_tsv
-- columns will be empty after rollback. Messages will need to be re-indexed by
-- the FTS worker if you need header search functionality.

-- Re-create columns
ALTER TABLE messages_fts ADD COLUMN IF NOT EXISTS headers TEXT;
ALTER TABLE messages_fts ADD COLUMN IF NOT EXISTS headers_tsv tsvector;

-- Re-create index
CREATE INDEX IF NOT EXISTS idx_messages_fts_headers_tsv ON messages_fts USING GIN (headers_tsv);
