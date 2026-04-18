-- Migration 000030: Drop headers_tsv index and headers column from messages_fts
--
DROP INDEX IF EXISTS idx_messages_fts_headers_tsv;

-- Drop the headers and headers_tsv columns
ALTER TABLE messages_fts DROP COLUMN IF EXISTS headers;
ALTER TABLE messages_fts DROP COLUMN IF EXISTS headers_tsv;
