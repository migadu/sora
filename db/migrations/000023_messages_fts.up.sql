-- Migration 023: full-text search moves from message_contents to messages_fts.
--
-- The copy of message_contents' search data below was missing from this file from
-- April 2026 until #791. A database that ran 23 without it keeps the vectors of the mail
-- it held only in message_contents, which nothing reads any more, so body search misses
-- all of that mail; scripts/fts_recover_message_contents.sql copies them into
-- messages_fts_v2. golang-migrate records only the version, so a database at or past 23
-- never runs this file again, and on a fresh install message_contents is empty and the
-- copy does nothing.

CREATE TABLE IF NOT EXISTS messages_fts (
    content_hash VARCHAR(64) PRIMARY KEY,
    headers TEXT,
    text_body TEXT,
    headers_tsv tsvector,
    text_body_tsv tsvector,
    sent_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Drop standard triggers that generated the TSVs automatically
DROP TRIGGER IF EXISTS message_contents_tsvector_update ON message_contents;

-- Copy every body's search data. Since 000016 that trigger nulled text_body once it had
-- computed text_body_tsv, so the vector is the only copy of a body's searchable text. A
-- row with text but no vector keeps its text, for the FTS worker to tokenise; a row with
-- a vector drops any text it still has (stored before 000016), as the worker would.
-- headers and headers_tsv are not copied: 000030 drops them. The copy runs before the
-- indexes below exist, so each is built once. 000050 carries these rows into
-- messages_fts_v2; past 25,000 rows it refuses to run until scripts/fts_v2_backfill.sql
-- has copied them.
-- Dropping the trigger locks message_contents ACCESS EXCLUSIVE until commit, but not
-- when it is already gone, hence the explicit lock: no write can commit between the copy
-- and the end of the migration. Rows an older binary stores there after this migration
-- are not copied; the recovery script above picks them up.
-- On a large database the copy can be made ahead, in content_hash-range batches of this
-- same INSERT after the CREATE TABLE above; this statement then adds only the rows
-- written since.
LOCK TABLE message_contents IN SHARE MODE;
INSERT INTO messages_fts (content_hash, text_body, text_body_tsv, sent_date, created_at)
SELECT content_hash, CASE WHEN text_body_tsv IS NULL THEN text_body END,
       text_body_tsv, sent_date, created_at
FROM message_contents
WHERE text_body_tsv IS NOT NULL OR text_body IS NOT NULL
ON CONFLICT (content_hash) DO NOTHING;

-- Create indexes for the FTS fields on the new table
CREATE INDEX IF NOT EXISTS idx_messages_fts_text_body_tsv ON messages_fts USING GIN (text_body_tsv);
CREATE INDEX IF NOT EXISTS idx_messages_fts_headers_tsv ON messages_fts USING GIN (headers_tsv);

-- Index for the FTS worker to efficiently poll the queue
CREATE INDEX IF NOT EXISTS idx_messages_fts_queue ON messages_fts (created_at) WHERE text_body_tsv IS NULL;

-- Index for PruneOldMessageVectors: range scan on sent_date for expired rows.
CREATE INDEX IF NOT EXISTS idx_messages_fts_sent_date ON messages_fts (sent_date) WHERE sent_date IS NOT NULL;

DROP FUNCTION IF EXISTS update_message_contents_tsvector();
