
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

-- Create indexes for the FTS fields on the new table
CREATE INDEX IF NOT EXISTS idx_messages_fts_text_body_tsv ON messages_fts USING GIN (text_body_tsv);
CREATE INDEX IF NOT EXISTS idx_messages_fts_headers_tsv ON messages_fts USING GIN (headers_tsv);

-- Index for the FTS worker to efficiently poll the queue
CREATE INDEX IF NOT EXISTS idx_messages_fts_queue ON messages_fts (created_at) WHERE text_body_tsv IS NULL;

-- Index for PruneOldMessageVectors: range scan on sent_date for expired rows.
CREATE INDEX IF NOT EXISTS idx_messages_fts_sent_date ON messages_fts (sent_date) WHERE sent_date IS NOT NULL;

DROP FUNCTION IF EXISTS update_message_contents_tsvector();
