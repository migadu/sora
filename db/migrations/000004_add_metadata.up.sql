-- Add METADATA extension support (RFC 5464)
-- Stores server and mailbox annotations

CREATE TABLE metadata (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
    entry_name TEXT NOT NULL,
    entry_value BYTEA,  -- NULL means entry exists but has no value
    content_type TEXT DEFAULT 'text/plain',
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,

    -- Server metadata has mailbox_id = NULL
    -- Mailbox metadata has mailbox_id set
    -- Each entry_name is unique per account/mailbox combination
    CONSTRAINT metadata_unique_entry UNIQUE(account_id, mailbox_id, entry_name)
);

-- Index for fast lookups by account and mailbox
CREATE INDEX idx_metadata_account_mailbox ON metadata(account_id, mailbox_id);

-- Index for server metadata lookups (mailbox_id IS NULL)
CREATE INDEX idx_metadata_server ON metadata(account_id) WHERE mailbox_id IS NULL;

-- Index for mailbox metadata lookups
CREATE INDEX idx_metadata_mailbox ON metadata(mailbox_id) WHERE mailbox_id IS NOT NULL;

-- Index for entry name prefix searches (for DEPTH > 0 queries)
CREATE INDEX idx_metadata_entry_prefix ON metadata(account_id, mailbox_id, entry_name text_pattern_ops);
