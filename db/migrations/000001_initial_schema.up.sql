-- PostgreSQL schema for managing email accounts, credentials, mailboxes, messages, and SIEVE scripts
-- Ensure the database has the necessary extensions installed, such as pg_trgm for full-text search.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE accounts (
	id BIGSERIAL PRIMARY KEY,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	deleted_at TIMESTAMPTZ NULL -- Soft deletion timestamp
);

-- Index for soft deletion queries
CREATE INDEX idx_accounts_deleted_at ON accounts(deleted_at);

-- A table to store account passwords and identities
CREATE TABLE credentials (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id),
	address TEXT NOT NULL,
	password TEXT NOT NULL,
	primary_identity BOOLEAN DEFAULT FALSE, -- Flag to indicate if this is the primary identity
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Index for case-insensitive, unique address lookups.
CREATE UNIQUE INDEX idx_credentials_lower_address ON credentials (LOWER(address));

-- Index to ensure that an account can have at most one primary identity.
CREATE UNIQUE INDEX idx_credentials_account_id_one_primary ON credentials (account_id) WHERE primary_identity IS TRUE;

-- Index for faster lookups by account_id (e.g., listing all credentials for an account)
CREATE INDEX idx_credentials_account_id ON credentials (account_id);

CREATE TABLE mailboxes (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id),
	highest_uid BIGINT DEFAULT 0 NOT NULL,                       -- The highest UID in the mailbox
	name TEXT NOT NULL,
	uid_validity BIGINT NOT NULL,                                -- Include uid_validity column for IMAP
	path TEXT NOT NULL DEFAULT '',                               -- Hex-encoded path of ancestor IDs
	subscribed BOOLEAN DEFAULT TRUE,                             -- Track mailbox subscription status
	is_shared BOOLEAN DEFAULT FALSE,                             -- Shared mailbox flag
	owner_domain TEXT,                                           -- Domain of mailbox owner for shared mailboxes
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	CONSTRAINT mailboxes_account_id_name_unique UNIQUE (account_id, name) -- Enforce unique mailbox names per account
);

-- Index for faster mailbox lookups by account_id and case insensitive name
CREATE INDEX idx_mailboxes_lower_name ON mailboxes (account_id, LOWER(name));

-- Index for faster mailbox lookups by account_id and subscription status
CREATE INDEX idx_mailboxes_account_subscribed ON mailboxes (account_id, subscribed);

-- Index for faster lookups by account_id (e.g., for account detail views)
CREATE INDEX idx_mailboxes_account_id ON mailboxes (account_id);

-- Index for path prefix searches (finding descendants)
-- Composite index with account_id first to reduce search scope
CREATE INDEX idx_mailboxes_path_prefix ON mailboxes (account_id, path text_pattern_ops);

-- Indexes for shared mailbox lookups
CREATE INDEX idx_mailboxes_is_shared ON mailboxes (is_shared) WHERE is_shared = TRUE;
CREATE INDEX idx_mailboxes_owner_domain ON mailboxes (owner_domain) WHERE owner_domain IS NOT NULL;

-- Composite index for shared mailbox + owner domain lookups
-- Used by get_accessible_mailboxes() when checking "anyone" access with domain restriction
CREATE INDEX idx_mailboxes_shared_domain ON mailboxes (is_shared, owner_domain) WHERE is_shared = TRUE AND owner_domain IS NOT NULL;

CREATE SEQUENCE messages_modseq;

CREATE TABLE messages (
	-- Unique identifier for the message row in the database
	id BIGSERIAL PRIMARY KEY,

    -- The account who owns the message
	account_id BIGINT REFERENCES accounts(id) ON DELETE RESTRICT,

	uid BIGINT NOT NULL,                -- The IMAP message UID within its mailbox
	-- S3 key components, to ensure we can always find the object even if user email changes
	s3_domain TEXT NOT NULL,
	s3_localpart TEXT NOT NULL,
	content_hash VARCHAR(64) NOT NULL,	-- Hash of the message content for deduplication
	uploaded BOOLEAN DEFAULT FALSE,	    -- Flag to indicate if the message was uploaded to S3
	recipients_json JSONB NOT NULL,	    -- JSONB field to store recipients
	message_id TEXT NOT NULL, 		    -- The Message-ID from the message headers
	in_reply_to TEXT,					-- The In-Reply-To header from the message
	subject TEXT,						-- Subject of the message
	sent_date TIMESTAMPTZ NOT NULL,		-- The date the message was sent
	internal_date TIMESTAMPTZ NOT NULL, -- The date the message was received
	flags INTEGER NOT NULL,				-- Bitwise flags for the message (e.g., \Seen, \Flagged)
	custom_flags JSONB DEFAULT '[]'::jsonb NOT NULL, -- Custom flags as a JSON array of strings (e.g., ["$Important", "$Label1"])
	size INTEGER NOT NULL,				-- Size of the message in bytes
	body_structure BYTEA NOT NULL,      -- Serialized BodyStructure of the message

	-- Denormalized fields for sorting performance
	subject_sort TEXT,
	from_name_sort TEXT,
	from_email_sort TEXT,
	to_email_sort TEXT,
	cc_email_sort TEXT,

	--
	-- Keep messages if mailbox is deleted by nullifying the mailbox_id
	--
	mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE SET NULL,

	--
	-- Information for restoring messages from S3
	--
	mailbox_path TEXT,			    -- Store the mailbox path for restoring messages

	flags_changed_at TIMESTAMPTZ,   -- Track the last time flags were changed
	expunged_at TIMESTAMPTZ,		-- Track the last time the message was expunged

	created_modseq BIGINT NOT NULL,
	updated_modseq BIGINT,
	expunged_modseq BIGINT,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	CONSTRAINT max_custom_flags_check CHECK (jsonb_array_length(custom_flags) <= 50), -- Limit to 50 custom flags
	CONSTRAINT messages_message_id_mailbox_id_key UNIQUE (message_id, mailbox_id)
);

-- Index for faster lookups by account_id, supporting various cleanup and query operations
CREATE INDEX idx_messages_account_id ON messages (account_id);

-- Index for faster lookups by account_id and mailbox_id
CREATE INDEX idx_messages_expunged_range ON messages (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE expunged_at IS NOT NULL;

CREATE INDEX idx_messages_content_hash ON messages (content_hash);

-- Index for faster lookups by content_hash and account_id (e.g., for upload worker)
CREATE INDEX idx_messages_content_hash_account_id ON messages (content_hash, account_id);

-- Index for DeleteMessageByHashAndMailbox (importer --force-reimport)
CREATE INDEX idx_messages_account_mailbox_hash ON messages (account_id, mailbox_id, content_hash);

-- Index for CleanupFailedUploads: efficiently find old messages that were never uploaded.
CREATE INDEX idx_messages_uploaded_created_at ON messages (created_at) WHERE uploaded = FALSE;

-- Index for ExpungeOldMessages: efficiently find non-expunged messages by created_at
CREATE INDEX idx_messages_expunged_null_created_at ON messages (created_at) WHERE expunged_at IS NULL;

-- Index for GetUserScopedObjectsForCleanup: efficiently find uploaded, expunged messages by expunged_at and grouping fields
CREATE INDEX idx_messages_cleanup_grouping ON messages (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE uploaded = TRUE AND expunged_at IS NOT NULL;

-- Index to optimize the GROUP BY in GetUserScopedObjectsForCleanup, allowing for fast index-only scans to find candidate groups.
CREATE INDEX idx_messages_s3_key_parts ON messages (account_id, s3_domain, s3_localpart, content_hash);

-- Index to speed up message lookups by message_id
CREATE INDEX idx_messages_message_id ON messages (LOWER(message_id));

-- Index to speed up message lookups by in_reply_to
CREATE INDEX idx_messages_in_reply_to ON messages (LOWER(in_reply_to));

-- Unique index to enforce UID uniqueness per mailbox and speed up lookups.
CREATE UNIQUE INDEX idx_messages_mailbox_id_uid ON messages (mailbox_id, uid);

-- Modseq index for fast lookups
CREATE INDEX idx_messages_created_modseq ON messages (created_modseq);
CREATE INDEX idx_messages_updated_modseq ON messages (updated_modseq);
CREATE INDEX idx_messages_mailbox_id_created_modseq ON messages (mailbox_id, created_modseq);
CREATE INDEX idx_messages_mailbox_id_updated_modseq ON messages (mailbox_id, updated_modseq);
CREATE INDEX idx_messages_expunged_modseq ON messages (expunged_modseq);

-- Index for PollMailbox: efficiently count non-expunged messages per mailbox
CREATE INDEX idx_messages_mailbox_id_expunged_at_is_null ON messages (mailbox_id) WHERE expunged_at IS NULL;

-- Index for PollMailbox: efficiently filter messages by mailbox_id and expunged_modseq
CREATE INDEX idx_messages_mailbox_id_expunged_modseq ON messages (mailbox_id, expunged_modseq);

-- Index for PruneOldMessageBodies and GetUnusedContentHashes: efficiently find active messages for a given content hash.
CREATE INDEX idx_messages_content_hash_active_sent_date ON messages (content_hash, sent_date) WHERE expunged_at IS NULL;

-- Index for faster searches on the subject field
CREATE INDEX idx_messages_subject_trgm ON messages USING gin (LOWER(subject) gin_trgm_ops);

-- Index for custom_flags to speed up searches for messages with specific custom flags
CREATE INDEX idx_messages_custom_flags ON messages USING GIN (custom_flags);

-- Index recipients_json for faster searches on recipients
-- This index uses the jsonb_path_ops for efficient querying
CREATE INDEX idx_messages_recipients_json ON messages USING GIN (recipients_json jsonb_path_ops);

-- For date range searches (SEARCH SINCE, SEARCH BEFORE)
CREATE INDEX idx_messages_mailbox_dates_uid ON messages (mailbox_id, internal_date, sent_date, uid) WHERE expunged_at IS NULL;

-- For size-based searches (SEARCH LARGER, SEARCH SMALLER)
CREATE INDEX idx_messages_mailbox_size_uid ON messages (mailbox_id, size, uid) WHERE expunged_at IS NULL;

-- Compound index for mailbox + multiple common search fields
CREATE INDEX idx_messages_mailbox_common_search ON messages (mailbox_id, (flags & 1), internal_date, size, uid) WHERE expunged_at IS NULL;

-- Indexes for denormalized sort columns
CREATE INDEX idx_messages_subject_sort ON messages (mailbox_id, subject_sort) WHERE expunged_at IS NULL;
CREATE INDEX idx_messages_from_email_sort ON messages (mailbox_id, from_email_sort) WHERE expunged_at IS NULL;
CREATE INDEX idx_messages_to_email_sort ON messages (mailbox_id, to_email_sort) WHERE expunged_at IS NULL;
CREATE INDEX idx_messages_cc_email_sort ON messages (mailbox_id, cc_email_sort) WHERE expunged_at IS NULL;
-- Index for display name sort (name fallback to email)
CREATE INDEX idx_messages_from_display_sort ON messages (mailbox_id, COALESCE(from_name_sort, from_email_sort)) WHERE expunged_at IS NULL;

-- Message sequence numbers caching table
-- Avoids expensive ROW_NUMBER() window functions on large mailboxes
CREATE TABLE message_sequences (
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid BIGINT NOT NULL,
    seqnum INT NOT NULL,
    PRIMARY KEY (mailbox_id, uid),
    UNIQUE (mailbox_id, seqnum)
);

-- Mailbox statistics caching table
-- Avoids expensive COUNT(*) and SUM() queries on large mailboxes
CREATE TABLE mailbox_stats (
    mailbox_id BIGINT PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_count INT NOT NULL DEFAULT 0,
    unseen_count INT NOT NULL DEFAULT 0,
    total_size BIGINT NOT NULL DEFAULT 0,
    highest_modseq BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Table to store message bodies, separated for performance
CREATE TABLE message_contents (
	content_hash VARCHAR(64) PRIMARY KEY, -- This is the same content_hash as in the messages table
	text_body TEXT, 			  		  -- Text body of the message, can be NULL for old messages to save space
	text_body_tsv tsvector,			   	  -- Full-text search index for text_body
	headers TEXT DEFAULT '' NOT NULL,     -- Raw message headers
	headers_tsv tsvector,			      -- Full-text search index for headers
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
	-- No direct FK to messages.id. The link is implicit:
	-- messages.content_hash = message_contents.content_hash
);

-- Index for PruneOldMessageBodies: efficiently find rows that have not been pruned yet.
CREATE INDEX idx_message_contents_text_body_not_null ON message_contents (content_hash) WHERE text_body IS NOT NULL;

-- Index for full-text search on the text_body field in message_contents
CREATE INDEX idx_message_contents_text_body_tsv ON message_contents USING GIN (text_body_tsv);
CREATE INDEX idx_message_contents_headers_tsv ON message_contents USING GIN (headers_tsv);

-- Pending uploads table for processing messages at own pace
CREATE TABLE pending_uploads (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
	instance_id TEXT NOT NULL, -- Unique identifier for the instance processing the upload, e.g., hostname
	content_hash VARCHAR(64) NOT NULL,
	attempts INTEGER DEFAULT 0,
	last_attempt TIMESTAMPTZ,
	size INTEGER NOT NULL,
	created_at TIMESTAMPTZ DEFAULT now(),
	updated_at TIMESTAMPTZ DEFAULT now(),
	UNIQUE (content_hash, account_id)
);

-- Index to support the primary query in ListPendingUploads
CREATE INDEX idx_pending_uploads_instance_id_created_at ON pending_uploads (instance_id, created_at);

-- Index for retry attempts (if you ever query by attempt count or want to exclude "too many attempts")
CREATE INDEX idx_pending_uploads_attempts ON pending_uploads (attempts);

--
-- SIEVE scripts
--
CREATE TABLE sieve_scripts (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
	active BOOLEAN NOT NULL DEFAULT TRUE,
	name TEXT NOT NULL,
	script TEXT NOT NULL,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	UNIQUE (account_id, name) 	-- Enforce unique script name per account
);

-- Index to speed up sieve script lookups by account_id
CREATE INDEX idx_sieve_scripts_account_id ON sieve_scripts (account_id);

-- Index to ensure that an account can have at most one active sieve script.
CREATE UNIQUE INDEX idx_sieve_scripts_account_id_one_active ON sieve_scripts (account_id) WHERE active IS TRUE;

-- Vacation responses tracking table
CREATE TABLE vacation_responses (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
	sender_address TEXT NOT NULL,
	response_date TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	UNIQUE (account_id, sender_address, response_date) -- Enforce unique responses per account and sender
);

-- Index for faster lookups by account_id and sender_address
CREATE INDEX idx_vacation_responses_account_sender ON vacation_responses (account_id, sender_address);

-- Index for cleanup of old responses
CREATE INDEX idx_vacation_responses_response_date ON vacation_responses (response_date);

-- Authentication rate limiting tracking table
CREATE TABLE auth_attempts (
	id BIGSERIAL PRIMARY KEY,
	ip_address INET NOT NULL,
	username TEXT,
	protocol TEXT NOT NULL,
	success BOOLEAN NOT NULL,
	attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_auth_attempts_cleanup ON auth_attempts (attempted_at); -- For cleaning up old rows

-- Partial indexes for failed attempts only (most common rate limiting case)
CREATE INDEX idx_auth_attempts_ip_failed ON auth_attempts (ip_address, attempted_at) WHERE success = false;
CREATE INDEX idx_auth_attempts_username_lower_failed ON auth_attempts (LOWER(username), attempted_at) WHERE success = false AND username IS NOT NULL;

-- Table-based locks for coordinating background workers
CREATE TABLE locks (
	lock_name TEXT PRIMARY KEY,
	acquired_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
);

-- active_connections table removed - connection tracking now uses gossip protocol instead of database
-- Gossip-based tracking eliminates database writes for every connection, improving scalability
-- See servers.connection_tracking configuration for gossip-based limits

-- Health status tracking for system components
CREATE TABLE health_status (
    component_name VARCHAR(255) NOT NULL,
    server_hostname VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'unreachable')),
    last_check TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_error TEXT,
    check_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0,
    metadata JSONB,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    PRIMARY KEY (component_name, server_hostname)
);

-- Index for faster health status lookups by server
CREATE INDEX idx_health_status_server ON health_status (server_hostname);

-- Index for faster health status lookups by status
CREATE INDEX idx_health_status_status ON health_status (status);

-- Index for faster health status cleanup by updated_at
CREATE INDEX idx_health_status_updated_at ON health_status (updated_at);

-- Cache metrics tracking for hit/miss ratios per instance
CREATE TABLE cache_metrics (
    instance_id VARCHAR(255) NOT NULL,
    server_hostname VARCHAR(255) NOT NULL,
    hits BIGINT DEFAULT 0,
    misses BIGINT DEFAULT 0,
    hit_rate DECIMAL(5,2) DEFAULT 0.00,
    total_operations BIGINT DEFAULT 0,
    uptime_seconds INTEGER DEFAULT 0,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    PRIMARY KEY (instance_id, server_hostname, recorded_at)
);

-- Index for faster cache metrics cleanup by recorded_at
CREATE INDEX idx_cache_metrics_recorded_at ON cache_metrics (recorded_at);

-- Index for latest metrics per instance
CREATE INDEX idx_cache_metrics_instance_latest ON cache_metrics (instance_id, recorded_at DESC);

-- Index for GetLatestCacheMetrics: efficiently find the latest record per instance and server
CREATE INDEX idx_cache_metrics_latest_per_instance_server ON cache_metrics (instance_id, server_hostname, recorded_at DESC);

-- METADATA extension support (RFC 5464)
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

-- ACL table for mailbox permissions (RFC 4314)
-- Stores access control entries for shared mailboxes
CREATE TABLE mailbox_acls (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,  -- NULL for "anyone"
    identifier TEXT NOT NULL,  -- Email address or "anyone"
    rights VARCHAR(20) NOT NULL, -- IMAP ACL rights: lrswipkxtea
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT mailbox_acls_unique_identifier UNIQUE (mailbox_id, identifier),
    CONSTRAINT mailbox_acls_valid_rights CHECK (rights ~ '^[lrswipkxtea]+$'),
    CONSTRAINT mailbox_acls_identifier_not_null CHECK (identifier IS NOT NULL AND identifier != ''),
    CONSTRAINT mailbox_acls_anyone_null_account CHECK ((identifier = 'anyone' AND account_id IS NULL) OR (identifier != 'anyone' AND account_id IS NOT NULL))
);

-- Composite index for the most common ACL lookup pattern (mailbox + account)
-- Used by has_mailbox_right() for direct user permission checks
CREATE INDEX idx_mailbox_acls_mailbox_account ON mailbox_acls (mailbox_id, account_id);

-- Composite index for "anyone" ACL lookups
-- Used by has_mailbox_right() for domain-wide permission checks
CREATE INDEX idx_mailbox_acls_mailbox_identifier ON mailbox_acls (mailbox_id, identifier);

-- Index for finding all ACLs for a specific account (reverse lookup)
-- Used by get_accessible_mailboxes() and ACL management operations
CREATE INDEX idx_mailbox_acls_account_id ON mailbox_acls (account_id) WHERE account_id IS NOT NULL;

-- Partial index for "anyone" ACLs only
-- Used by get_accessible_mailboxes() for finding domain-wide shared mailboxes
CREATE INDEX idx_mailbox_acls_anyone ON mailbox_acls (identifier, mailbox_id) WHERE identifier = 'anyone';

-- Triggers for message_sequences maintenance
CREATE OR REPLACE FUNCTION maintain_message_sequences()
RETURNS TRIGGER AS
$$
DECLARE
    v_mailbox_id BIGINT;
    affected_mailboxes_query TEXT;
BEGIN
    -- This trigger function rebuilds the sequence numbers for affected mailboxes.
    -- We get the mailbox_id from the transition tables, depending on trigger event.

    -- Build query based on available transition tables
    IF TG_OP = 'INSERT' THEN
        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL';
    ELSIF TG_OP = 'DELETE' THEN
        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
    ELSE -- UPDATE
        affected_mailboxes_query := '
            SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL
            UNION
            SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
    END IF;

    -- Process all affected mailboxes
    FOR v_mailbox_id IN EXECUTE affected_mailboxes_query LOOP
        -- Lock the mailbox to prevent concurrent modifications from other transactions.
        PERFORM pg_advisory_xact_lock(v_mailbox_id);

        -- Atomically rebuild the sequence numbers for the entire mailbox.
        -- This is more robust and often faster for bulk operations than per-row adjustments.
        DELETE FROM message_sequences WHERE mailbox_id = v_mailbox_id;
        INSERT INTO message_sequences (mailbox_id, uid, seqnum)
        SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (ORDER BY m.uid)
        FROM messages m
        WHERE m.mailbox_id = v_mailbox_id AND m.expunged_at IS NULL;
    END LOOP;

    RETURN NULL; -- Result is ignored for AFTER STATEMENT triggers.
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_maintain_message_sequences_insert
AFTER INSERT ON messages
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();

CREATE TRIGGER trigger_maintain_message_sequences_update
AFTER UPDATE ON messages
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();

CREATE TRIGGER trigger_maintain_message_sequences_delete
AFTER DELETE ON messages
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();

-- Triggers for mailbox_stats maintenance
CREATE OR REPLACE FUNCTION maintain_mailbox_stats()
RETURNS TRIGGER AS $$
DECLARE
    v_mailbox_id BIGINT;
    count_delta INT := 0;
    unseen_delta INT := 0;
    size_delta BIGINT := 0;
    modseq_val BIGINT := 0;
BEGIN
    -- Determine which mailbox_id to use
    IF TG_OP = 'INSERT' THEN
        v_mailbox_id := NEW.mailbox_id;
    ELSE -- DELETE or UPDATE
        v_mailbox_id := OLD.mailbox_id;
    END IF;

    -- If mailbox_id is NULL, do nothing (e.g., message moved out of a deleted mailbox)
    IF v_mailbox_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Calculate deltas based on operation
    IF TG_OP = 'INSERT' AND NEW.expunged_at IS NULL THEN
        count_delta := 1;
        size_delta := NEW.size;
        unseen_delta := 1 - (NEW.flags & 1); -- 1 if unseen, 0 if seen
        modseq_val := NEW.created_modseq;

    ELSIF TG_OP = 'DELETE' AND OLD.expunged_at IS NULL THEN
        count_delta := -1;
        size_delta := -OLD.size;
        unseen_delta := -(1 - (OLD.flags & 1));
        -- modseq is a high-water mark, not decreased on delete

    ELSIF TG_OP = 'UPDATE' THEN
        -- Case 1: Message is expunged (soft delete)
        IF OLD.expunged_at IS NULL AND NEW.expunged_at IS NOT NULL THEN
            count_delta := -1;
            size_delta := -OLD.size;
            unseen_delta := -(1 - (OLD.flags & 1));
            modseq_val := COALESCE(NEW.expunged_modseq, 0);
        -- Case 2: Message is restored (un-expunged)
        ELSIF OLD.expunged_at IS NOT NULL AND NEW.expunged_at IS NULL THEN
            count_delta := 1;
            size_delta := NEW.size;
            unseen_delta := 1 - (NEW.flags & 1);
            -- modseq is not changed on restore, it's a new state
        -- Case 3: Flags changed on an active message
        ELSIF OLD.expunged_at IS NULL AND NEW.expunged_at IS NULL AND OLD.flags != NEW.flags THEN
            unseen_delta := (1 - (NEW.flags & 1)) - (1 - (OLD.flags & 1));
            modseq_val := COALESCE(NEW.updated_modseq, 0);
        END IF;
    END IF;

    -- Apply the deltas if any change occurred
    IF count_delta != 0 OR size_delta != 0 OR unseen_delta != 0 OR modseq_val != 0 THEN
        INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
        VALUES (v_mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now())
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + count_delta,
            unseen_count = mailbox_stats.unseen_count + unseen_delta,
            total_size = mailbox_stats.total_size + size_delta,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, modseq_val),
            updated_at = now();
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_messages_stats_insert AFTER INSERT ON messages FOR EACH ROW EXECUTE FUNCTION maintain_mailbox_stats();
CREATE TRIGGER trigger_messages_stats_delete AFTER DELETE ON messages FOR EACH ROW EXECUTE FUNCTION maintain_mailbox_stats();
CREATE TRIGGER trigger_messages_stats_update AFTER UPDATE ON messages FOR EACH ROW WHEN (OLD.flags IS DISTINCT FROM NEW.flags OR OLD.expunged_at IS DISTINCT FROM NEW.expunged_at) EXECUTE FUNCTION maintain_mailbox_stats();

-- Function to check if an account has a specific right on a mailbox
-- Returns TRUE if:
--   1. User owns the mailbox (both shared and non-shared), OR
--   2. User has an ACL entry with the requested right, OR
--   3. User is in same domain and there's an "anyone" ACL entry with the requested right
CREATE OR REPLACE FUNCTION has_mailbox_right(
    p_mailbox_id BIGINT,
    p_account_id BIGINT,
    p_right CHAR(1)
) RETURNS BOOLEAN AS $$
DECLARE
    v_rights TEXT;
    v_is_owner BOOLEAN;
    v_owner_domain TEXT;
    v_user_domain TEXT;
BEGIN
    -- Check if user is the owner (both shared and non-shared mailboxes)
    SELECT
        (account_id = p_account_id),
        owner_domain
    INTO v_is_owner, v_owner_domain
    FROM mailboxes
    WHERE id = p_mailbox_id;

    -- Owners have all rights (both shared and non-shared mailboxes)
    IF v_is_owner THEN
        RETURN TRUE;
    END IF;

    -- Check direct ACL entry for this user
    SELECT rights INTO v_rights
    FROM mailbox_acls
    WHERE mailbox_id = p_mailbox_id AND account_id = p_account_id;

    IF v_rights IS NOT NULL AND position(p_right IN v_rights) > 0 THEN
        RETURN TRUE;
    END IF;

    -- Check "anyone" ACL entry (only for shared mailboxes in same domain)
    IF v_owner_domain IS NOT NULL THEN
        -- Get user's domain
        SELECT SPLIT_PART(address, '@', 2) INTO v_user_domain
        FROM credentials
        WHERE account_id = p_account_id AND primary_identity = TRUE;

        -- If user is in same domain as mailbox owner, check "anyone" rights
        IF v_user_domain = v_owner_domain THEN
            SELECT rights INTO v_rights
            FROM mailbox_acls
            WHERE mailbox_id = p_mailbox_id AND identifier = 'anyone';

            IF v_rights IS NOT NULL AND position(p_right IN v_rights) > 0 THEN
                RETURN TRUE;
            END IF;
        END IF;
    END IF;

    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;

-- Helper function to get all mailboxes accessible to a user
-- Returns both owned mailboxes and shared mailboxes with ACL access
CREATE OR REPLACE FUNCTION get_accessible_mailboxes(
    p_account_id BIGINT
) RETURNS TABLE (
    mailbox_id BIGINT,
    mailbox_name TEXT,
    is_shared BOOLEAN,
    access_rights TEXT
) AS $$
DECLARE
    v_user_domain TEXT;
BEGIN
    -- Get user's domain
    SELECT SPLIT_PART(address, '@', 2) INTO v_user_domain
    FROM credentials
    WHERE account_id = p_account_id AND primary_identity = TRUE;

    RETURN QUERY
    -- Personal mailboxes (owned by user)
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        'lrswipkxtea'::TEXT as access_rights  -- Full rights for owned mailboxes
    FROM mailboxes m
    WHERE m.account_id = p_account_id
      AND NOT COALESCE(m.is_shared, FALSE)

    UNION ALL

    -- Shared mailboxes with direct ACL access
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.account_id = p_account_id
      AND COALESCE(m.is_shared, FALSE) = TRUE

    UNION ALL

    -- Shared mailboxes with "anyone" access (same domain only)
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.identifier = 'anyone'
      AND COALESCE(m.is_shared, FALSE) = TRUE
      AND m.owner_domain = v_user_domain;  -- Same domain restriction
END;
$$ LANGUAGE plpgsql STABLE;

-- Populate the message_sequences table for all existing non-expunged messages
-- This is a one-time operation to bootstrap the cache.
INSERT INTO message_sequences (mailbox_id, uid, seqnum)
SELECT
    m.mailbox_id,
    m.uid,
    ROW_NUMBER() OVER (PARTITION BY m.mailbox_id ORDER BY m.uid) AS seqnum
FROM
    messages m
WHERE
    m.expunged_at IS NULL AND m.mailbox_id IS NOT NULL;

-- Populate the mailbox_stats table for all existing mailboxes
-- This is a one-time operation to bootstrap the cache.
INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
SELECT
    m.mailbox_id,
    COUNT(m.id),
    COUNT(m.id) FILTER (WHERE (m.flags & 1) = 0),
    COALESCE(SUM(m.size), 0),
    COALESCE((SELECT MAX(modseq) FROM (SELECT created_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id UNION ALL SELECT updated_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id AND updated_modseq IS NOT NULL UNION ALL SELECT expunged_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id AND expunged_modseq IS NOT NULL) as modseqs), 0),
    now()
FROM messages m
WHERE m.mailbox_id IS NOT NULL AND m.expunged_at IS NULL
GROUP BY m.mailbox_id;
