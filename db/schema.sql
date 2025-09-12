-- PostgreSQL schema for managing email accounts, credentials, mailboxes, messages, and SIEVE scripts
-- Ensure the database has the necessary extensions installed, such as pg_trgm for full-text search.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS accounts (
	id BIGSERIAL PRIMARY KEY,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	deleted_at TIMESTAMPTZ NULL -- Soft deletion timestamp
);

-- Index for soft deletion queries
CREATE INDEX IF NOT EXISTS idx_accounts_deleted_at ON accounts(deleted_at);

-- Table for tracking server affinity for proxy connections
CREATE TABLE IF NOT EXISTS server_affinity (
    account_id BIGINT NOT NULL,
    is_prelookup_account BOOLEAN NOT NULL DEFAULT FALSE,
    last_server_addr VARCHAR(255) NOT NULL,
    last_server_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, is_prelookup_account)
);

-- Index for faster lookups by last_server_addr (e.g., for maintenance)
CREATE INDEX IF NOT EXISTS idx_server_affinity_last_server_addr ON server_affinity(last_server_addr);

-- A table to store account passwords and identities
CREATE TABLE IF NOT EXISTS credentials (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id),
	address TEXT NOT NULL,
	password TEXT NOT NULL,
	primary_identity BOOLEAN DEFAULT FALSE, -- Flag to indicate if this is the primary identity
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

-- Index for case-insensitive, unique address lookups.
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_lower_address ON credentials (LOWER(address));

-- Index to ensure that an account can have at most one primary identity.
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_account_id_one_primary ON credentials (account_id) WHERE primary_identity IS TRUE;

-- Index for faster lookups by account_id (e.g., listing all credentials for an account)
CREATE INDEX IF NOT EXISTS idx_credentials_account_id ON credentials (account_id);

CREATE TABLE IF NOT EXISTS mailboxes (
	id BIGSERIAL PRIMARY KEY,	
	account_id BIGINT REFERENCES accounts(id),
	highest_uid BIGINT DEFAULT 0 NOT NULL,                       -- The highest UID in the mailbox
	name TEXT NOT NULL,
	uid_validity BIGINT NOT NULL,                                -- Include uid_validity column for IMAP
	path TEXT NOT NULL DEFAULT '',                               -- Hex-encoded path of ancestor IDs
	subscribed BOOLEAN DEFAULT TRUE,                             -- Track mailbox subscription status	
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	CONSTRAINT mailboxes_account_id_name_unique UNIQUE (account_id, name) -- Enforce unique mailbox names per account
);

-- Index for faster mailbox lookups by account_id and case insensitive name
CREATE INDEX IF NOT EXISTS idx_mailboxes_lower_name ON mailboxes (account_id, LOWER(name));

-- Index for faster mailbox lookups by account_id and subscription status
CREATE INDEX IF NOT EXISTS idx_mailboxes_account_subscribed ON mailboxes (account_id, subscribed);

-- Index for faster lookups by account_id (e.g., for account detail views)
CREATE INDEX IF NOT EXISTS idx_mailboxes_account_id ON mailboxes (account_id);

-- Index for path prefix searches (finding descendants)
-- Composite index with account_id first to reduce search scope
CREATE INDEX IF NOT EXISTS idx_mailboxes_path_prefix ON mailboxes (account_id, path text_pattern_ops);

CREATE SEQUENCE IF NOT EXISTS messages_modseq;

CREATE TABLE IF NOT EXISTS messages (
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
	CONSTRAINT max_custom_flags_check CHECK (jsonb_array_length(custom_flags) <= 50) -- Limit to 50 custom flags
);

-- Index for faster lookups by account_id, supporting various cleanup and query operations
CREATE INDEX IF NOT EXISTS idx_messages_account_id ON messages (account_id);

-- Index for faster lookups by account_id and mailbox_id
CREATE INDEX IF NOT EXISTS idx_messages_expunged_range ON messages (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE expunged_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_content_hash ON messages (content_hash);

-- Index for faster lookups by content_hash and account_id (e.g., for upload worker)
CREATE INDEX IF NOT EXISTS idx_messages_content_hash_account_id ON messages (content_hash, account_id);

-- Index for DeleteMessageByHashAndMailbox (importer --force-reimport)
CREATE INDEX IF NOT EXISTS idx_messages_account_mailbox_hash ON messages (account_id, mailbox_id, content_hash);

-- Index for CleanupFailedUploads: efficiently find old messages that were never uploaded.
CREATE INDEX IF NOT EXISTS idx_messages_uploaded_created_at ON messages (created_at) WHERE uploaded = FALSE;

-- Index for ExpungeOldMessages: efficiently find non-expunged messages by created_at
CREATE INDEX IF NOT EXISTS idx_messages_expunged_null_created_at ON messages (created_at) WHERE expunged_at IS NULL;

-- Index for GetUserScopedObjectsForCleanup: efficiently find uploaded, expunged messages by expunged_at and grouping fields
CREATE INDEX IF NOT EXISTS idx_messages_cleanup_grouping ON messages (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE uploaded = TRUE AND expunged_at IS NOT NULL;

-- Index to optimize the GROUP BY in GetUserScopedObjectsForCleanup, allowing for fast index-only scans to find candidate groups.
CREATE INDEX IF NOT EXISTS idx_messages_s3_key_parts ON messages (account_id, s3_domain, s3_localpart, content_hash);

-- Index to speed up message lookups by message_id
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages (LOWER(message_id));

-- Index to speed up message lookups by in_reply_to
CREATE INDEX IF NOT EXISTS idx_messages_in_reply_to ON messages (LOWER(in_reply_to));

-- Unique index to enforce UID uniqueness per mailbox and speed up lookups.
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_id_uid ON messages (mailbox_id, uid);

-- Modseq index for fast lookups
CREATE INDEX IF NOT EXISTS idx_messages_created_modseq ON messages (created_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_updated_modseq ON messages (updated_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_created_modseq ON messages (mailbox_id, created_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_updated_modseq ON messages (mailbox_id, updated_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_expunged_modseq ON messages (expunged_modseq);

-- Index for PollMailbox: efficiently count non-expunged messages per mailbox
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_expunged_at_is_null ON messages (mailbox_id) WHERE expunged_at IS NULL;

-- Index for PollMailbox: efficiently filter messages by mailbox_id and expunged_modseq
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_expunged_modseq ON messages (mailbox_id, expunged_modseq);

-- Index for PruneOldMessageBodies and GetUnusedContentHashes: efficiently find active messages for a given content hash.
CREATE INDEX IF NOT EXISTS idx_messages_content_hash_active_sent_date ON messages (content_hash, sent_date) WHERE expunged_at IS NULL;

-- Index for faster searches on the subject field
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm ON messages USING gin (LOWER(subject) gin_trgm_ops);

-- Index for custom_flags to speed up searches for messages with specific custom flags
CREATE INDEX IF NOT EXISTS idx_messages_custom_flags ON messages USING GIN (custom_flags);

-- Index recipients_json for faster searches on recipients
-- This index uses the jsonb_path_ops for efficient querying
CREATE INDEX IF NOT EXISTS idx_messages_recipients_json ON messages USING GIN (recipients_json jsonb_path_ops);

-- For fast flag-only searches (common IMAP operations like SEARCH UNSEEN)
-- This index on the expression `(flags & 1)` allows for fast filtering on the \Seen flag (for both SEEN and UNSEEN searches).
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_seen_flag_uid ON messages (mailbox_id, (flags & 1), uid) WHERE expunged_at IS NULL;

-- For date range searches (SEARCH SINCE, SEARCH BEFORE)
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_dates_uid ON messages (mailbox_id, internal_date, sent_date, uid) WHERE expunged_at IS NULL;

-- For size-based searches (SEARCH LARGER, SEARCH SMALLER)  
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_size_uid ON messages (mailbox_id, size, uid) WHERE expunged_at IS NULL;

-- Compound index for mailbox + multiple common search fields
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_common_search ON messages (mailbox_id, (flags & 1), internal_date, size, uid) WHERE expunged_at IS NULL;

-- Table to store message bodies, separated for performance
CREATE TABLE IF NOT EXISTS message_contents (
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
CREATE INDEX IF NOT EXISTS idx_message_contents_text_body_not_null ON message_contents (content_hash) WHERE text_body IS NOT NULL;

-- Index for full-text search on the text_body field in message_contents
CREATE INDEX IF NOT EXISTS idx_message_contents_text_body_tsv ON message_contents USING GIN (text_body_tsv);
CREATE INDEX IF NOT EXISTS idx_message_contents_headers_tsv ON message_contents USING GIN (headers_tsv);

-- Pending uploads table for processing messages at own pace
CREATE TABLE IF NOT EXISTS pending_uploads (
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
CREATE INDEX IF NOT EXISTS idx_pending_uploads_instance_id_created_at ON pending_uploads (instance_id, created_at);

-- Index for retry attempts (if you ever query by attempt count or want to exclude "too many attempts")
CREATE INDEX IF NOT EXISTS idx_pending_uploads_attempts ON pending_uploads (attempts);

--
-- SIEVE scripts
--
CREATE TABLE IF NOT EXISTS sieve_scripts (
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
CREATE INDEX IF NOT EXISTS idx_sieve_scripts_account_id ON sieve_scripts (account_id);

-- Index to ensure that an account can have at most one active sieve script.
CREATE UNIQUE INDEX IF NOT EXISTS idx_sieve_scripts_account_id_one_active ON sieve_scripts (account_id) WHERE active IS TRUE;

-- Vacation responses tracking table
CREATE TABLE IF NOT EXISTS vacation_responses (
	id BIGSERIAL PRIMARY KEY,
	account_id BIGINT REFERENCES accounts(id) ON DELETE CASCADE,
	sender_address TEXT NOT NULL,
	response_date TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
	UNIQUE (account_id, sender_address, response_date) -- Enforce unique responses per account and sender
);

-- Index for faster lookups by account_id and sender_address
CREATE INDEX IF NOT EXISTS idx_vacation_responses_account_sender ON vacation_responses (account_id, sender_address);

-- Index for cleanup of old responses
CREATE INDEX IF NOT EXISTS idx_vacation_responses_response_date ON vacation_responses (response_date);

-- Authentication rate limiting tracking table
CREATE TABLE IF NOT EXISTS auth_attempts (
	id BIGSERIAL PRIMARY KEY,
	ip_address INET NOT NULL,
	username TEXT,
	protocol TEXT NOT NULL,
	success BOOLEAN NOT NULL,
	attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_cleanup ON auth_attempts (attempted_at); -- For cleaning up old rows

-- Partial indexes for failed attempts only (most common rate limiting case)
CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip_failed ON auth_attempts (ip_address, attempted_at) WHERE success = false;
CREATE INDEX IF NOT EXISTS idx_auth_attempts_username_lower_failed ON auth_attempts (LOWER(username), attempted_at) WHERE success = false AND username IS NOT NULL;

-- Table-based locks for coordinating background workers
CREATE TABLE IF NOT EXISTS locks (
	lock_name TEXT PRIMARY KEY,
	acquired_at TIMESTAMPTZ NOT NULL,
	expires_at TIMESTAMPTZ NOT NULL
);

-- Table for tracking active proxy connections
CREATE TABLE IF NOT EXISTS active_connections (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL,
    is_prelookup_account BOOLEAN NOT NULL DEFAULT FALSE,
	instance_id VARCHAR(255) NOT NULL,
    protocol VARCHAR(20) NOT NULL,
    client_addr VARCHAR(255) NOT NULL,
    server_addr VARCHAR(255) NOT NULL,
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT now(),
    should_terminate BOOLEAN DEFAULT false,
    UNIQUE(account_id, is_prelookup_account, protocol, client_addr)
);

-- It's a good idea to add an index for faster cleanup on startup.
CREATE INDEX IF NOT EXISTS idx_active_connections_instance_id ON active_connections(instance_id);

-- Index for faster lookups by account_id
CREATE INDEX IF NOT EXISTS idx_active_connections_account_id ON active_connections (account_id, is_prelookup_account);

-- Index for faster lookups by server_addr
CREATE INDEX IF NOT EXISTS idx_active_connections_server_addr ON active_connections (server_addr);

-- Index for GetTerminatedConnectionsByInstance: efficiently find connections to terminate.
CREATE INDEX IF NOT EXISTS idx_active_connections_term_instance ON active_connections (instance_id) WHERE should_terminate = true;

-- Index for cleanup of stale connections
CREATE INDEX IF NOT EXISTS idx_active_connections_last_activity ON active_connections (last_activity);

-- Index for protocol-based queries
CREATE INDEX IF NOT EXISTS idx_active_connections_protocol ON active_connections (protocol);

-- Health status tracking for system components
CREATE TABLE IF NOT EXISTS health_status (
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
CREATE INDEX IF NOT EXISTS idx_health_status_server ON health_status (server_hostname);

-- Index for faster health status lookups by status
CREATE INDEX IF NOT EXISTS idx_health_status_status ON health_status (status);

-- Index for faster health status cleanup by updated_at
CREATE INDEX IF NOT EXISTS idx_health_status_updated_at ON health_status (updated_at);

-- Cache metrics tracking for hit/miss ratios per instance
CREATE TABLE IF NOT EXISTS cache_metrics (
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
CREATE INDEX IF NOT EXISTS idx_cache_metrics_recorded_at ON cache_metrics (recorded_at);

-- Index for latest metrics per instance
CREATE INDEX IF NOT EXISTS idx_cache_metrics_instance_latest ON cache_metrics (instance_id, recorded_at DESC);

-- Index for GetLatestCacheMetrics: efficiently find the latest record per instance and server
CREATE INDEX IF NOT EXISTS idx_cache_metrics_latest_per_instance_server ON cache_metrics (instance_id, server_hostname, recorded_at DESC);
