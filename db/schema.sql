CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	username TEXT UNIQUE NOT NULL, -- Already indexed because of the UNIQUE constraint
	password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mailboxes (
	id SERIAL PRIMARY KEY,
	user_id INTEGER REFERENCES users(id),
	highest_uid INTEGER DEFAULT 0 NOT NULL,                         -- The highest UID in the mailbox
	name TEXT NOT NULL,
	uid_validity BIGINT NOT NULL,                                  -- Include uid_validity column for IMAP
	parent_id INTEGER REFERENCES mailboxes(id) ON DELETE CASCADE,  -- Self-referencing for parent mailbox
	subscribed BOOLEAN DEFAULT TRUE,  														 -- New field to track mailbox subscription status
	UNIQUE (user_id, name, parent_id)  														 -- Enforce unique mailbox names per user and parent mailbox
);

-- Index for faster mailbox lookups by user_id and case insensitive name
CREATE INDEX IF NOT EXISTS idx_mailboxes_lower_name_parent_id ON mailboxes (user_id, LOWER(name), parent_id);

-- Partial unique index for top-level mailboxes
CREATE UNIQUE INDEX IF NOT EXISTS unique_top_level_mailbox_name ON mailboxes (user_id, name)
	WHERE parent_id IS NULL;

-- Index for faster mailbox lookups by user_id and subscription status
CREATE INDEX IF NOT EXISTS idx_mailboxes_user_subscribed ON mailboxes (user_id, subscribed);

-- Index for faster mailbox lookups by user_id
CREATE INDEX IF NOT EXISTS idx_mailboxes_user_id ON mailboxes (user_id);

-- Index to speed up parent-child hierarchy lookups
CREATE INDEX IF NOT EXISTS idx_mailboxes_parent_id ON mailboxes (parent_id);

CREATE SEQUENCE IF NOT EXISTS messages_modseq;

CREATE TABLE IF NOT EXISTS messages (
	id SERIAL PRIMARY KEY, 					-- Unique message ID, also the UID of messages in a mailbox

	uid INTEGER NOT NULL,            -- The message UID in its mailbox
	storage_uuid TEXT NOT NULL,			-- Unique object key for the message
	recipients_json JSONB NOT NULL,	-- JSONB field to store recipients
	message_id TEXT NOT NULL, 			-- The Message-ID from the message headers
	in_reply_to TEXT,								-- The In-Reply-To header from the message
	subject TEXT,										-- Subject of the message
	sent_date TIMESTAMP NOT NULL,		-- The date the message was sent
	internal_date TIMESTAMP NOT NULL, -- The date the message was received
	flags INTEGER NOT NULL,					-- Bitwise flags for the message (e.g., \Seen, \Flagged)
	size INTEGER NOT NULL,					-- Size of the message in bytes
	body_structure BYTEA NOT NULL,  -- Serialized BodyStructure of the message
	text_body TEXT NOT NULL, 			  -- Text body of the message
	text_body_tsv tsvector,					-- Full-text search index for text_body

	--
	-- Keep messages if mailbox is deleted by nullifying the mailbox_id
	--
	mailbox_id INTEGER REFERENCES mailboxes(id) ON DELETE SET NULL,

	--
	-- Information for restoring messages from S3
	--
	mailbox_name TEXT,			   -- Store the mailbox path for restoring messages

	deleted_at TIMESTAMP,			  -- Soft delete column
	flags_changed_at TIMESTAMP, -- Track the last time flags were changed
	expunged_at TIMESTAMP,			-- Track the last time the message was expunged

	created_modseq BIGINT NOT NULL,
	updated_modseq BIGINT,
	expunged_modseq BIGINT
);

-- Index to speed up message lookups by mailbox_id (for listing, searching)
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id ON messages (mailbox_id);

CREATE INDEX IF NOT EXISTS idx_messages_storage_uuid ON messages (storage_uuid);

-- Index to speed up message lookups by message_id
CREATE INDEX IF NOT EXISTS idx_messages_message_id ON messages (LOWER(message_id));

-- Index to speed up message lookups by in_reply_to
CREATE INDEX IF NOT EXISTS idx_messages_in_reply_to ON messages (LOWER(in_reply_to));

-- Index to speed up message lookups by mailbox_id and uid
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_mailbox_id_uid ON messages (mailbox_id, uid);

-- Index to quickly search messages by internal_date (for date-based queries)
CREATE INDEX IF NOT EXISTS idx_messages_internal_date ON messages (internal_date);
CREATE INDEX IF NOT EXISTS idx_messages_sent_date ON messages (sent_date);
CREATE INDEX IF NOT EXISTS idx_messages_flags_changed_at ON messages (flags_changed_at);
CREATE INDEX IF NOT EXISTS idx_messages_expunged_at ON messages (expunged_at);
CREATE INDEX IF NOT EXISTS idx_messages_deleted_at ON messages (deleted_at);

-- Index for flags to speed up searches for seen messages
CREATE INDEX IF NOT EXISTS idx_messages_flag_seen ON messages ((flags & 1)) WHERE (flags & 1) != 0;

-- Modseq index for fast lookups
CREATE INDEX IF NOT EXISTS idx_messages_created_modseq ON messages (created_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_updated_modseq ON messages (updated_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_expunged_modseq ON messages (expunged_modseq);

-- Index for faster searches on the subject field
-- This index uses the pg_trgm extension for trigram similarity searches
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm ON messages USING gin (LOWER(subject) gin_trgm_ops);

-- Index for full-text search on the text_body field
CREATE INDEX IF NOT EXISTS idx_messages_text_body_tsv ON messages USING GIN (text_body_tsv);

-- Index recipients_json for faster searches on recipients
-- This index uses the jsonb_path_ops for efficient querying
CREATE INDEX IF NOT EXISTS idx_messages_recipients_json ON messages USING GIN (recipients_json jsonb_path_ops);
