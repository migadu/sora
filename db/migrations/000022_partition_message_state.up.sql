-- Migration 022: Vertical Partitioning of Message State
-- Extracts highly mutable fields (flags, custom_flags, updated_modseq) into a side table
-- to enable HOT (Heap Only Tuples) updates on the massive messages table.

BEGIN;

CREATE TABLE IF NOT EXISTS message_state (
    message_id BIGINT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    mailbox_id BIGINT REFERENCES mailboxes(id) ON DELETE CASCADE,
    flags INTEGER NOT NULL DEFAULT 0,
    custom_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    flags_changed_at TIMESTAMPTZ,
    updated_modseq BIGINT,
    CONSTRAINT max_custom_flags_check CHECK (jsonb_array_length(custom_flags) <= 50)
);

-- Indexes for the new state table
CREATE INDEX IF NOT EXISTS idx_message_state_mailbox_id_updated_modseq ON message_state (mailbox_id, updated_modseq) WHERE updated_modseq IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_message_state_custom_flags ON message_state USING GIN (custom_flags);

-- Drop old columns and indices from messages
DROP INDEX IF EXISTS idx_messages_updated_modseq;
DROP INDEX IF EXISTS idx_messages_mailbox_id_updated_modseq;
DROP INDEX IF EXISTS idx_messages_custom_flags;
DROP INDEX IF EXISTS idx_messages_mailbox_common_search;
DROP INDEX IF EXISTS idx_messages_mailbox_modseqs;
DROP INDEX IF EXISTS idx_messages_first_unseen;

-- Recreate indices on messages without mutable fields
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_common_search ON messages (mailbox_id, internal_date, size, uid) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_modseqs ON messages (mailbox_id, created_modseq, expunged_modseq);

CREATE INDEX IF NOT EXISTS idx_message_state_first_unseen ON message_state (mailbox_id, message_id) WHERE (flags & 1) = 0;

-- ============================================================================
-- 1. DROP OLD TRIGGERS
-- ============================================================================
DROP TRIGGER IF EXISTS trigger_messages_stats_insert_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_delete_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_update_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_insert_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_delete_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_update_stmt ON messages;

-- ============================================================================
-- 2. MESSAGES TABLE TRIGGER (handles counts, size, creation modseqs)
-- ============================================================================
CREATE OR REPLACE FUNCTION maintain_mailbox_stats_messages() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(size) AS size_delta,
                   MAX(created_modseq) AS modseq_val
            FROM new_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        INSERT INTO mailbox_stats (mailbox_id, message_count, total_size, highest_modseq, updated_at)
        SELECT mailbox_id, count_delta, size_delta, modseq_val, now() FROM deltas
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + EXCLUDED.message_count,
            total_size = mailbox_stats.total_size + EXCLUDED.total_size,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, EXCLUDED.highest_modseq),
            updated_at = now();
            
    ELSIF TG_OP = 'DELETE' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(size) AS size_delta
            FROM old_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        UPDATE mailbox_stats ms
        SET message_count = ms.message_count - d.count_delta,
            total_size = ms.total_size - d.size_delta,
            updated_at = now()
        FROM deltas d
        WHERE ms.mailbox_id = d.mailbox_id;
        
    ELSIF TG_OP = 'UPDATE' THEN
        WITH deltas AS (
            SELECT 
                mb.mailbox_id,
                SUM(mb.count_delta) AS count_delta,
                SUM(mb.unseen_delta) AS unseen_delta,
                SUM(mb.size_delta) AS size_delta,
                MAX(mb.modseq_val) AS max_modseq
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            LEFT JOIN message_state ms ON ms.message_id = n.id AND ms.mailbox_id = o.mailbox_id
            CROSS JOIN LATERAL (
                SELECT o.mailbox_id AS mailbox_id,
                       -1 AS count_delta,
                       -(1 - COALESCE(ms.flags & 1, 0)) AS unseen_delta,
                       -o.size AS size_delta,
                       0::BIGINT AS modseq_val
                WHERE o.expunged_at IS NULL 
                  AND (o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                UNION ALL
                SELECT n.mailbox_id AS mailbox_id,
                       1 AS count_delta,
                       1 - COALESCE(ms.flags & 1, 0) AS unseen_delta,
                       n.size AS size_delta,
                       CASE WHEN o.mailbox_id IS DISTINCT FROM n.mailbox_id THEN COALESCE(n.created_modseq, 0) ELSE 0 END AS modseq_val
                WHERE n.expunged_at IS NULL
                  AND (o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                UNION ALL
                SELECT n.mailbox_id AS mailbox_id,
                       0 AS count_delta,
                       0 AS unseen_delta,
                       0::BIGINT AS size_delta,
                       COALESCE(n.expunged_modseq, 0) AS modseq_val
                WHERE o.expunged_at IS NULL AND n.expunged_at IS NOT NULL
            ) mb
            WHERE mb.mailbox_id IS NOT NULL
            GROUP BY mb.mailbox_id
        )
        UPDATE mailbox_stats ms
        SET message_count = ms.message_count + d.count_delta,
            unseen_count = ms.unseen_count + d.unseen_delta,
            total_size = ms.total_size + d.size_delta,
            highest_modseq = GREATEST(ms.highest_modseq, d.max_modseq),
            updated_at = now()
        FROM deltas d
        WHERE ms.mailbox_id = d.mailbox_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_messages_base_stats_insert_stmt
    AFTER INSERT ON messages
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_messages();

CREATE TRIGGER trigger_messages_base_stats_delete_stmt
    AFTER DELETE ON messages
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_messages();

CREATE TRIGGER trigger_messages_base_stats_update_stmt
    AFTER UPDATE ON messages
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_messages();

-- ============================================================================
-- 3. MESSAGE STATE TABLE TRIGGER (handles flags unseen counts, modseqs, cache)
-- ============================================================================
CREATE OR REPLACE FUNCTION maintain_mailbox_stats_state() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Updates unseen counts and custom flags cache
        WITH deltas AS (
            SELECT ms.mailbox_id,
                   SUM(1 - (ms.flags & 1)) AS unseen_delta,
                   MAX(ms.updated_modseq) AS modseq_val
            FROM new_table ms
            JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
            WHERE m.expunged_at IS NULL AND ms.mailbox_id IS NOT NULL
            GROUP BY ms.mailbox_id
        )
        UPDATE mailbox_stats mstats
        SET unseen_count = mstats.unseen_count + d.unseen_delta,
            highest_modseq = GREATEST(mstats.highest_modseq, d.modseq_val),
            updated_at = now()
        FROM deltas d
        WHERE mstats.mailbox_id = d.mailbox_id;

        UPDATE mailbox_stats mstats
        SET custom_flags_cache = (
            SELECT COALESCE(jsonb_agg(DISTINCT flag ORDER BY flag), '[]'::jsonb)
            FROM (
                SELECT jsonb_array_elements_text(COALESCE(mstats.custom_flags_cache, '[]'::jsonb)) AS flag
                UNION
                SELECT jsonb_array_elements_text(n.custom_flags) AS flag
                FROM new_table n
                WHERE n.mailbox_id = mstats.mailbox_id AND n.custom_flags IS NOT NULL
            ) sub WHERE flag !~ '^\\'
        )
        FROM (
            SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL AND custom_flags IS NOT NULL AND custom_flags != '[]'::jsonb
        ) am
        WHERE mstats.mailbox_id = am.mailbox_id;

    ELSIF TG_OP = 'DELETE' THEN
        WITH deltas AS (
            SELECT ms.mailbox_id,
                   SUM(1 - (ms.flags & 1)) AS unseen_delta
            FROM old_table ms
            JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
            WHERE m.expunged_at IS NULL AND ms.mailbox_id IS NOT NULL
            GROUP BY ms.mailbox_id
        )
        UPDATE mailbox_stats mstats
        SET unseen_count = mstats.unseen_count - d.unseen_delta,
            updated_at = now()
        FROM deltas d
        WHERE mstats.mailbox_id = d.mailbox_id;
        
    ELSIF TG_OP = 'UPDATE' THEN
        WITH deltas AS (
             SELECT n.mailbox_id,
                SUM( (1 - (n.flags & 1)) - (1 - (o.flags & 1)) ) AS unseen_delta,
                MAX(n.updated_modseq) AS modseq_val
            FROM old_table o
            JOIN new_table n ON o.message_id = n.message_id
            JOIN messages m ON m.id = n.message_id AND m.mailbox_id = n.mailbox_id
            WHERE m.expunged_at IS NULL AND n.mailbox_id IS NOT NULL AND n.flags IS DISTINCT FROM o.flags
            GROUP BY n.mailbox_id
        )
        UPDATE mailbox_stats mstats
        SET unseen_count = mstats.unseen_count + d.unseen_delta,
            highest_modseq = GREATEST(mstats.highest_modseq, d.modseq_val),
            updated_at = now()
        FROM deltas d
        WHERE mstats.mailbox_id = d.mailbox_id;

        UPDATE mailbox_stats mstats
        SET custom_flags_cache = (
            SELECT COALESCE(jsonb_agg(DISTINCT flag ORDER BY flag), '[]'::jsonb)
            FROM (
                SELECT jsonb_array_elements_text(COALESCE(mstats.custom_flags_cache, '[]'::jsonb)) AS flag
                UNION
                SELECT jsonb_array_elements_text(n.custom_flags) AS flag
                FROM new_table n
                JOIN old_table o ON n.message_id = o.message_id
                WHERE n.mailbox_id = mstats.mailbox_id AND n.custom_flags IS NOT NULL AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
            ) sub WHERE flag !~ '^\\'
        )
        FROM (
            SELECT DISTINCT n.mailbox_id FROM old_table o JOIN new_table n ON o.message_id = n.message_id
            WHERE n.mailbox_id IS NOT NULL AND n.custom_flags IS NOT NULL AND n.custom_flags != '[]'::jsonb AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
        ) am
        WHERE mstats.mailbox_id = am.mailbox_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_message_state_stats_insert_stmt
    AFTER INSERT ON message_state
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_state();

CREATE TRIGGER trigger_message_state_stats_delete_stmt
    AFTER DELETE ON message_state
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_state();

CREATE TRIGGER trigger_message_state_stats_update_stmt
    AFTER UPDATE ON message_state
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_state();

-- Set defaults on legacy columns so INSERTs that only write to message_state
-- don't violate NOT NULL constraints during the transition period.
ALTER TABLE messages ALTER COLUMN flags SET DEFAULT 0;

-- Drop constraint first
ALTER TABLE messages
    DROP CONSTRAINT max_custom_flags_check;

-- Then drop columns
ALTER TABLE messages
    DROP COLUMN flags,
    DROP COLUMN custom_flags,
    DROP COLUMN flags_changed_at,
    DROP COLUMN updated_modseq;

DROP TRIGGER IF EXISTS zzz_sync_message_state_trigger ON messages;
DROP FUNCTION IF EXISTS sync_message_state();

COMMIT;

