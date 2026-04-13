-- Migration 022: Vertical Partitioning of Message State (Down)

BEGIN;

ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS flags INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS custom_flags JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS flags_changed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS updated_modseq BIGINT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'max_custom_flags_check' AND conrelid = 'messages'::regclass
    ) THEN
        ALTER TABLE messages ADD CONSTRAINT max_custom_flags_check CHECK (jsonb_array_length(custom_flags) <= 50);
    END IF;
END $$;

-- Migrate data back
UPDATE messages m
SET flags = ms.flags,
    custom_flags = ms.custom_flags,
    flags_changed_at = ms.flags_changed_at,
    updated_modseq = ms.updated_modseq
FROM message_state ms
WHERE m.id = ms.message_id;

-- Recreate indices
CREATE INDEX IF NOT EXISTS idx_messages_updated_modseq ON messages (updated_modseq) WHERE updated_modseq IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_id_updated_modseq ON messages (mailbox_id, updated_modseq);
CREATE INDEX IF NOT EXISTS idx_messages_custom_flags ON messages USING GIN (custom_flags);

-- Recreate idx_messages_mailbox_common_search with (flags & 1)
DROP INDEX IF EXISTS idx_messages_mailbox_common_search;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_common_search ON messages (mailbox_id, (flags & 1), internal_date, size, uid) WHERE expunged_at IS NULL;

-- Recreate idx_messages_mailbox_modseqs
DROP INDEX IF EXISTS idx_messages_mailbox_modseqs;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_modseqs ON messages (mailbox_id, created_modseq, updated_modseq, expunged_modseq);

CREATE INDEX IF NOT EXISTS idx_messages_first_unseen ON messages (mailbox_id, uid) WHERE (flags & 1) = 0 AND expunged_at IS NULL;

-- Drop table
DROP TABLE message_state;

-- Revert triggers back to how they were in Migration 019
DROP TRIGGER IF EXISTS trigger_messages_base_stats_insert_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_messages_base_stats_delete_stmt ON messages;
DROP TRIGGER IF EXISTS trigger_messages_base_stats_update_stmt ON messages;

-- (The down migration for 022 restores the exact original functions from 019)
CREATE OR REPLACE FUNCTION maintain_mailbox_stats_statement()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(1 - (flags & 1)) AS unseen_delta,
                   SUM(size) AS size_delta,
                   MAX(created_modseq) AS modseq_val
            FROM new_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
        SELECT mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now() FROM deltas
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + EXCLUDED.message_count,
            unseen_count = mailbox_stats.unseen_count + EXCLUDED.unseen_count,
            total_size = mailbox_stats.total_size + EXCLUDED.total_size,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, EXCLUDED.highest_modseq),
            updated_at = now();

    ELSIF TG_OP = 'DELETE' THEN
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(1 - (flags & 1)) AS unseen_delta,
                   SUM(size) AS size_delta
            FROM old_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        UPDATE mailbox_stats ms
        SET message_count = ms.message_count - d.count_delta,
            unseen_count = ms.unseen_count - d.unseen_delta,
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
            CROSS JOIN LATERAL (
                SELECT o.mailbox_id AS mailbox_id,
                       -1 AS count_delta,
                       -(1 - (o.flags & 1)) AS unseen_delta,
                       -o.size AS size_delta,
                       0::BIGINT AS modseq_val
                WHERE o.expunged_at IS NULL 
                  AND (o.flags IS DISTINCT FROM n.flags OR o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                UNION ALL
                SELECT n.mailbox_id AS mailbox_id,
                       1 AS count_delta,
                       1 - (n.flags & 1) AS unseen_delta,
                       n.size AS size_delta,
                       GREATEST(
                           CASE WHEN n.flags IS DISTINCT FROM o.flags THEN COALESCE(n.updated_modseq, 0) ELSE 0 END,
                           CASE WHEN o.mailbox_id IS DISTINCT FROM n.mailbox_id THEN COALESCE(n.created_modseq, 0) ELSE 0 END
                       ) AS modseq_val
                WHERE n.expunged_at IS NULL
                  AND (o.flags IS DISTINCT FROM n.flags OR o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
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

CREATE TRIGGER trigger_messages_stats_insert_stmt
    AFTER INSERT ON messages
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_statement();

CREATE TRIGGER trigger_messages_stats_delete_stmt
    AFTER DELETE ON messages
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_statement();

CREATE TRIGGER trigger_messages_stats_update_stmt
    AFTER UPDATE ON messages
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_mailbox_stats_statement();

CREATE OR REPLACE FUNCTION maintain_custom_flags_cache_statement()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE mailbox_stats ms
        SET custom_flags_cache = (
            SELECT COALESCE(jsonb_agg(DISTINCT flag ORDER BY flag), '[]'::jsonb)
            FROM (
                SELECT jsonb_array_elements_text(COALESCE(ms.custom_flags_cache, '[]'::jsonb)) AS flag
                UNION
                SELECT jsonb_array_elements_text(n.custom_flags) AS flag
                FROM new_table n
                WHERE n.mailbox_id = ms.mailbox_id AND n.custom_flags IS NOT NULL
            ) sub WHERE flag !~ '^\\'
        )
        FROM (SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL AND custom_flags IS NOT NULL AND custom_flags != '[]'::jsonb) am
        WHERE ms.mailbox_id = am.mailbox_id;
    ELSIF TG_OP = 'DELETE' THEN
        NULL;
    ELSE
        UPDATE mailbox_stats ms
        SET custom_flags_cache = (
            SELECT COALESCE(jsonb_agg(DISTINCT flag ORDER BY flag), '[]'::jsonb)
            FROM (
                SELECT jsonb_array_elements_text(COALESCE(ms.custom_flags_cache, '[]'::jsonb)) AS flag
                UNION
                SELECT jsonb_array_elements_text(n.custom_flags) AS flag
                FROM new_table n JOIN old_table o ON n.id = o.id
                WHERE n.mailbox_id = ms.mailbox_id AND n.custom_flags IS NOT NULL AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
            ) sub WHERE flag !~ '^\\'
        )
        FROM (SELECT DISTINCT n.mailbox_id FROM old_table o JOIN new_table n ON o.id = n.id WHERE n.mailbox_id IS NOT NULL AND n.custom_flags IS NOT NULL AND n.custom_flags != '[]'::jsonb AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)) am
        WHERE ms.mailbox_id = am.mailbox_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_zzz_custom_flags_cache_insert_stmt
    AFTER INSERT ON messages
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_custom_flags_cache_statement();

CREATE TRIGGER trigger_zzz_custom_flags_cache_delete_stmt
    AFTER DELETE ON messages
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_custom_flags_cache_statement();

CREATE TRIGGER trigger_zzz_custom_flags_cache_update_stmt
    AFTER UPDATE ON messages
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT EXECUTE FUNCTION maintain_custom_flags_cache_statement();

COMMIT;
