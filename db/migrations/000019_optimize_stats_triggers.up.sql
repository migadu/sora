-- Migration 019: Optimize maintain_mailbox_stats and maintain_custom_flags_cache triggers
-- Replaces O(N) FOR EACH ROW triggers doing massive computations with O(1) FOR EACH STATEMENT batching.

-- ============================================================================
-- 1. DROP OLD ROW-LEVEL TRIGGERS
-- ============================================================================
DROP TRIGGER IF EXISTS trigger_messages_stats_insert ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_delete ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_update ON messages;

DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache ON messages;
DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_update ON messages;

-- ============================================================================
-- 2. STATEMENT-LEVEL MAILBOX STATS
-- ============================================================================
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
                -- 1. Subtraction from OLD mailbox (if message is active)
                SELECT o.mailbox_id AS mailbox_id,
                       -1 AS count_delta,
                       -(1 - (o.flags & 1)) AS unseen_delta,
                       -o.size AS size_delta,
                       0::BIGINT AS modseq_val
                WHERE o.expunged_at IS NULL 
                  AND (o.flags IS DISTINCT FROM n.flags OR o.expunged_at IS DISTINCT FROM n.expunged_at OR o.mailbox_id IS DISTINCT FROM n.mailbox_id)
                
                UNION ALL
                
                -- 2. Addition to NEW mailbox (if message is active)
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
                
                -- 3. Modseq tracking for EXPUNGED messages (applies to NEW mailbox)
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
        WHERE ms.mailbox_id = d.mailbox_id
          AND (d.count_delta != 0 OR d.unseen_delta != 0 OR d.size_delta != 0 OR d.max_modseq > ms.highest_modseq);
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_messages_stats_insert_stmt ON messages;
CREATE TRIGGER trigger_messages_stats_insert_stmt
    AFTER INSERT ON messages
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_mailbox_stats_statement();

DROP TRIGGER IF EXISTS trigger_messages_stats_delete_stmt ON messages;
CREATE TRIGGER trigger_messages_stats_delete_stmt
    AFTER DELETE ON messages
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_mailbox_stats_statement();

DROP TRIGGER IF EXISTS trigger_messages_stats_update_stmt ON messages;
CREATE TRIGGER trigger_messages_stats_update_stmt
    AFTER UPDATE ON messages
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_mailbox_stats_statement();

-- ============================================================================
-- 3. STATEMENT-LEVEL CUSTOM FLAGS CACHE
-- ============================================================================
CREATE OR REPLACE FUNCTION maintain_custom_flags_cache_statement()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE mailbox_stats ms
        SET custom_flags_cache = COALESCE(
            (SELECT jsonb_agg(DISTINCT flag ORDER BY flag)
             FROM messages m
             CROSS JOIN LATERAL jsonb_array_elements_text(m.custom_flags) AS elem(flag)
             WHERE m.mailbox_id = am.mailbox_id
               AND m.expunged_at IS NULL
               AND flag !~ '^\\'),
            '[]'::jsonb
        )
        FROM (
            SELECT DISTINCT mailbox_id 
            FROM new_table 
            WHERE mailbox_id IS NOT NULL AND custom_flags IS NOT NULL AND custom_flags != '[]'::jsonb
        ) am
        WHERE ms.mailbox_id = am.mailbox_id;

    ELSIF TG_OP = 'DELETE' THEN
        UPDATE mailbox_stats ms
        SET custom_flags_cache = COALESCE(
            (SELECT jsonb_agg(DISTINCT flag ORDER BY flag)
             FROM messages m
             CROSS JOIN LATERAL jsonb_array_elements_text(m.custom_flags) AS elem(flag)
             WHERE m.mailbox_id = am.mailbox_id
               AND m.expunged_at IS NULL
               AND flag !~ '^\\'),
            '[]'::jsonb
        )
        FROM (
            SELECT DISTINCT mailbox_id 
            FROM old_table 
            WHERE mailbox_id IS NOT NULL AND custom_flags IS NOT NULL AND custom_flags != '[]'::jsonb
        ) am
        WHERE ms.mailbox_id = am.mailbox_id;

    ELSE -- UPDATE
        UPDATE mailbox_stats ms
        SET custom_flags_cache = COALESCE(
            (SELECT jsonb_agg(DISTINCT flag ORDER BY flag)
             FROM messages m
             CROSS JOIN LATERAL jsonb_array_elements_text(m.custom_flags) AS elem(flag)
             WHERE m.mailbox_id = am.mailbox_id
               AND m.expunged_at IS NULL
               AND flag !~ '^\\'),
            '[]'::jsonb
        )
        FROM (
            SELECT DISTINCT o.mailbox_id
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            WHERE o.mailbox_id IS NOT NULL
              AND (
                  o.custom_flags IS DISTINCT FROM n.custom_flags OR 
                  (o.expunged_at IS NULL) IS DISTINCT FROM (n.expunged_at IS NULL) OR
                  o.mailbox_id IS DISTINCT FROM n.mailbox_id
              )
            UNION
            SELECT DISTINCT n.mailbox_id
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            WHERE n.mailbox_id IS NOT NULL
              AND (
                  o.custom_flags IS DISTINCT FROM n.custom_flags OR 
                  (o.expunged_at IS NULL) IS DISTINCT FROM (n.expunged_at IS NULL) OR
                  o.mailbox_id IS DISTINCT FROM n.mailbox_id
              )
        ) am
        WHERE ms.mailbox_id = am.mailbox_id;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_insert_stmt ON messages;
CREATE TRIGGER trigger_zzz_custom_flags_cache_insert_stmt
    AFTER INSERT ON messages
    REFERENCING NEW TABLE AS new_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_custom_flags_cache_statement();

DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_delete_stmt ON messages;
CREATE TRIGGER trigger_zzz_custom_flags_cache_delete_stmt
    AFTER DELETE ON messages
    REFERENCING OLD TABLE AS old_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_custom_flags_cache_statement();

DROP TRIGGER IF EXISTS trigger_zzz_custom_flags_cache_update_stmt ON messages;
CREATE TRIGGER trigger_zzz_custom_flags_cache_update_stmt
    AFTER UPDATE ON messages
    REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
    FOR EACH STATEMENT
    EXECUTE FUNCTION maintain_custom_flags_cache_statement();
