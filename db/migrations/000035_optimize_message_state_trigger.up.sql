-- Migration 035: Optimize maintain_mailbox_stats_state trigger to skip expensive JSONB operations
-- when only system flags change (no custom flags involved).
--
-- Problem: The UPDATE branch unconditionally runs JSONB aggregation even when removing
-- system flags like \Deleted. This causes 2+ second spikes on large flag batches.
--
-- Solution: Only update custom_flags_cache when custom_flags actually changed.

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
        -- FIXED: Use INSERT ... ON CONFLICT DO UPDATE so unseen_deltas are not lost
        -- if this trigger executes before the messages trigger
        INSERT INTO mailbox_stats (mailbox_id, unseen_count, highest_modseq, updated_at)
        SELECT mailbox_id, unseen_delta, COALESCE(modseq_val, 0), now() FROM deltas
        ON CONFLICT (mailbox_id) DO UPDATE SET
            unseen_count = mailbox_stats.unseen_count + EXCLUDED.unseen_count,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, EXCLUDED.highest_modseq),
            updated_at = now();

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
        -- Update unseen counts and modseqs (always needed for flag changes)
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

        -- OPTIMIZATION: Skip expensive JSONB aggregation if no custom flags changed.
        -- The original code unconditionally scanned custom_flags_cache (line 228 in migration 22)
        -- even when only system flags changed, causing 2s+ spikes on large batches.
        -- Now we check IF EXISTS first and short-circuit if there's nothing to update.
        IF EXISTS (
            SELECT 1
            FROM old_table o
            JOIN new_table n ON o.message_id = n.message_id
            WHERE n.mailbox_id IS NOT NULL
              AND n.custom_flags IS NOT NULL
              AND n.custom_flags != '[]'::jsonb
              AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
            LIMIT 1
        ) THEN
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
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
