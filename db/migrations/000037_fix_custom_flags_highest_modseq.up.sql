-- Migration 037: Fix mailbox_stats trigger bugs (this migration was NOT yet deployed when the
-- second bug below was found, so both fixes are folded in here instead of a separate migration).
--
-- Bug 1 (maintain_mailbox_stats_state): The trigger on message_state only updated highest_modseq when
-- n.flags IS DISTINCT FROM o.flags. When only CUSTOM flags change, highest_modseq was not bumped on
-- mailbox_stats, causing HIGHESTMODSEQ desync in IMAP (PollMailbox early-exits on currentModSeq <= since).
-- Fix: include n.custom_flags IS DISTINCT FROM o.custom_flags in the modseq delta check (below).
--
-- Bug 2 (maintain_mailbox_stats_messages): The UPDATE branch wrote the count/size/unseen deltas with a
-- plain `UPDATE mailbox_stats ... WHERE mailbox_id = d.mailbox_id`. When the additions side targets a
-- mailbox that has NO mailbox_stats row yet, that UPDATE matches 0 rows and the +N is silently dropped,
-- permanently undercounting message_count (and unseen_count/total_size). Reachable via `sora-admin
-- messages restore`: restore creates the target mailbox on the fly (no stats row, see db/restore.go) then
-- un-expunges messages into it via UPDATE messages SET expunged_at=NULL, mailbox_id=$target.
-- Fix: the UPDATE branch's final write becomes INSERT ... ON CONFLICT (mailbox_id) DO UPDATE (UPSERT),
-- mirroring the already-correct INSERT branch, so a brand-new destination mailbox gets its row created.
--
-- Scope note: only the messages UPDATE branch is converted to UPSERT. The DELETE branches and the
-- message_state UPDATE/DELETE branches are subtraction/flag-change paths that ALWAYS operate on a mailbox
-- that already has a stats row (the row is created by the INSERT/UPDATE-additions path first), and their
-- deltas can be negative -- UPSERTing them would risk inserting rows with negative counts, so they are
-- intentionally left as plain UPDATE. Existing on-disk drift is healed separately by
-- db.RecalculateMailboxStats / `sora-admin mailbox recalculate-stats`.

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
            WHERE m.expunged_at IS NULL AND n.mailbox_id IS NOT NULL AND (n.flags IS DISTINCT FROM o.flags OR n.custom_flags IS DISTINCT FROM o.custom_flags)
            GROUP BY n.mailbox_id
        )
        UPDATE mailbox_stats mstats
        SET unseen_count = mstats.unseen_count + d.unseen_delta,
            highest_modseq = GREATEST(mstats.highest_modseq, d.modseq_val),
            updated_at = now()
        FROM deltas d
        WHERE mstats.mailbox_id = d.mailbox_id;

        -- OPTIMIZATION: Skip expensive JSONB aggregation if no custom flags changed.
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

-- Bug 2 fix: maintain_mailbox_stats_messages UPDATE branch must UPSERT so additions into a
-- mailbox without an existing mailbox_stats row are not silently dropped. Body copied verbatim from
-- migration 000025; ONLY the final write of the UPDATE branch changed (plain UPDATE -> UPSERT).
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
        -- Subtraction-only path: the mailbox always has a stats row (it had active messages),
        -- so a plain UPDATE is correct here; UPSERT would risk inserting a negative count.
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
        WITH relevant_changes AS (
            SELECT
                o.mailbox_id AS old_mailbox_id,
                n.mailbox_id AS new_mailbox_id,
                o.expunged_at IS NULL AS was_active,
                n.expunged_at IS NULL AS is_active,
                o.size AS old_size,
                n.size AS new_size,
                n.expunged_modseq,
                n.created_modseq,
                n.id AS message_id
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            WHERE o.mailbox_id IS DISTINCT FROM n.mailbox_id
               OR o.expunged_at IS DISTINCT FROM n.expunged_at
        ),
        changes_with_flags AS (
            SELECT
                c.*,
                COALESCE(ms.flags & 1, 0) AS seen_flag
            FROM relevant_changes c
            LEFT JOIN message_state ms ON ms.message_id = c.message_id AND ms.mailbox_id = c.old_mailbox_id
            WHERE c.was_active OR c.is_active
        ),
        deltas AS (
            -- Subtractions from old mailbox (expunge or move)
            SELECT
                old_mailbox_id AS mailbox_id,
                COUNT(*) * -1 AS count_delta,
                SUM(-(1 - seen_flag)) AS unseen_delta,
                SUM(-old_size) AS size_delta,
                0::BIGINT AS max_modseq
            FROM changes_with_flags
            WHERE was_active
            GROUP BY old_mailbox_id

            UNION ALL

            -- Additions to new mailbox (un-expunge or move)
            SELECT
                new_mailbox_id AS mailbox_id,
                COUNT(*) AS count_delta,
                SUM(1 - seen_flag) AS unseen_delta,
                SUM(new_size) AS size_delta,
                MAX(CASE WHEN old_mailbox_id IS DISTINCT FROM new_mailbox_id THEN created_modseq ELSE 0 END) AS max_modseq
            FROM changes_with_flags
            WHERE is_active
            GROUP BY new_mailbox_id

            UNION ALL

            -- Modseq updates for pure expunges
            SELECT
                new_mailbox_id AS mailbox_id,
                0 AS count_delta,
                0 AS unseen_delta,
                0::BIGINT AS size_delta,
                MAX(expunged_modseq) AS max_modseq
            FROM relevant_changes
            WHERE is_active = false AND was_active = true
            GROUP BY new_mailbox_id
        ),
        aggregated_deltas AS (
            SELECT
                mailbox_id,
                SUM(count_delta) AS count_delta,
                SUM(unseen_delta) AS unseen_delta,
                SUM(size_delta) AS size_delta,
                MAX(max_modseq) AS max_modseq
            FROM deltas
            WHERE mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        -- UPSERT: a brand-new destination mailbox (additions only, all deltas >= 0) gets its row
        -- created; an existing source/destination mailbox is updated in place. Source mailboxes
        -- (net-negative deltas) always already have a row, so DO UPDATE applies, never a fresh INSERT.
        INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
        SELECT mailbox_id, count_delta, unseen_delta, size_delta, max_modseq, now()
        FROM aggregated_deltas
        WHERE mailbox_id IS NOT NULL
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + EXCLUDED.message_count,
            unseen_count = mailbox_stats.unseen_count + EXCLUDED.unseen_count,
            total_size = mailbox_stats.total_size + EXCLUDED.total_size,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, EXCLUDED.highest_modseq),
            updated_at = now();
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Correct production data: set highest_modseq to the actual max updated_modseq
-- if it was missed due to custom flags trigger bug.
UPDATE mailbox_stats ms
SET highest_modseq = GREATEST(ms.highest_modseq, sub.max_modseq),
    updated_at = NOW()
FROM (
    SELECT mailbox_id, MAX(updated_modseq) AS max_modseq
    FROM message_state
    GROUP BY mailbox_id
) sub
WHERE ms.mailbox_id = sub.mailbox_id AND ms.highest_modseq < sub.max_modseq;

