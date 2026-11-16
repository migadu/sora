-- Migration 066: an un-expunged message raises its mailbox's highest_modseq.
--
-- maintain_mailbox_stats_messages took an addition's created_modseq toward the mailbox's
-- highest_modseq only when the message changed mailbox, and 0 for a message un-expunged in place:
--
--     MAX(CASE WHEN old_mailbox_id IS DISTINCT FROM new_mailbox_id THEN created_modseq ELSE 0 END)
--
-- Restore (db.RestoreMessages) is the only UPDATE that un-expunges, and it now gives the message a
-- fresh created_modseq, as RFC 7162 section 3.1 requires for a message that appears in a mailbox
-- ("the server generates a new modification sequence that is higher than the highest modification
-- sequence of all messages in the mailbox and assigns it to the appended message"). HIGHESTMODSEQ is
-- "the highest mod-sequence value of all messages in the mailbox" (section 3.1.2.1), so every addition
-- now counts its created_modseq. An addition is either an un-expunge or a move, so the CASE is gone.
--
-- Body copied verbatim from migration 000037; ONLY that expression changed. Replacing the function
-- rewrites no table. An older binary's restore keeps the old created_modseq, which GREATEST ignores,
-- exactly as before.

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
                MAX(created_modseq) AS max_modseq
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
