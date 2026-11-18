-- Migration 076: a live message without a message_state row counts as unseen in
-- mailbox_stats.unseen_count.
--
-- Such a message (left by older builds) has no flags: FETCH and the User API show it unread and
-- SEARCH UNSEEN matches it (#1899). unseen_count left it out, so STATUS UNSEEN, the User API mailbox
-- list and SELECT's [UNSEEN n] gate disagreed with SEARCH (#1949). The messages UPDATE branch already
-- counted it as unseen (COALESCE(ms.flags & 1, 0)), so expunging one took 1 from a count that never
-- held it.
--
-- unseen_count is now the number of live messages without a \Seen state row:
--   - messages INSERT adds each live message as unseen (it has no state row yet);
--   - message_state INSERT takes out the \Seen ones (-flags&1 instead of +(1 - flags&1));
--   - message_state DELETE of a live message's row puts a \Seen one back (+flags&1 instead of
--     -(1 - flags&1));
--   - the messages UPDATE/DELETE and message_state UPDATE branches are unchanged.
-- Every current insert writes the message and its state row in one statement, and the deltas add up
-- the same whichever trigger runs first. db.liveUnseenCount (RecomputeMailboxUnseen, repair-unseen)
-- counts the same set.
--
-- Replacing the functions rewrites no table. Existing counts of mailboxes holding such messages stay
-- too low by their number until `sora-admin mailbox repair-unseen --apply` recomputes them.
--
-- Bodies copied verbatim from migrations 000037 (maintain_mailbox_stats_state) and 000066
-- (maintain_mailbox_stats_messages); only the branches above changed.

CREATE OR REPLACE FUNCTION maintain_mailbox_stats_state() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- A live message without a state row is counted unseen (the messages trigger counted
        -- it on insert), so its new row takes it out of unseen_count only if it is \Seen.
        WITH deltas AS (
            SELECT ms.mailbox_id,
                   -SUM(ms.flags & 1) AS unseen_delta,
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
        -- A live message that loses its state row has no flags left, so it is unseen again:
        -- only a \Seen row's deletion changes unseen_count.
        WITH deltas AS (
            SELECT ms.mailbox_id,
                   SUM(ms.flags & 1) AS unseen_delta
            FROM old_table ms
            JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
            WHERE m.expunged_at IS NULL AND ms.mailbox_id IS NOT NULL
            GROUP BY ms.mailbox_id
        )
        UPDATE mailbox_stats mstats
        SET unseen_count = mstats.unseen_count + d.unseen_delta,
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

CREATE OR REPLACE FUNCTION maintain_mailbox_stats_messages() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- A new message has no state row yet, so it is unseen; the message_state INSERT
        -- trigger takes out the ones whose row is \Seen.
        WITH deltas AS (
            SELECT mailbox_id,
                   COUNT(*) AS count_delta,
                   SUM(size) AS size_delta,
                   MAX(created_modseq) AS modseq_val
            FROM new_table
            WHERE expunged_at IS NULL AND mailbox_id IS NOT NULL
            GROUP BY mailbox_id
        )
        INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
        SELECT mailbox_id, count_delta, count_delta, size_delta, modseq_val, now() FROM deltas
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + EXCLUDED.message_count,
            unseen_count = mailbox_stats.unseen_count + EXCLUDED.unseen_count,
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
