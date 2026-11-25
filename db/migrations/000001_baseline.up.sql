-- Sora database schema, baseline.
--
-- This one file creates the complete schema. It replaces the 75 migrations (000001 to
-- 000077) the project had accumulated; their history is in git. A database that was built by
-- that chain and reached its last version (77) has this schema and is moved to version 1 by
-- hand, see docs/DATABASE.md ("Moving a database to the baseline"). A database on an older
-- version of the chain must first be upgraded with the last release that carries the chain.
--
-- The body is pg_dump output (PostgreSQL 17) of the schema as it runs in production, so
-- object and column order are those of a live database. Change the schema with a new
-- migration, never by editing this file.
--
-- It runs as one transaction (db/migrate_driver.go).

-- EXTENSION: btree_gin
CREATE EXTENSION IF NOT EXISTS btree_gin WITH SCHEMA public;

-- EXTENSION: pg_trgm
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

-- FUNCTION: has_mailbox_right(bigint, bigint, character)
CREATE FUNCTION public.has_mailbox_right(p_mailbox_id bigint, p_account_id bigint, p_right character) RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_rights TEXT;
    v_is_owner BOOLEAN;
    v_owner_domain TEXT;
    v_user_domain TEXT;
BEGIN
    -- Check if user is the owner (both shared and non-shared mailboxes)
    -- FIXED: Removed "AND NOT COALESCE(is_shared, FALSE)" condition
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
$$;

-- FUNCTION: maintain_credentials_domain()
CREATE FUNCTION public.maintain_credentials_domain() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.domain := SPLIT_PART(NEW.address, '@', 2);
    RETURN NEW;
END;
$$;

-- FUNCTION: maintain_custom_flags_cache()
CREATE FUNCTION public.maintain_custom_flags_cache() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_mailbox_id BIGINT;
    v_old_flags JSONB;
    v_new_flags JSONB;
    v_needs_rebuild BOOLEAN := FALSE;
BEGIN
    -- Determine mailbox and whether custom flags actually changed
    IF TG_OP = 'INSERT' THEN
        v_mailbox_id := NEW.mailbox_id;
        v_new_flags := NEW.custom_flags;
        -- Only rebuild if the new message has custom flags
        IF v_new_flags IS NOT NULL AND v_new_flags != '[]'::jsonb THEN
            v_needs_rebuild := TRUE;
        END IF;
    ELSIF TG_OP = 'DELETE' THEN
        v_mailbox_id := OLD.mailbox_id;
        -- Only rebuild if deleted message had custom flags
        IF OLD.custom_flags IS NOT NULL AND OLD.custom_flags != '[]'::jsonb THEN
            v_needs_rebuild := TRUE;
        END IF;
    ELSE -- UPDATE
        v_mailbox_id := COALESCE(NEW.mailbox_id, OLD.mailbox_id);
        v_old_flags := OLD.custom_flags;
        v_new_flags := NEW.custom_flags;
        -- Rebuild if custom flags changed or message was expunged/restored
        IF v_old_flags IS DISTINCT FROM v_new_flags
           OR (OLD.expunged_at IS NULL) IS DISTINCT FROM (NEW.expunged_at IS NULL) THEN
            v_needs_rebuild := TRUE;
        END IF;
    END IF;

    IF v_mailbox_id IS NULL OR NOT v_needs_rebuild THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Rebuild the cache for this mailbox
    UPDATE mailbox_stats
    SET custom_flags_cache = COALESCE(
        (SELECT jsonb_agg(DISTINCT flag ORDER BY flag)
         FROM messages m
         CROSS JOIN LATERAL jsonb_array_elements_text(m.custom_flags) AS elem(flag)
         WHERE m.mailbox_id = v_mailbox_id
           AND m.expunged_at IS NULL
           AND flag !~ '^\\'),
        '[]'::jsonb
    )
    WHERE mailbox_id = v_mailbox_id;

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

-- FUNCTION: maintain_custom_flags_cache_statement()
CREATE FUNCTION public.maintain_custom_flags_cache_statement() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
            ) sub
            WHERE flag !~ '^\\'
        )
        FROM (
            SELECT DISTINCT mailbox_id 
            FROM new_table 
            WHERE mailbox_id IS NOT NULL AND custom_flags IS NOT NULL AND custom_flags != '[]'::jsonb
        ) am
        WHERE ms.mailbox_id = am.mailbox_id;

    ELSIF TG_OP = 'DELETE' THEN
        -- Retaining custom flags on expunge is highly optimized (O(1)) and compliant with RFC 3501.
        -- We no longer rescan the entire mailbox just to delete a custom flag that zero messages use.
        NULL;

    ELSE -- UPDATE
        UPDATE mailbox_stats ms
        SET custom_flags_cache = (
            SELECT COALESCE(jsonb_agg(DISTINCT flag ORDER BY flag), '[]'::jsonb)
            FROM (
                SELECT jsonb_array_elements_text(COALESCE(ms.custom_flags_cache, '[]'::jsonb)) AS flag
                UNION
                SELECT jsonb_array_elements_text(n.custom_flags) AS flag
                FROM new_table n
                JOIN old_table o ON n.id = o.id
                WHERE n.mailbox_id = ms.mailbox_id 
                  AND n.custom_flags IS NOT NULL 
                  AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
            ) sub
            WHERE flag !~ '^\\'
        )
        FROM (
            SELECT DISTINCT n.mailbox_id
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            WHERE n.mailbox_id IS NOT NULL
              AND n.custom_flags IS NOT NULL AND n.custom_flags != '[]'::jsonb
              AND (n.custom_flags IS DISTINCT FROM o.custom_flags OR n.mailbox_id IS DISTINCT FROM o.mailbox_id)
        ) am
        WHERE ms.mailbox_id = am.mailbox_id;
    END IF;

    RETURN NULL;
END;
$$;

-- FUNCTION: maintain_mailbox_stats()
CREATE FUNCTION public.maintain_mailbox_stats() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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

    ELSIF TG_OP = 'UPDATE' THEN
        -- Track changes in message count (expunge status changes)
        IF (OLD.expunged_at IS NULL) != (NEW.expunged_at IS NULL) THEN
            IF NEW.expunged_at IS NULL THEN
                count_delta := 1;
                size_delta := NEW.size;
            ELSE
                count_delta := -1;
                size_delta := -NEW.size;
            END IF;
        END IF;

        -- Track changes in unseen count (flags changes)
        IF (OLD.flags & 1) != (NEW.flags & 1) AND NEW.expunged_at IS NULL THEN
            IF (NEW.flags & 1) = 0 THEN
                unseen_delta := 1; -- became unseen
            ELSE
                unseen_delta := -1; -- became seen
            END IF;
        END IF;
    END IF;

    -- No changes to track
    IF count_delta = 0 AND unseen_delta = 0 AND size_delta = 0 THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Insert or update mailbox_stats
    -- NOTE: custom_flags_cache now has DEFAULT '[]'::jsonb, so we don't need to set it explicitly
    -- We only need COALESCE in the ON CONFLICT to catch pre-existing NULL rows
    INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
    VALUES (v_mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now())
    ON CONFLICT (mailbox_id) DO UPDATE SET
        message_count = mailbox_stats.message_count + count_delta,
        unseen_count = mailbox_stats.unseen_count + unseen_delta,
        total_size = mailbox_stats.total_size + size_delta,
        highest_modseq = GREATEST(mailbox_stats.highest_modseq, modseq_val),
        updated_at = now(),
        custom_flags_cache = COALESCE(mailbox_stats.custom_flags_cache, '[]'::jsonb);

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

-- FUNCTION: maintain_mailbox_stats_messages()
CREATE FUNCTION public.maintain_mailbox_stats_messages() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;

-- FUNCTION: maintain_mailbox_stats_state()
CREATE FUNCTION public.maintain_mailbox_stats_state() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;

-- FUNCTION: maintain_mailbox_stats_statement()
CREATE FUNCTION public.maintain_mailbox_stats_statement() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
$$;

-- FUNCTION: preserve_message_state_initial_modseq()
-- Records the version a flag row was created with, from its actual INSERT, and keeps it
-- through updates. Rows from before the column existed keep NULL (unknown).
CREATE FUNCTION public.preserve_message_state_initial_modseq() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.initial_modseq := NEW.updated_modseq;
    ELSE
        -- Preserve NULL too: a later UPDATE cannot reconstruct a legacy birth.
        NEW.initial_modseq := OLD.initial_modseq;
    END IF;
    RETURN NEW;
END;
$$;

-- FUNCTION: record_credential_change()
CREATE FUNCTION public.record_credential_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_TABLE_NAME = 'accounts' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO credential_changes (account_id, ends_sessions) VALUES (OLD.id, TRUE);
        ELSE
            INSERT INTO credential_changes (account_id, ends_sessions) VALUES (NEW.id, TRUE);
        END IF;
    ELSE
        INSERT INTO credential_changes (account_id, ends_sessions) VALUES (OLD.account_id, FALSE);
    END IF;
    RETURN NULL;
END;
$$;

-- TABLE: accounts
CREATE TABLE public.accounts (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    purge_requested_at timestamp with time zone,
    purge_attempts integer DEFAULT 0 NOT NULL,
    purge_next_attempt_at timestamp with time zone
);

-- SEQUENCE: accounts_id_seq
CREATE SEQUENCE public.accounts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: accounts_id_seq
ALTER SEQUENCE public.accounts_id_seq OWNED BY public.accounts.id;

-- TABLE: backend_maintenance
-- Backend hosts taken out of rotation. Proxies poll this table and stop routing new
-- sessions to a listed host while the host keeps running, because only the instance that
-- created a pending upload can finish it. instance_id names that upload backlog.
CREATE TABLE public.backend_maintenance (
    host text NOT NULL,
    instance_id text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

-- TABLE: cache_metrics
CREATE TABLE public.cache_metrics (
    instance_id character varying(255) NOT NULL,
    server_hostname character varying(255) NOT NULL,
    hits bigint DEFAULT 0,
    misses bigint DEFAULT 0,
    hit_rate numeric(5,2) DEFAULT 0.00,
    total_operations bigint DEFAULT 0,
    uptime_seconds integer DEFAULT 0,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

-- TABLE: credential_changes
-- The credential change feed: every node learns of revoked logins from here. Rows are not
-- ordered by id or changed_at, because transactions commit out of order. writer_xid is the
-- writing transaction; readers take a primary snapshot's xmin as an inclusive boundary and
-- read all visible changes at or above it, so a late commit cannot be skipped. changed_at is
-- diagnostic. first_observed_at is stamped once the row is visible, and only that stamp
-- allows retention pruning.
CREATE TABLE public.credential_changes (
    id bigint NOT NULL,
    account_id bigint NOT NULL,
    ends_sessions boolean NOT NULL,
    changed_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    writer_xid bigint DEFAULT ((pg_current_xact_id())::text)::bigint NOT NULL,
    first_observed_at timestamp with time zone
);

-- SEQUENCE: credential_changes_id_seq
CREATE SEQUENCE public.credential_changes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: credential_changes_id_seq
ALTER SEQUENCE public.credential_changes_id_seq OWNED BY public.credential_changes.id;

-- TABLE: credentials
CREATE TABLE public.credentials (
    id bigint NOT NULL,
    account_id bigint,
    address text NOT NULL,
    password text NOT NULL,
    primary_identity boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    domain text NOT NULL
);

-- SEQUENCE: credentials_id_seq
CREATE SEQUENCE public.credentials_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: credentials_id_seq
ALTER SEQUENCE public.credentials_id_seq OWNED BY public.credentials.id;

-- TABLE: database_identity
-- A logical identity of this database, for resumable imports. It is data, not a process,
-- host or connection identity: restarts, replica failover and backups preserve it. A clone run
-- as an independent destination must be given a new one before importing into it.
CREATE TABLE public.database_identity (
    singleton boolean DEFAULT true NOT NULL,
    identity uuid DEFAULT gen_random_uuid() NOT NULL,
    CONSTRAINT database_identity_singleton_check CHECK (singleton)
);

-- TABLE: health_status
CREATE TABLE public.health_status (
    component_name character varying(255) NOT NULL,
    server_hostname character varying(255) NOT NULL,
    status character varying(50) NOT NULL,
    last_check timestamp with time zone DEFAULT now(),
    last_error text,
    check_count integer DEFAULT 0,
    fail_count integer DEFAULT 0,
    metadata jsonb,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT health_status_status_check CHECK (((status)::text = ANY (ARRAY[('healthy'::character varying)::text, ('degraded'::character varying)::text, ('unhealthy'::character varying)::text, ('unreachable'::character varying)::text])))
);

-- TABLE: instance_heartbeats
CREATE TABLE public.instance_heartbeats (
    instance_id text NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL
);

-- TABLE: instance_sessions
CREATE TABLE public.instance_sessions (
    instance_id text NOT NULL,
    open_sessions bigint NOT NULL,
    refusing_since timestamp with time zone,
    addresses text[] DEFAULT '{}'::text[] NOT NULL,
    reported_at timestamp with time zone DEFAULT now() NOT NULL
);

-- TABLE: locks
CREATE TABLE public.locks (
    lock_name text NOT NULL,
    acquired_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

-- TABLE: mailbox_acls
CREATE TABLE public.mailbox_acls (
    id bigint NOT NULL,
    mailbox_id bigint NOT NULL,
    account_id bigint,
    rights character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    identifier text NOT NULL,
    CONSTRAINT mailbox_acls_anyone_null_account CHECK ((((identifier = 'anyone'::text) AND (account_id IS NULL)) OR ((identifier <> 'anyone'::text) AND (account_id IS NOT NULL)))),
    CONSTRAINT mailbox_acls_identifier_not_null CHECK (((identifier IS NOT NULL) AND (identifier <> ''::text))),
    CONSTRAINT mailbox_acls_valid_rights CHECK (((rights)::text ~ '^[lrswipkxtea]+$'::text))
);

-- SEQUENCE: mailbox_acls_id_seq
CREATE SEQUENCE public.mailbox_acls_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: mailbox_acls_id_seq
ALTER SEQUENCE public.mailbox_acls_id_seq OWNED BY public.mailbox_acls.id;

-- TABLE: mailbox_stats
CREATE TABLE public.mailbox_stats (
    mailbox_id bigint NOT NULL,
    message_count integer DEFAULT 0 NOT NULL,
    unseen_count integer DEFAULT 0 NOT NULL,
    total_size bigint DEFAULT 0 NOT NULL,
    highest_modseq bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    custom_flags_cache jsonb DEFAULT '[]'::jsonb
);

-- TABLE: mailboxes
CREATE TABLE public.mailboxes (
    id bigint NOT NULL,
    account_id bigint,
    highest_uid bigint DEFAULT 0 NOT NULL,
    name text NOT NULL,
    uid_validity bigint NOT NULL,
    path text DEFAULT ''::text NOT NULL,
    subscribed boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_shared boolean DEFAULT false,
    owner_domain text,
    deleted_at timestamp with time zone,
    special_use text
);

-- SEQUENCE: mailboxes_id_seq
CREATE SEQUENCE public.mailboxes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: mailboxes_id_seq
ALTER SEQUENCE public.mailboxes_id_seq OWNED BY public.mailboxes.id;

-- TABLE: message_state
CREATE TABLE public.message_state (
    message_id bigint NOT NULL,
    mailbox_id bigint,
    flags integer DEFAULT 0 NOT NULL,
    custom_flags jsonb DEFAULT '[]'::jsonb NOT NULL,
    flags_changed_at timestamp with time zone,
    updated_modseq bigint,
    initial_modseq bigint,
    CONSTRAINT max_custom_flags_check CHECK ((jsonb_array_length(custom_flags) <= 50))
);

-- TABLE: messages
CREATE TABLE public.messages (
    id bigint NOT NULL,
    account_id bigint,
    uid bigint NOT NULL,
    s3_domain text NOT NULL,
    s3_localpart text NOT NULL,
    content_hash character varying(64) NOT NULL,
    uploaded boolean DEFAULT false,
    recipients_json jsonb NOT NULL,
    message_id text NOT NULL,
    in_reply_to text,
    subject text,
    sent_date timestamp with time zone NOT NULL,
    internal_date timestamp with time zone NOT NULL,
    size integer NOT NULL,
    body_structure bytea NOT NULL,
    subject_sort text,
    from_name_sort text,
    from_email_sort text,
    to_email_sort text,
    cc_email_sort text,
    mailbox_id bigint,
    mailbox_path text,
    expunged_at timestamp with time zone,
    created_modseq bigint NOT NULL,
    expunged_modseq bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    to_name_sort text,
    "references" text,
    delivery_hash character varying(64),
    extra_addresses text,
    sent_utc_offset integer,
    sent_date_unknown boolean,
    restored_at timestamp with time zone,
    header_presence smallint,
    message_id_raw text
);

-- COMMENT: COLUMN messages.to_name_sort
COMMENT ON COLUMN public.messages.to_name_sort IS 'Normalized TO display name for RFC 5256 DISPLAYTO sorting. NULL if no display name available.';

-- TABLE: messages_fts_v2
-- Body search vectors, one row per (content_hash, account_id); account_id is the mailbox
-- OWNER. Scoping by account is what keeps a body search proportional to one account's mail
-- (see the multicolumn GIN idx_messages_fts_v2_account_tsv). text_body is nulled once its
-- vector is computed, so the vector is the only copy: treat this table as data, not a cache.
CREATE TABLE public.messages_fts_v2 (
    content_hash character varying(64) NOT NULL,
    account_id bigint NOT NULL,
    text_body text,
    text_body_tsv tsvector,
    sent_date timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

-- SEQUENCE: messages_id_seq
CREATE SEQUENCE public.messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: messages_id_seq
ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;

-- SEQUENCE: messages_modseq
CREATE SEQUENCE public.messages_modseq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- TABLE: metadata
CREATE TABLE public.metadata (
    id bigint NOT NULL,
    account_id bigint NOT NULL,
    mailbox_id bigint,
    entry_name text NOT NULL,
    entry_value bytea,
    content_type text DEFAULT 'text/plain'::text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

-- SEQUENCE: metadata_id_seq
CREATE SEQUENCE public.metadata_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: metadata_id_seq
ALTER SEQUENCE public.metadata_id_seq OWNED BY public.metadata.id;

-- TABLE: pending_uploads
CREATE TABLE public.pending_uploads (
    id bigint NOT NULL,
    account_id bigint,
    instance_id text NOT NULL,
    content_hash character varying(64) NOT NULL,
    attempts integer DEFAULT 0,
    last_attempt timestamp with time zone,
    size integer NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    lease_until timestamp with time zone,
    lease_owner text
);

-- SEQUENCE: pending_uploads_id_seq
CREATE SEQUENCE public.pending_uploads_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: pending_uploads_id_seq
ALTER SEQUENCE public.pending_uploads_id_seq OWNED BY public.pending_uploads.id;

-- TABLE: redirect_deliveries
-- The Sieve redirect targets each delivery has already handed to the relay queue. An MTA
-- that misses the 250 delivers the same bytes again, possibly to another node; a row here
-- makes the retry skip that target. delivery_hash is BLAKE3 of the message as received, the
-- same identity as messages.delivery_hash. No foreign key: rows age out with redirect_log.
CREATE TABLE public.redirect_deliveries (
    account_id bigint NOT NULL,
    delivery_hash character varying(64) NOT NULL,
    redirect_to text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

-- TABLE: redirect_log
CREATE TABLE public.redirect_log (
    account_id bigint NOT NULL,
    redirect_date timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    rate_limit integer
);

-- TABLE: s3_body_delete_intents
-- A storage DELETE cannot be retracted when its PostgreSQL lock connection dies, so the
-- intent is committed before the request is sent. An unknown outcome stays quarantined until
-- an operator reconciles it; timestamps and leases here are diagnostic, never permission to
-- clear the row.
CREATE TABLE public.s3_body_delete_intents (
    content_hash text NOT NULL,
    operation_id uuid NOT NULL,
    object_keys text[] NOT NULL,
    retire_snapshot jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    last_error text,
    CONSTRAINT s3_body_delete_intents_content_hash_check CHECK ((content_hash <> ''::text)),
    CONSTRAINT s3_body_delete_intents_object_keys_check CHECK ((cardinality(object_keys) > 0)),
    CONSTRAINT s3_body_delete_intents_retire_snapshot_check CHECK ((jsonb_typeof(retire_snapshot) = 'array'::text))
);

-- TABLE: sieve_scripts
CREATE TABLE public.sieve_scripts (
    id bigint NOT NULL,
    account_id bigint,
    active boolean DEFAULT true NOT NULL,
    name text NOT NULL,
    script text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

-- SEQUENCE: sieve_scripts_id_seq
CREATE SEQUENCE public.sieve_scripts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: sieve_scripts_id_seq
ALTER SEQUENCE public.sieve_scripts_id_seq OWNED BY public.sieve_scripts.id;

-- TABLE: subscriptions
CREATE TABLE public.subscriptions (
    id bigint NOT NULL,
    account_id bigint NOT NULL,
    mailbox_name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

-- SEQUENCE: subscriptions_id_seq
ALTER TABLE public.subscriptions ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.subscriptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

-- TABLE: vacation_responses
CREATE TABLE public.vacation_responses (
    id bigint NOT NULL,
    account_id bigint,
    sender_address text NOT NULL,
    response_date timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    response_identity text DEFAULT ''::text NOT NULL
);

-- SEQUENCE: vacation_responses_id_seq
CREATE SEQUENCE public.vacation_responses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- SEQUENCE OWNED BY: vacation_responses_id_seq
ALTER SEQUENCE public.vacation_responses_id_seq OWNED BY public.vacation_responses.id;

-- DEFAULT: accounts id
ALTER TABLE ONLY public.accounts ALTER COLUMN id SET DEFAULT nextval('public.accounts_id_seq'::regclass);

-- DEFAULT: credential_changes id
ALTER TABLE ONLY public.credential_changes ALTER COLUMN id SET DEFAULT nextval('public.credential_changes_id_seq'::regclass);

-- DEFAULT: credentials id
ALTER TABLE ONLY public.credentials ALTER COLUMN id SET DEFAULT nextval('public.credentials_id_seq'::regclass);

-- DEFAULT: mailbox_acls id
ALTER TABLE ONLY public.mailbox_acls ALTER COLUMN id SET DEFAULT nextval('public.mailbox_acls_id_seq'::regclass);

-- DEFAULT: mailboxes id
ALTER TABLE ONLY public.mailboxes ALTER COLUMN id SET DEFAULT nextval('public.mailboxes_id_seq'::regclass);

-- DEFAULT: messages id
ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);

-- DEFAULT: metadata id
ALTER TABLE ONLY public.metadata ALTER COLUMN id SET DEFAULT nextval('public.metadata_id_seq'::regclass);

-- DEFAULT: pending_uploads id
ALTER TABLE ONLY public.pending_uploads ALTER COLUMN id SET DEFAULT nextval('public.pending_uploads_id_seq'::regclass);

-- DEFAULT: sieve_scripts id
ALTER TABLE ONLY public.sieve_scripts ALTER COLUMN id SET DEFAULT nextval('public.sieve_scripts_id_seq'::regclass);

-- DEFAULT: vacation_responses id
ALTER TABLE ONLY public.vacation_responses ALTER COLUMN id SET DEFAULT nextval('public.vacation_responses_id_seq'::regclass);

-- CONSTRAINT: accounts accounts_pkey
ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);

-- CONSTRAINT: backend_maintenance backend_maintenance_pkey
ALTER TABLE ONLY public.backend_maintenance
    ADD CONSTRAINT backend_maintenance_pkey PRIMARY KEY (host);

-- CONSTRAINT: cache_metrics cache_metrics_pkey
ALTER TABLE ONLY public.cache_metrics
    ADD CONSTRAINT cache_metrics_pkey PRIMARY KEY (instance_id, server_hostname, recorded_at);

-- CONSTRAINT: credential_changes credential_changes_pkey
ALTER TABLE ONLY public.credential_changes
    ADD CONSTRAINT credential_changes_pkey PRIMARY KEY (id);

-- CONSTRAINT: credentials credentials_pkey
ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);

-- CONSTRAINT: database_identity database_identity_pkey
ALTER TABLE ONLY public.database_identity
    ADD CONSTRAINT database_identity_pkey PRIMARY KEY (singleton);

-- CONSTRAINT: health_status health_status_pkey
ALTER TABLE ONLY public.health_status
    ADD CONSTRAINT health_status_pkey PRIMARY KEY (component_name, server_hostname);

-- CONSTRAINT: instance_heartbeats instance_heartbeats_pkey
ALTER TABLE ONLY public.instance_heartbeats
    ADD CONSTRAINT instance_heartbeats_pkey PRIMARY KEY (instance_id);

-- CONSTRAINT: instance_sessions instance_sessions_pkey
ALTER TABLE ONLY public.instance_sessions
    ADD CONSTRAINT instance_sessions_pkey PRIMARY KEY (instance_id);

-- CONSTRAINT: locks locks_pkey
ALTER TABLE ONLY public.locks
    ADD CONSTRAINT locks_pkey PRIMARY KEY (lock_name);

-- CONSTRAINT: mailbox_acls mailbox_acls_pkey
ALTER TABLE ONLY public.mailbox_acls
    ADD CONSTRAINT mailbox_acls_pkey PRIMARY KEY (id);

-- CONSTRAINT: mailbox_acls mailbox_acls_unique_identifier
ALTER TABLE ONLY public.mailbox_acls
    ADD CONSTRAINT mailbox_acls_unique_identifier UNIQUE (mailbox_id, identifier);

-- CONSTRAINT: mailbox_stats mailbox_stats_pkey
ALTER TABLE ONLY public.mailbox_stats
    ADD CONSTRAINT mailbox_stats_pkey PRIMARY KEY (mailbox_id);

-- CONSTRAINT: mailboxes mailboxes_pkey
ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_pkey PRIMARY KEY (id);

-- CONSTRAINT: message_state message_state_pkey
ALTER TABLE ONLY public.message_state
    ADD CONSTRAINT message_state_pkey PRIMARY KEY (message_id);

-- CONSTRAINT: messages_fts_v2 messages_fts_v2_pkey
ALTER TABLE ONLY public.messages_fts_v2
    ADD CONSTRAINT messages_fts_v2_pkey PRIMARY KEY (content_hash, account_id);

-- CONSTRAINT: messages messages_pkey
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);

-- CONSTRAINT: metadata metadata_pkey
ALTER TABLE ONLY public.metadata
    ADD CONSTRAINT metadata_pkey PRIMARY KEY (id);

-- CONSTRAINT: metadata metadata_unique_entry
ALTER TABLE ONLY public.metadata
    ADD CONSTRAINT metadata_unique_entry UNIQUE (account_id, mailbox_id, entry_name);

-- CONSTRAINT: pending_uploads pending_uploads_content_hash_account_id_key
ALTER TABLE ONLY public.pending_uploads
    ADD CONSTRAINT pending_uploads_content_hash_account_id_key UNIQUE (content_hash, account_id);

-- CONSTRAINT: pending_uploads pending_uploads_pkey
ALTER TABLE ONLY public.pending_uploads
    ADD CONSTRAINT pending_uploads_pkey PRIMARY KEY (id);

-- CONSTRAINT: redirect_deliveries redirect_deliveries_pkey
ALTER TABLE ONLY public.redirect_deliveries
    ADD CONSTRAINT redirect_deliveries_pkey PRIMARY KEY (account_id, delivery_hash, redirect_to);

-- CONSTRAINT: s3_body_delete_intents s3_body_delete_intents_pkey
ALTER TABLE ONLY public.s3_body_delete_intents
    ADD CONSTRAINT s3_body_delete_intents_pkey PRIMARY KEY (content_hash);

-- CONSTRAINT: sieve_scripts sieve_scripts_account_id_name_key
ALTER TABLE ONLY public.sieve_scripts
    ADD CONSTRAINT sieve_scripts_account_id_name_key UNIQUE (account_id, name);

-- CONSTRAINT: sieve_scripts sieve_scripts_pkey
ALTER TABLE ONLY public.sieve_scripts
    ADD CONSTRAINT sieve_scripts_pkey PRIMARY KEY (id);

-- CONSTRAINT: subscriptions subscriptions_pkey
ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_pkey PRIMARY KEY (id);

-- CONSTRAINT: vacation_responses vacation_responses_identity_date_key
ALTER TABLE ONLY public.vacation_responses
    ADD CONSTRAINT vacation_responses_identity_date_key UNIQUE (account_id, sender_address, response_identity, response_date);

-- CONSTRAINT: vacation_responses vacation_responses_pkey
ALTER TABLE ONLY public.vacation_responses
    ADD CONSTRAINT vacation_responses_pkey PRIMARY KEY (id);

-- INDEX: idx_accounts_deleted_at
CREATE INDEX idx_accounts_deleted_at ON public.accounts USING btree (deleted_at);

-- INDEX: idx_accounts_purge_requested
CREATE INDEX idx_accounts_purge_requested ON public.accounts USING btree (purge_requested_at) WHERE (purge_requested_at IS NOT NULL);

-- INDEX: idx_cache_metrics_instance_latest
CREATE INDEX idx_cache_metrics_instance_latest ON public.cache_metrics USING btree (instance_id, recorded_at DESC);

-- INDEX: idx_cache_metrics_latest_per_instance_server
CREATE INDEX idx_cache_metrics_latest_per_instance_server ON public.cache_metrics USING btree (instance_id, server_hostname, recorded_at DESC);

-- INDEX: idx_cache_metrics_recorded_at
CREATE INDEX idx_cache_metrics_recorded_at ON public.cache_metrics USING btree (recorded_at);

-- INDEX: idx_credential_changes_observed
CREATE INDEX idx_credential_changes_observed ON public.credential_changes USING btree (first_observed_at);

-- INDEX: idx_credential_changes_writer_xid
CREATE INDEX idx_credential_changes_writer_xid ON public.credential_changes USING btree (writer_xid);

-- INDEX: idx_credentials_account_id
CREATE INDEX idx_credentials_account_id ON public.credentials USING btree (account_id);

-- INDEX: idx_credentials_account_id_one_primary
CREATE UNIQUE INDEX idx_credentials_account_id_one_primary ON public.credentials USING btree (account_id) WHERE (primary_identity IS TRUE);

-- INDEX: idx_credentials_account_primary
CREATE INDEX idx_credentials_account_primary ON public.credentials USING btree (account_id, primary_identity) WHERE (primary_identity = true);

-- INDEX: idx_credentials_domain
CREATE INDEX idx_credentials_domain ON public.credentials USING btree (domain);

-- INDEX: idx_credentials_lower_address
CREATE UNIQUE INDEX idx_credentials_lower_address ON public.credentials USING btree (lower(address));

-- INDEX: idx_health_status_server
CREATE INDEX idx_health_status_server ON public.health_status USING btree (server_hostname);

-- INDEX: idx_health_status_status
CREATE INDEX idx_health_status_status ON public.health_status USING btree (status);

-- INDEX: idx_health_status_updated_at
CREATE INDEX idx_health_status_updated_at ON public.health_status USING btree (updated_at);

-- INDEX: idx_mailbox_acls_account_id
CREATE INDEX idx_mailbox_acls_account_id ON public.mailbox_acls USING btree (account_id) WHERE (account_id IS NOT NULL);

-- INDEX: idx_mailbox_acls_anyone
CREATE INDEX idx_mailbox_acls_anyone ON public.mailbox_acls USING btree (identifier, mailbox_id) WHERE (identifier = 'anyone'::text);

-- INDEX: idx_mailbox_acls_anyone_rights
CREATE INDEX idx_mailbox_acls_anyone_rights ON public.mailbox_acls USING btree (mailbox_id, rights) WHERE (identifier = 'anyone'::text);

-- INDEX: idx_mailbox_acls_mailbox_account
CREATE INDEX idx_mailbox_acls_mailbox_account ON public.mailbox_acls USING btree (mailbox_id, account_id);

-- INDEX: idx_mailbox_acls_mailbox_account_rights
CREATE INDEX idx_mailbox_acls_mailbox_account_rights ON public.mailbox_acls USING btree (mailbox_id, account_id, rights);

-- INDEX: idx_mailbox_acls_mailbox_identifier
CREATE INDEX idx_mailbox_acls_mailbox_identifier ON public.mailbox_acls USING btree (mailbox_id, identifier);

-- INDEX: idx_mailboxes_account_id
CREATE INDEX idx_mailboxes_account_id ON public.mailboxes USING btree (account_id);

-- INDEX: idx_mailboxes_account_parent_path
CREATE INDEX idx_mailboxes_account_parent_path ON public.mailboxes USING btree (account_id, "left"(path, (length(path) - 16)));

-- INDEX: idx_mailboxes_account_path_length
CREATE INDEX idx_mailboxes_account_path_length ON public.mailboxes USING btree (account_id, length(path), path text_pattern_ops);

-- INDEX: idx_mailboxes_account_subscribed
CREATE INDEX idx_mailboxes_account_subscribed ON public.mailboxes USING btree (account_id, subscribed);

-- INDEX: idx_mailboxes_deleted_at
CREATE INDEX idx_mailboxes_deleted_at ON public.mailboxes USING btree (deleted_at) WHERE (deleted_at IS NOT NULL);

-- INDEX: idx_mailboxes_is_shared
CREATE INDEX idx_mailboxes_is_shared ON public.mailboxes USING btree (is_shared) WHERE (is_shared = true);

-- INDEX: idx_mailboxes_owner_domain
CREATE INDEX idx_mailboxes_owner_domain ON public.mailboxes USING btree (owner_domain) WHERE (owner_domain IS NOT NULL);

-- INDEX: idx_mailboxes_path_prefix
CREATE INDEX idx_mailboxes_path_prefix ON public.mailboxes USING btree (account_id, path text_pattern_ops);

-- INDEX: idx_mailboxes_shared_domain
CREATE INDEX idx_mailboxes_shared_domain ON public.mailboxes USING btree (is_shared, owner_domain) WHERE ((is_shared = true) AND (owner_domain IS NOT NULL));

-- INDEX: idx_mailboxes_shared_owner_domain
CREATE INDEX idx_mailboxes_shared_owner_domain ON public.mailboxes USING btree (is_shared, owner_domain) WHERE ((is_shared = true) AND (owner_domain IS NOT NULL));

-- INDEX: idx_message_state_custom_flags
CREATE INDEX idx_message_state_custom_flags ON public.message_state USING gin (custom_flags) WITH (fastupdate=off);

-- INDEX: idx_message_state_first_unseen
CREATE INDEX idx_message_state_first_unseen ON public.message_state USING btree (mailbox_id, message_id) WHERE ((flags & 1) = 0);

-- INDEX: idx_message_state_mailbox_id
CREATE INDEX idx_message_state_mailbox_id ON public.message_state USING btree (mailbox_id);

-- INDEX: idx_message_state_mailbox_id_updated_modseq
CREATE INDEX idx_message_state_mailbox_id_updated_modseq ON public.message_state USING btree (mailbox_id, updated_modseq) WHERE (updated_modseq IS NOT NULL);

-- INDEX: idx_messages_account_hash_active
CREATE INDEX idx_messages_account_hash_active ON public.messages USING btree (account_id, content_hash) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_account_hash_expunged
CREATE INDEX idx_messages_account_hash_expunged ON public.messages USING btree (account_id, content_hash, expunged_at) WHERE (expunged_at IS NOT NULL);

-- INDEX: idx_messages_cc_email_sort_trgm
CREATE INDEX idx_messages_cc_email_sort_trgm ON public.messages USING gin (cc_email_sort public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_cleanup_grouping
CREATE INDEX idx_messages_cleanup_grouping ON public.messages USING btree (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE ((uploaded = true) AND (expunged_at IS NOT NULL));

-- INDEX: idx_messages_content_hash_account_id
CREATE INDEX idx_messages_content_hash_account_id ON public.messages USING btree (content_hash, account_id);

-- INDEX: idx_messages_content_hash_active_sent_date
CREATE INDEX idx_messages_content_hash_active_sent_date ON public.messages USING btree (content_hash, sent_date) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_created_modseq
CREATE INDEX idx_messages_created_modseq ON public.messages USING btree (created_modseq);

-- INDEX: idx_messages_expunged_null_created_at
CREATE INDEX idx_messages_expunged_null_created_at ON public.messages USING btree (created_at) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_expunged_range
CREATE INDEX idx_messages_expunged_range ON public.messages USING btree (account_id, s3_domain, s3_localpart, content_hash, expunged_at) WHERE (expunged_at IS NOT NULL);

-- INDEX: idx_messages_from_email_sort_trgm
CREATE INDEX idx_messages_from_email_sort_trgm ON public.messages USING gin (from_email_sort public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_from_name_sort_trgm
CREATE INDEX idx_messages_from_name_sort_trgm ON public.messages USING gin (from_name_sort public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_fts_v2_account_id
CREATE INDEX idx_messages_fts_v2_account_id ON public.messages_fts_v2 USING btree (account_id);

-- INDEX: idx_messages_fts_v2_account_tsv
CREATE INDEX idx_messages_fts_v2_account_tsv ON public.messages_fts_v2 USING gin (account_id, text_body_tsv) WITH (fastupdate=off) WHERE (text_body_tsv IS NOT NULL);

-- INDEX: idx_messages_fts_v2_queue
CREATE INDEX idx_messages_fts_v2_queue ON public.messages_fts_v2 USING btree (created_at) WHERE (text_body_tsv IS NULL);

-- INDEX: idx_messages_fts_v2_sent_date
CREATE INDEX idx_messages_fts_v2_sent_date ON public.messages_fts_v2 USING btree (sent_date) WHERE (sent_date IS NOT NULL);

-- INDEX: idx_messages_in_reply_to
CREATE INDEX idx_messages_in_reply_to ON public.messages USING btree (lower(in_reply_to));

-- INDEX: idx_messages_mailbox_active
CREATE INDEX idx_messages_mailbox_active ON public.messages USING btree (mailbox_id) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_mailbox_dates_uid
CREATE INDEX idx_messages_mailbox_dates_uid ON public.messages USING btree (mailbox_id, internal_date, sent_date, uid) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_mailbox_delivery_hash
CREATE INDEX idx_messages_mailbox_delivery_hash ON public.messages USING btree (mailbox_id, delivery_hash) WHERE ((expunged_at IS NULL) AND (delivery_hash IS NOT NULL));

-- INDEX: idx_messages_mailbox_headers_v3
-- The covering index header search is answered from, without touching the heap. Its text
-- columns are bounded by the application so that a tuple stays under the btree limit.
CREATE INDEX idx_messages_mailbox_headers_v3 ON public.messages USING btree (mailbox_id) INCLUDE (id, uid, content_hash, created_modseq, expunged_modseq, internal_date, sent_date, size, subject, subject_sort, from_email_sort, from_name_sort, to_email_sort, to_name_sort, cc_email_sort, extra_addresses, header_presence) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_mailbox_id_created_modseq
CREATE INDEX idx_messages_mailbox_id_created_modseq ON public.messages USING btree (mailbox_id, created_modseq);

-- INDEX: idx_messages_mailbox_id_expunged_modseq
CREATE INDEX idx_messages_mailbox_id_expunged_modseq ON public.messages USING btree (mailbox_id, expunged_modseq);

-- INDEX: idx_messages_mailbox_id_uid
CREATE UNIQUE INDEX idx_messages_mailbox_id_uid ON public.messages USING btree (mailbox_id, uid);

-- INDEX: idx_messages_mailbox_message_id_raw
CREATE INDEX idx_messages_mailbox_message_id_raw ON public.messages USING btree (mailbox_id, id) WHERE ((message_id_raw IS NOT NULL) AND (expunged_at IS NULL));

-- INDEX: idx_messages_mailbox_sent_date_unknown
CREATE INDEX idx_messages_mailbox_sent_date_unknown ON public.messages USING btree (mailbox_id, id) WHERE (sent_date_unknown AND (expunged_at IS NULL));

-- INDEX: idx_messages_mailbox_size_uid
CREATE INDEX idx_messages_mailbox_size_uid ON public.messages USING btree (mailbox_id, size, uid) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_mailbox_uid_active
CREATE INDEX idx_messages_mailbox_uid_active ON public.messages USING btree (mailbox_id, uid) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_mailbox_uid_expunged_modseq
CREATE INDEX idx_messages_mailbox_uid_expunged_modseq ON public.messages USING btree (mailbox_id, uid, expunged_modseq);

-- INDEX: idx_messages_message_id
CREATE INDEX idx_messages_message_id ON public.messages USING btree (lower(message_id));

-- INDEX: idx_messages_message_id_mailbox_lookup
CREATE INDEX idx_messages_message_id_mailbox_lookup ON public.messages USING btree (mailbox_id, message_id) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_recipients_json
CREATE INDEX idx_messages_recipients_json ON public.messages USING gin (recipients_json jsonb_path_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_s3_key_parts
CREATE INDEX idx_messages_s3_key_parts ON public.messages USING btree (account_id, s3_domain, s3_localpart, content_hash);

-- INDEX: idx_messages_subject_trgm
CREATE INDEX idx_messages_subject_trgm ON public.messages USING gin (lower(subject) public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_to_email_sort_trgm
CREATE INDEX idx_messages_to_email_sort_trgm ON public.messages USING gin (to_email_sort public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_to_name_sort_trgm
CREATE INDEX idx_messages_to_name_sort_trgm ON public.messages USING gin (to_name_sort public.gin_trgm_ops) WITH (fastupdate=off) WHERE (expunged_at IS NULL);

-- INDEX: idx_messages_uploaded_created_at
CREATE INDEX idx_messages_uploaded_created_at ON public.messages USING btree (created_at) WHERE (uploaded = false);

-- INDEX: idx_metadata_account_mailbox
CREATE INDEX idx_metadata_account_mailbox ON public.metadata USING btree (account_id, mailbox_id);

-- INDEX: idx_metadata_entry_prefix
CREATE INDEX idx_metadata_entry_prefix ON public.metadata USING btree (account_id, mailbox_id, entry_name text_pattern_ops);

-- INDEX: idx_metadata_mailbox
CREATE INDEX idx_metadata_mailbox ON public.metadata USING btree (mailbox_id) WHERE (mailbox_id IS NOT NULL);

-- INDEX: idx_metadata_server
CREATE INDEX idx_metadata_server ON public.metadata USING btree (account_id) WHERE (mailbox_id IS NULL);

-- INDEX: idx_pending_uploads_attempts
CREATE INDEX idx_pending_uploads_attempts ON public.pending_uploads USING btree (attempts);

-- INDEX: idx_pending_uploads_instance_id_created_at
CREATE INDEX idx_pending_uploads_instance_id_created_at ON public.pending_uploads USING btree (instance_id, created_at);

-- INDEX: idx_sieve_scripts_account_id
CREATE INDEX idx_sieve_scripts_account_id ON public.sieve_scripts USING btree (account_id);

-- INDEX: idx_sieve_scripts_account_id_one_active
CREATE UNIQUE INDEX idx_sieve_scripts_account_id_one_active ON public.sieve_scripts USING btree (account_id) WHERE (active IS TRUE);

-- INDEX: idx_vacation_responses_response_date
CREATE INDEX idx_vacation_responses_response_date ON public.vacation_responses USING btree (response_date);

-- INDEX: mailboxes_account_id_lower_name_unique
-- Mailbox names are unique per account regardless of case, among LIVE mailboxes only: a
-- soft-deleted mailbox (deleted_at set) must not block creating its name again.
CREATE UNIQUE INDEX mailboxes_account_id_lower_name_unique ON public.mailboxes USING btree (account_id, lower(name)) WHERE (deleted_at IS NULL);

-- INDEX: mailboxes_account_special_use_unique
CREATE UNIQUE INDEX mailboxes_account_special_use_unique ON public.mailboxes USING btree (account_id, special_use) WHERE ((special_use IS NOT NULL) AND (deleted_at IS NULL));

-- INDEX: metadata_unique_server_entry
CREATE UNIQUE INDEX metadata_unique_server_entry ON public.metadata USING btree (account_id, entry_name) WHERE (mailbox_id IS NULL);

-- INDEX: redirect_deliveries_created_at_idx
CREATE INDEX redirect_deliveries_created_at_idx ON public.redirect_deliveries USING btree (created_at);

-- INDEX: redirect_log_account_date_idx
CREATE INDEX redirect_log_account_date_idx ON public.redirect_log USING btree (account_id, redirect_date);

-- INDEX: subscriptions_account_lname_unique
CREATE UNIQUE INDEX subscriptions_account_lname_unique ON public.subscriptions USING btree (account_id, lower(mailbox_name));

-- TRIGGER: accounts trigger_accounts_out_of_service
CREATE CONSTRAINT TRIGGER trigger_accounts_out_of_service AFTER UPDATE OF deleted_at ON public.accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (((old.deleted_at IS NULL) AND (new.deleted_at IS NOT NULL))) EXECUTE FUNCTION public.record_credential_change();

-- TRIGGER: accounts trigger_accounts_removed
CREATE CONSTRAINT TRIGGER trigger_accounts_removed AFTER DELETE ON public.accounts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.record_credential_change();

-- TRIGGER: credentials trigger_credentials_changed
CREATE CONSTRAINT TRIGGER trigger_credentials_changed AFTER UPDATE OF password, address, account_id ON public.credentials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (((old.password IS DISTINCT FROM new.password) OR (old.address IS DISTINCT FROM new.address) OR (old.account_id IS DISTINCT FROM new.account_id))) EXECUTE FUNCTION public.record_credential_change();

-- TRIGGER: credentials trigger_credentials_removed
CREATE CONSTRAINT TRIGGER trigger_credentials_removed AFTER DELETE ON public.credentials DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.record_credential_change();

-- TRIGGER: credentials trigger_maintain_credentials_domain
CREATE TRIGGER trigger_maintain_credentials_domain BEFORE INSERT OR UPDATE OF address ON public.credentials FOR EACH ROW EXECUTE FUNCTION public.maintain_credentials_domain();

-- TRIGGER: message_state trigger_message_state_initial_modseq
CREATE TRIGGER trigger_message_state_initial_modseq BEFORE INSERT OR UPDATE ON public.message_state FOR EACH ROW EXECUTE FUNCTION public.preserve_message_state_initial_modseq();

-- TRIGGER: message_state trigger_message_state_stats_delete_stmt
CREATE TRIGGER trigger_message_state_stats_delete_stmt AFTER DELETE ON public.message_state REFERENCING OLD TABLE AS old_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_state();

-- TRIGGER: message_state trigger_message_state_stats_insert_stmt
CREATE TRIGGER trigger_message_state_stats_insert_stmt AFTER INSERT ON public.message_state REFERENCING NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_state();

-- TRIGGER: message_state trigger_message_state_stats_update_stmt
CREATE TRIGGER trigger_message_state_stats_update_stmt AFTER UPDATE ON public.message_state REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_state();

-- TRIGGER: messages trigger_messages_base_stats_delete_stmt
CREATE TRIGGER trigger_messages_base_stats_delete_stmt AFTER DELETE ON public.messages REFERENCING OLD TABLE AS old_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_messages();

-- TRIGGER: messages trigger_messages_base_stats_insert_stmt
CREATE TRIGGER trigger_messages_base_stats_insert_stmt AFTER INSERT ON public.messages REFERENCING NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_messages();

-- TRIGGER: messages trigger_messages_base_stats_update_stmt
CREATE TRIGGER trigger_messages_base_stats_update_stmt AFTER UPDATE ON public.messages REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table FOR EACH STATEMENT EXECUTE FUNCTION public.maintain_mailbox_stats_messages();

-- FK CONSTRAINT: credentials credentials_account_id_fkey
ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id);

-- FK CONSTRAINT: mailbox_acls mailbox_acls_account_id_fkey
ALTER TABLE ONLY public.mailbox_acls
    ADD CONSTRAINT mailbox_acls_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- FK CONSTRAINT: mailbox_acls mailbox_acls_mailbox_id_fkey
ALTER TABLE ONLY public.mailbox_acls
    ADD CONSTRAINT mailbox_acls_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

-- FK CONSTRAINT: mailbox_stats mailbox_stats_mailbox_id_fkey
ALTER TABLE ONLY public.mailbox_stats
    ADD CONSTRAINT mailbox_stats_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

-- FK CONSTRAINT: mailboxes mailboxes_account_id_fkey
ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id);

-- FK CONSTRAINT: message_state message_state_mailbox_id_fkey
ALTER TABLE ONLY public.message_state
    ADD CONSTRAINT message_state_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

-- FK CONSTRAINT: message_state message_state_message_id_fkey
ALTER TABLE ONLY public.message_state
    ADD CONSTRAINT message_state_message_id_fkey FOREIGN KEY (message_id) REFERENCES public.messages(id) ON DELETE CASCADE;

-- FK CONSTRAINT: messages messages_account_id_fkey
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE RESTRICT;

-- FK CONSTRAINT: messages messages_mailbox_id_fkey
ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE SET NULL;

-- FK CONSTRAINT: metadata metadata_account_id_fkey
ALTER TABLE ONLY public.metadata
    ADD CONSTRAINT metadata_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- FK CONSTRAINT: metadata metadata_mailbox_id_fkey
ALTER TABLE ONLY public.metadata
    ADD CONSTRAINT metadata_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.mailboxes(id) ON DELETE CASCADE;

-- FK CONSTRAINT: pending_uploads pending_uploads_account_id_fkey
ALTER TABLE ONLY public.pending_uploads
    ADD CONSTRAINT pending_uploads_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- FK CONSTRAINT: sieve_scripts sieve_scripts_account_id_fkey
ALTER TABLE ONLY public.sieve_scripts
    ADD CONSTRAINT sieve_scripts_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- FK CONSTRAINT: subscriptions subscriptions_account_id_fkey
ALTER TABLE ONLY public.subscriptions
    ADD CONSTRAINT subscriptions_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- FK CONSTRAINT: vacation_responses vacation_responses_account_id_fkey
ALTER TABLE ONLY public.vacation_responses
    ADD CONSTRAINT vacation_responses_account_id_fkey FOREIGN KEY (account_id) REFERENCES public.accounts(id) ON DELETE CASCADE;

-- SQL-language functions come last: their bodies are checked against the tables above.

-- FUNCTION: message_sent_utc_offset(bigint)
CREATE FUNCTION public.message_sent_utc_offset(bigint) RETURNS integer
    LANGUAGE sql STABLE COST 1 PARALLEL SAFE
    AS $_$ SELECT sent_utc_offset FROM messages WHERE id = $1 $_$;

-- The one row of database_identity. Every other table starts empty.
INSERT INTO public.database_identity (singleton) VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;
