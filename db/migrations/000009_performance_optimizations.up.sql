-- Migration 009: Performance optimizations for top 5 queries
-- Targets queries identified in database-performance-analysis.md
--
-- ZERO-DOWNTIME DEPLOYMENT: the pre-migration script this migration was written with is
-- not in this repository. The file runs as one transaction, so its index builds hold
-- write locks on messages and mailboxes, and the ADD COLUMN's ACCESS EXCLUSIVE lock on
-- mailbox_stats, until the last build ends. On a large database build the three indexes
-- below by hand first, outside a transaction, with CREATE INDEX CONCURRENTLY IF NOT EXISTS
-- and exactly the names and definitions used below; this migration then skips them.

-- ============================================================================
-- 1. CUSTOM FLAGS CACHE (Query #5: 8.80% of load, 27.4M calls)
-- ============================================================================
-- Cache distinct custom flags per mailbox in mailbox_stats to avoid
-- expensive JSONB LATERAL expansion on every SELECT/EXAMINE.
-- The GetUniqueCustomFlagsForMailbox query currently scans all messages
-- and expands their custom_flags JSONB arrays.
--
-- NOTE: Adding a column with a DEFAULT NULL is instant in PG11+
-- (no table rewrite, just a catalog update). This is safe on large tables.
-- NULL means "not yet populated" — the Go code falls back to the full scan.
-- '[]' means "populated, no custom flags".

ALTER TABLE mailbox_stats ADD COLUMN IF NOT EXISTS custom_flags_cache JSONB DEFAULT NULL;

-- NOTE: nothing here fills the cache of existing mailboxes. Their rows stay NULL, the Go
-- code falls back to the full scan for them, and the trigger below rebuilds a mailbox's
-- cache on its next custom-flag change. Migration 000024 later fills every cache still
-- NULL from message_state. Before #613 it set them to '[]' instead, so on a database
-- that ran that 000024, keywords set before this migration, in a mailbox whose cache was
-- never rebuilt, are missing from the cache and from that mailbox's FLAGS.

-- Trigger function to maintain custom_flags_cache when message flags change
CREATE OR REPLACE FUNCTION maintain_custom_flags_cache()
RETURNS TRIGGER AS $$
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
$$ LANGUAGE plpgsql;

-- NOTE: Trigger names start with 'trigger_zzz_' to ensure they fire AFTER
-- the mailbox_stats triggers (trigger_messages_stats_*), which are named
-- alphabetically earlier. PostgreSQL fires same-timing same-event triggers
-- in alphabetical order. The custom_flags_cache trigger needs the mailbox_stats
-- row to already exist (created by the stats INSERT trigger).
CREATE TRIGGER trigger_zzz_custom_flags_cache
    AFTER INSERT OR DELETE ON messages
    FOR EACH ROW
    EXECUTE FUNCTION maintain_custom_flags_cache();

CREATE TRIGGER trigger_zzz_custom_flags_cache_update
    AFTER UPDATE ON messages
    FOR EACH ROW
    WHEN (OLD.custom_flags IS DISTINCT FROM NEW.custom_flags
          OR (OLD.expunged_at IS NULL) IS DISTINCT FROM (NEW.expunged_at IS NULL))
    EXECUTE FUNCTION maintain_custom_flags_cache();

-- ============================================================================
-- 2. COMPOSITE INDEX FOR FIRST UNSEEN SEQUENCE (Query #2: 10.66% of load)
-- ============================================================================
-- The first-unseen-seqnum query joins messages with message_sequences
-- filtering on (mailbox_id, flags & FlagSeen = 0). A composite index
-- on messages for the flag bitwise check helps PostgreSQL filter early.
-- Also add a covering index on message_sequences for the seqnum lookup.

-- Index for flag-based filtering: supports (m.flags & $2) = $3 pattern
-- No partial index predicate because the query relies on the JOIN with
-- message_sequences (which only contains active messages) rather than
-- an explicit WHERE expunged_at IS NULL filter.
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_flags_uid
    ON messages (mailbox_id, flags, uid);

-- ============================================================================
-- 3. OPTIMIZE SEQUENCE NUMBER REBUILD (Query #3: 10.14% of load, 138ms avg)
-- ============================================================================
-- The current trigger does a full DELETE + INSERT rebuild of all sequence
-- numbers for the entire mailbox. For single-message INSERT operations
-- (which are the most common - LMTP delivery, APPEND), we can do an
-- incremental update instead: just INSERT the new row with the next seqnum.
-- For expunge and move operations, we still need the full rebuild.

-- NOTE: We only replace the function body, NOT the triggers.
-- The existing triggers (from migration 002) reference the function by name,
-- so CREATE OR REPLACE FUNCTION atomically updates what the triggers execute.
-- This avoids DROP TRIGGER + CREATE TRIGGER which would require ACCESS EXCLUSIVE
-- locks and create a window where triggers don't exist.

CREATE OR REPLACE FUNCTION maintain_message_sequences()
RETURNS TRIGGER AS
$$
DECLARE
    v_mailbox_id BIGINT;
    affected_mailboxes_query TEXT;
    should_run BOOLEAN;
    v_insert_count INT;
    v_has_expunged BOOLEAN;
    v_new_uid BIGINT;
    v_max_existing_uid BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- OPTIMIZATION: For single-message inserts of non-expunged messages,
        -- do an incremental update instead of a full rebuild.
        -- This covers the most common case: LMTP delivery and APPEND.
        SELECT COUNT(*), bool_or(expunged_at IS NOT NULL)
        INTO v_insert_count, v_has_expunged
        FROM new_table;

        IF v_insert_count = 1 AND NOT COALESCE(v_has_expunged, FALSE) THEN
            -- Get the new message's mailbox and UID
            SELECT mailbox_id, uid INTO v_mailbox_id, v_new_uid
            FROM new_table WHERE mailbox_id IS NOT NULL;

            IF v_mailbox_id IS NOT NULL THEN
                PERFORM pg_advisory_xact_lock(v_mailbox_id);

                -- Check if new UID is higher than all existing UIDs (common case: APPEND/LMTP)
                -- For imports with --preserve-uids or restoration, UIDs may not be monotonic,
                -- so we must fall through to a full rebuild in those cases.
                SELECT MAX(uid) INTO v_max_existing_uid
                FROM message_sequences WHERE mailbox_id = v_mailbox_id;

                IF v_new_uid > COALESCE(v_max_existing_uid, 0) THEN
                    -- Fast path: new message has the highest UID, just append with next seqnum
                    INSERT INTO message_sequences (mailbox_id, uid, seqnum)
                    VALUES (v_mailbox_id, v_new_uid,
                            COALESCE((SELECT MAX(seqnum) FROM message_sequences WHERE mailbox_id = v_mailbox_id), 0) + 1)
                    ON CONFLICT (mailbox_id, uid) DO NOTHING;

                    RETURN NULL;
                END IF;
                -- Non-monotonic UID: fall through to full rebuild
            END IF;
        END IF;

        -- Multi-message insert or has expunged: fall through to full rebuild
        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL';

    ELSIF TG_OP = 'DELETE' THEN
        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';

    ELSE -- TG_OP = 'UPDATE'
        -- For UPDATE, only run the rebuild if sequencing-related columns changed.
        EXECUTE '
            SELECT EXISTS (
                SELECT 1
                FROM old_table o
                JOIN new_table n ON o.id = n.id
                WHERE o.mailbox_id IS DISTINCT FROM n.mailbox_id
                   OR (o.expunged_at IS NULL) IS DISTINCT FROM (n.expunged_at IS NULL)
            )
        ' INTO should_run;

        IF NOT should_run THEN
            RETURN NULL;
        END IF;

        affected_mailboxes_query := '
            SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL
            UNION
            SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
    END IF;

    -- Full rebuild for all affected mailboxes
    FOR v_mailbox_id IN EXECUTE affected_mailboxes_query LOOP
        PERFORM pg_advisory_xact_lock(v_mailbox_id);

        DELETE FROM message_sequences WHERE mailbox_id = v_mailbox_id;
        INSERT INTO message_sequences (mailbox_id, uid, seqnum)
        SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (ORDER BY m.uid)
        FROM messages m
        WHERE m.mailbox_id = v_mailbox_id AND m.expunged_at IS NULL;
    END LOOP;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. OPTIMIZE MAILBOX LIST QUERY (Query #4: 9.35% of load)
-- ============================================================================
-- The has_children EXISTS subquery uses path LIKE and LENGTH comparison.
-- Add a composite index that covers this specific pattern.

-- Index for has_children check: covers the EXISTS(SELECT 1 FROM mailboxes WHERE account_id = X AND LENGTH(path) = Y AND path LIKE Z)
CREATE INDEX IF NOT EXISTS idx_mailboxes_account_path_length
    ON mailboxes (account_id, LENGTH(path), path text_pattern_ops);

-- ============================================================================
-- 5. OPTIMIZE POLL QUERY EXPUNGED SEQUENCE NUMBERS (Query #1: 26.76% of load)
-- ============================================================================
-- The correlated subquery for expunged messages calculates pre-expunge
-- sequence numbers by counting messages. Add a composite index to speed
-- up this COUNT(*) subquery.

-- Index for the expunged sequence number calculation:
-- WHERE mailbox_id = X AND uid <= Y AND (expunged_modseq IS NULL OR expunged_modseq > Z)
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_uid_expunged_modseq
    ON messages (mailbox_id, uid, expunged_modseq);
