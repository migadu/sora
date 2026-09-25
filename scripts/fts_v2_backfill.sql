-- Backfill messages_fts_v2 from messages_fts. Runbook: docs/fts-v2-rollout.md.
--
-- WHY THIS IS A DATA MIGRATION AND NOT A CACHE REBUILD
--   text_body is nulled the moment its vector is computed (db/fts.go), so the tsvector in
--   messages_fts is the ONLY copy of that data. It cannot be recomputed without re-fetching
--   and re-parsing every message body from S3. Losing it loses body search for existing mail.
--   Run this before the new binary is deployed, and do not drop messages_fts until the soak.
--
-- HOW TO RUN
--   psql -h <primary> -p 5432 -d <db> -f scripts/fts_v2_backfill.sql
--   Connect DIRECTLY to the primary, never through a transaction pooler: the procedures below
--   COMMIT between batches, which a transaction pooler will not carry correctly.
--
--   Recency-first, so the mail users actually search becomes searchable first and an aborted
--   run still leaves the useful part done. Run EACH CALL AS ITS OWN STATEMENT -- one
--   `psql -c` per CALL, or one per line in an interactive session. Several CALLs in a single
--   `psql -c "...; ..."` run as one implicit transaction, and the procedures' COMMITs then
--   fail with "invalid transaction termination":
--     CALL fts_v2_backfill_recent(interval '24 months', 5000, 200);  -- newest first
--     CALL fts_v2_backfill_rest(5000, 200);                          -- everything older
--     CALL fts_v2_catchup(0);                                        -- pairs missed in flight
--   Later catch-up passes resume from the id the previous pass prints, not from 0.
--   Check progress with: SELECT * FROM fts_v2_verification();
--
--   Completion is recorded in fts_v2_backfill_state, and migration 000050 refuses to run on a
--   large installation unless `rest` completed. If you deliberately backfill only recent mail
--   (accepting that older mail is not body-searchable), record that decision explicitly:
--     INSERT INTO fts_v2_backfill_state (step) VALUES ('accept_partial');
--
--   Every procedure is resumable: re-running continues from where it stopped, and running one
--   twice is a no-op. Progress is RAISE NOTICE'd per batch.
--
-- PACING
--   batch_rows = hashes per transaction, sleep_ms = pause between transactions. Start at
--   (5000, 200) and watch pg_stat_replication.replay_lag on all three replicas. Searches are
--   served EXCLUSIVELY by replicas, so replica lag is directly user-visible: raise sleep_ms
--   the moment lag grows.

-- ---------------------------------------------------------------------------------------
-- Progress record. Migration 000050 reads it: on a large installation it refuses to run
-- unless 'rest' (everything) completed, or an operator recorded 'accept_partial'. 'recent'
-- also stores the lower bound it covered, so 'rest' can start below it instead of re-reading
-- every vector 'recent' already copied.
-- ---------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS fts_v2_backfill_state (
    step         text        PRIMARY KEY CHECK (step IN ('recent', 'rest', 'accept_partial')),
    lo           timestamptz,
    completed_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------------------
-- Core batch. Returns rows inserted and the cursor for the next page.
--
-- Pagination is KEYSET on (sent_date, content_hash) descending, not a plain watermark.
-- A watermark of `sent_date <= last_seen` re-selects the boundary row forever and never
-- terminates; a strict `<` on sent_date alone silently skips every row that ties on that
-- timestamp. The composite cursor is unique (content_hash is the PK), so it always advances
-- and never skips. It must also advance past hashes that insert NOTHING -- an orphan hash
-- with no messages row is a legitimate candidate that yields zero pairs, and "loop until a
-- batch inserts nothing" would spin on it forever.
--
-- Drives from messages_fts (small) and enumerates accounts with an INDEX-ONLY scan on the
-- existing idx_messages_content_hash_account_id (content_hash, account_id). The DISTINCT is
-- on account_id alone inside the LATERAL: never DISTINCT over the row, because
-- text_body_tsv is TOASTed and sorting it would dominate the whole job.
--
-- Keep it index-only: do NOT join mailboxes here. A row belongs to the mailbox OWNER (the
-- account every search scopes to), and messages.account_id is the owner for all mail
-- delivered since June 2026. Only older mail that someone else added to a shared mailbox
-- differs (0 rows on production). Joining mailboxes to catch those would turn this into a
-- heap fetch plus a mailbox lookup for every message row in the table. The catch-up below
-- keys on the owner, and its first pass (from id 0) adds any such owner-keyed rows.
--
-- No expunged_at filter, deliberately. The orphan sweep counts ANY messages row including
-- expunged ones (db/cleaner.go), and `sora-admin messages restore` un-expunges rows without
-- recreating FTS data. Filtering here would make restored mail permanently unsearchable.
-- ---------------------------------------------------------------------------------------
-- The previous version had no p_hi. CREATE OR REPLACE with a different argument list adds an
-- overload instead of replacing it, so drop it first.
DROP FUNCTION IF EXISTS fts_v2_backfill_batch(timestamptz, timestamptz, varchar, int);
CREATE OR REPLACE FUNCTION fts_v2_backfill_batch(
    p_lo timestamptz, p_cur_date timestamptz, p_cur_hash varchar(64), p_batch int,
    p_hi timestamptz DEFAULT NULL
) RETURNS TABLE (inserted bigint, hashes bigint, next_date timestamptz, next_hash varchar(64))
LANGUAGE plpgsql AS $$
DECLARE
    v_ins bigint;
    v_hashes bigint;
    v_date timestamptz;
    v_hash varchar(64);
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS fts_v2_batch (
        content_hash varchar(64), text_body text, text_body_tsv tsvector,
        sent_date timestamptz, created_at timestamptz
    ) ON COMMIT DROP;
    DELETE FROM fts_v2_batch;

    INSERT INTO fts_v2_batch
    SELECT f.content_hash, f.text_body, f.text_body_tsv, f.sent_date, f.created_at
    FROM messages_fts f
    WHERE f.sent_date IS NOT NULL
      AND f.sent_date > p_lo
      AND (p_hi IS NULL OR f.sent_date <= p_hi)
      AND (p_cur_date IS NULL OR (f.sent_date, f.content_hash) < (p_cur_date, p_cur_hash))
    ORDER BY f.sent_date DESC, f.content_hash DESC
    LIMIT p_batch;

    SELECT count(*) INTO v_hashes FROM fts_v2_batch;
    SELECT b.sent_date, b.content_hash INTO v_date, v_hash
    FROM fts_v2_batch b ORDER BY b.sent_date ASC, b.content_hash ASC LIMIT 1;

    INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
    SELECT b.content_hash, p.account_id, b.text_body, b.text_body_tsv, b.sent_date, b.created_at
    FROM fts_v2_batch b
    CROSS JOIN LATERAL (
        SELECT DISTINCT m.account_id FROM messages m WHERE m.content_hash = b.content_hash
    ) p
    ON CONFLICT (content_hash, account_id) DO NOTHING;
    GET DIAGNOSTICS v_ins = ROW_COUNT;

    RETURN QUERY SELECT v_ins, v_hashes, v_date, v_hash;
END $$;

-- Rows with a NULL sent_date, paginated by content_hash. The retention prune deliberately
-- never touches these (its index is partial on sent_date IS NOT NULL), so they must not be
-- skipped here either.
CREATE OR REPLACE FUNCTION fts_v2_backfill_batch_nulldate(
    p_cur_hash varchar(64), p_batch int
) RETURNS TABLE (inserted bigint, hashes bigint, next_hash varchar(64))
LANGUAGE plpgsql AS $$
DECLARE
    v_ins bigint; v_hashes bigint; v_hash varchar(64);
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS fts_v2_batch_nd (
        content_hash varchar(64), text_body text, text_body_tsv tsvector, created_at timestamptz
    ) ON COMMIT DROP;
    DELETE FROM fts_v2_batch_nd;

    INSERT INTO fts_v2_batch_nd
    SELECT f.content_hash, f.text_body, f.text_body_tsv, f.created_at
    FROM messages_fts f
    WHERE f.sent_date IS NULL AND (p_cur_hash IS NULL OR f.content_hash > p_cur_hash)
    ORDER BY f.content_hash ASC
    LIMIT p_batch;

    SELECT count(*), max(content_hash) INTO v_hashes, v_hash FROM fts_v2_batch_nd;

    INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
    SELECT b.content_hash, p.account_id, b.text_body, b.text_body_tsv, NULL, b.created_at
    FROM fts_v2_batch_nd b
    CROSS JOIN LATERAL (
        SELECT DISTINCT m.account_id FROM messages m WHERE m.content_hash = b.content_hash
    ) p
    ON CONFLICT (content_hash, account_id) DO NOTHING;
    GET DIAGNOSTICS v_ins = ROW_COUNT;

    RETURN QUERY SELECT v_ins, v_hashes, v_hash;
END $$;

-- ---------------------------------------------------------------------------------------
-- Newest-first over the last p_horizon of mail.
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE fts_v2_backfill_recent(
    p_horizon interval, p_batch int DEFAULT 5000, p_sleep_ms int DEFAULT 200
) LANGUAGE plpgsql AS $$
DECLARE
    v_lo timestamptz := now() - p_horizon;
    v_date timestamptz := NULL;
    v_hash varchar(64) := NULL;
    r record;
    v_total bigint := 0;
BEGIN
    LOOP
        SELECT * INTO r FROM fts_v2_backfill_batch(v_lo, v_date, v_hash, p_batch);
        EXIT WHEN r.hashes = 0;
        v_total := v_total + r.inserted;
        v_date := r.next_date; v_hash := r.next_hash;
        COMMIT;
        RAISE NOTICE 'recent: +% rows (% hashes), total %, cursor %', r.inserted, r.hashes, v_total, v_date;
        PERFORM pg_sleep(p_sleep_ms / 1000.0);
    END LOOP;
    -- Recorded only on completion. A wider horizon from a later run covers more, so keep the
    -- lowest bound.
    INSERT INTO fts_v2_backfill_state (step, lo) VALUES ('recent', v_lo)
    ON CONFLICT (step) DO UPDATE
        SET lo = LEAST(fts_v2_backfill_state.lo, EXCLUDED.lo), completed_at = now();
    COMMIT;
    RAISE NOTICE 'recent: done, % rows, covers sent_date > %', v_total, v_lo;
END $$;

-- ---------------------------------------------------------------------------------------
-- Everything else: all remaining dated rows, then the NULL-sent_date tail.
--
-- If fts_v2_backfill_recent completed, only rows at or below its bound are read: it already
-- copied everything above (sent_date > lo), and re-reading those TOASTed vectors would only
-- repeat its I/O to insert nothing.
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE fts_v2_backfill_rest(
    p_batch int DEFAULT 5000, p_sleep_ms int DEFAULT 200
) LANGUAGE plpgsql AS $$
DECLARE
    v_date timestamptz := NULL;
    v_hash varchar(64) := NULL;
    v_hi timestamptz;
    r record;
    v_total bigint := 0;
BEGIN
    SELECT lo INTO v_hi FROM fts_v2_backfill_state WHERE step = 'recent';
    IF v_hi IS NOT NULL THEN
        RAISE NOTICE 'rest: recent already covers sent_date > %, starting below it', v_hi;
    END IF;
    LOOP
        SELECT * INTO r FROM fts_v2_backfill_batch('-infinity', v_date, v_hash, p_batch, v_hi);
        EXIT WHEN r.hashes = 0;
        v_total := v_total + r.inserted;
        v_date := r.next_date; v_hash := r.next_hash;
        COMMIT;
        RAISE NOTICE 'rest: +% rows (% hashes), total %, cursor %', r.inserted, r.hashes, v_total, v_date;
        PERFORM pg_sleep(p_sleep_ms / 1000.0);
    END LOOP;

    v_hash := NULL;
    LOOP
        SELECT * INTO r FROM fts_v2_backfill_batch_nulldate(v_hash, p_batch);
        EXIT WHEN r.hashes = 0;
        v_total := v_total + r.inserted;
        v_hash := r.next_hash;
        COMMIT;
        RAISE NOTICE 'rest(null sent_date): +% rows (% hashes), total %', r.inserted, r.hashes, v_total;
        PERFORM pg_sleep(p_sleep_ms / 1000.0);
    END LOOP;
    INSERT INTO fts_v2_backfill_state (step) VALUES ('rest')
    ON CONFLICT (step) DO UPDATE SET completed_at = now();
    COMMIT;
    RAISE NOTICE 'rest: done, % rows', v_total;
END $$;

-- ---------------------------------------------------------------------------------------
-- Catch-up: pairs that exist in messages but not yet in messages_fts_v2.
--
-- Keyed on messages.id (monotonic PK), NOT created_at: the only created_at index is partial
-- on expunged_at IS NULL, and expunged rows must be included (see the note above).
--
-- Enumerate the missing PAIRS first (two small columns), then join the payload in — same
-- reason as the LATERAL above.
--
-- Unlike the backfill batches, this keys on the mailbox OWNER. It reads messages by id range
-- anyway, so the mailbox lookup costs little here, and its first pass from id 0 is what gives
-- pre-June shared-mailbox mail (stored under the adder's account) its owner-keyed row.
--
-- Run it after the backfill, after the index build, immediately before the deploy, and then
-- in a loop during the rolling deploy until it reports 0 twice in a row (old binaries write
-- only messages_fts, so they keep producing work until the last node has rolled).
--
-- Each pass ends by printing the id the next pass should start from: the highest id it saw,
-- minus p_resume_margin, because ids are allocated at INSERT but become visible at COMMIT,
-- so a slow transaction can commit a row below max(id) after this pass read it. Starting
-- every pass from 0 instead rescans the whole table each time. It sleeps only after a step
-- that inserted something, so an empty range is not paced like a busy one.
-- ---------------------------------------------------------------------------------------
-- An earlier version of this script defined a 3-argument catch-up. CREATE OR REPLACE with a
-- different argument list adds an overload instead of replacing it, which makes a 3-argument
-- CALL ambiguous, so drop it first.
DROP PROCEDURE IF EXISTS fts_v2_catchup(bigint, int, int);
CREATE OR REPLACE PROCEDURE fts_v2_catchup(
    p_from_id bigint DEFAULT 0, p_batch int DEFAULT 20000, p_sleep_ms int DEFAULT 200,
    p_resume_margin bigint DEFAULT 100000
) LANGUAGE plpgsql AS $$
DECLARE
    v_id bigint := p_from_id;
    v_max bigint;
    v_ins bigint;
    v_total bigint := 0;
BEGIN
    -- COALESCE so an empty messages table reports "up to id 0" rather than NULL.
    SELECT COALESCE(max(id), 0) INTO v_max FROM messages;
    WHILE v_id < v_max LOOP
        WITH want AS (
            SELECT DISTINCT m.content_hash, COALESCE(mb.account_id, m.account_id) AS account_id
            FROM messages m LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
            WHERE m.id > v_id AND m.id <= v_id + p_batch
        ), missing AS (
            SELECT w.content_hash, w.account_id FROM want w
            WHERE NOT EXISTS (SELECT 1 FROM messages_fts_v2 v
                              WHERE v.content_hash = w.content_hash AND v.account_id = w.account_id)
        )
        INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
        SELECT x.content_hash, x.account_id, f.text_body, f.text_body_tsv, f.sent_date, f.created_at
        FROM missing x
        JOIN messages_fts f ON f.content_hash = x.content_hash
        ON CONFLICT (content_hash, account_id) DO NOTHING;
        GET DIAGNOSTICS v_ins = ROW_COUNT;

        v_total := v_total + v_ins;
        v_id := v_id + p_batch;
        COMMIT;
        IF v_ins > 0 THEN
            RAISE NOTICE 'catchup: +% rows up to id %, total %', v_ins, v_id, v_total;
            PERFORM pg_sleep(p_sleep_ms / 1000.0);
        END IF;
    END LOOP;
    RAISE NOTICE 'catchup: done, % rows up to id %. Next pass: CALL fts_v2_catchup(%);',
        v_total, v_max, GREATEST(v_max - p_resume_margin, 0);
END $$;

-- ---------------------------------------------------------------------------------------
-- Verification: SELECT * FROM fts_v2_verification();
--
-- Cheap by design, because it is run on the production primary right before a deploy. Table
-- sizes are planner estimates (run ANALYZE first), and missing pairs are counted only over
-- the newest p_recent_ids messages, where a gap would come from. A full count would be one
-- long query over every message, holding a snapshot that stalls vacuum on the primary and,
-- with hot_standby_feedback, on the replicas too. The full-coverage check is the catch-up
-- itself reporting 0 rows twice in a row.
-- ---------------------------------------------------------------------------------------
DROP VIEW IF EXISTS fts_v2_verification;
CREATE OR REPLACE FUNCTION fts_v2_verification(p_recent_ids bigint DEFAULT 1000000)
RETURNS TABLE (
    v1_rows_est bigint, v2_rows_est bigint, v2_queued bigint, v2_queue_backlog bigint,
    recent_missing_pairs bigint, checked_from_id bigint,
    recent_done_lo timestamptz, rest_done boolean, accept_partial boolean,
    v1_total text, v2_total text
) LANGUAGE plpgsql STABLE AS $$
-- plpgsql, not sql: a LANGUAGE sql body is validated when the function is created, so the
-- script would fail to load before messages_fts_v2 exists.
BEGIN
    RETURN QUERY
    WITH bounds AS (SELECT GREATEST(COALESCE(max(id), 0) - p_recent_ids, 0) AS from_id FROM messages)
    SELECT
        (SELECT reltuples::bigint FROM pg_class WHERE oid = 'messages_fts'::regclass),
        (SELECT reltuples::bigint FROM pg_class WHERE oid = 'messages_fts_v2'::regclass),
        (SELECT count(*) FROM messages_fts_v2 WHERE text_body_tsv IS NULL),
        (SELECT count(*) FROM messages_fts_v2
          WHERE text_body_tsv IS NULL AND created_at < now() - interval '10 min'),
        (SELECT count(*) FROM (
            SELECT DISTINCT m.content_hash, COALESCE(mb.account_id, m.account_id) AS account_id
            FROM messages m
            JOIN messages_fts f ON f.content_hash = m.content_hash
            LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
            WHERE m.id > (SELECT from_id FROM bounds)
         ) want
         WHERE NOT EXISTS (SELECT 1 FROM messages_fts_v2 v
                           WHERE v.content_hash = want.content_hash AND v.account_id = want.account_id)),
        (SELECT from_id FROM bounds),
        (SELECT lo FROM fts_v2_backfill_state WHERE step = 'recent'),
        EXISTS (SELECT 1 FROM fts_v2_backfill_state WHERE step = 'rest'),
        EXISTS (SELECT 1 FROM fts_v2_backfill_state WHERE step = 'accept_partial'),
        pg_size_pretty(pg_total_relation_size('messages_fts')),
        pg_size_pretty(pg_total_relation_size('messages_fts_v2'));
END $$;
