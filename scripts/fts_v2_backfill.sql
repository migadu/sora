-- Backfill messages_fts_v2 from messages_fts. See tasks/fts-per-account-composite-gin.md.
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
--   run still leaves the useful part done:
--     CALL fts_v2_backfill_recent(interval '24 months', 5000, 200);  -- newest first
--     CALL fts_v2_backfill_rest(5000, 200);                          -- everything older
--     CALL fts_v2_catchup(0);                                        -- pairs missed in flight
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
-- Drives from messages_fts (small) and enumerates owners with an index-only scan on the
-- existing idx_messages_content_hash_account_id (content_hash, account_id). The DISTINCT is
-- on account_id alone inside the LATERAL: never DISTINCT over the row, because text_body_tsv
-- is TOASTed and sorting it would dominate the whole job.
--
-- No expunged_at filter, deliberately. The orphan sweep counts ANY messages row including
-- expunged ones (db/cleaner.go), and `sora-admin messages restore` un-expunges rows without
-- recreating FTS data. Filtering here would make restored mail permanently unsearchable.
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fts_v2_backfill_batch(
    p_lo timestamptz, p_cur_date timestamptz, p_cur_hash varchar(64), p_batch int
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
    RAISE NOTICE 'recent: done, % rows', v_total;
END $$;

-- ---------------------------------------------------------------------------------------
-- Everything else: all remaining dated rows, then the NULL-sent_date tail.
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE fts_v2_backfill_rest(
    p_batch int DEFAULT 5000, p_sleep_ms int DEFAULT 200
) LANGUAGE plpgsql AS $$
DECLARE
    v_date timestamptz := NULL;
    v_hash varchar(64) := NULL;
    r record;
    v_total bigint := 0;
BEGIN
    LOOP
        SELECT * INTO r FROM fts_v2_backfill_batch('-infinity', v_date, v_hash, p_batch);
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
-- Run it after the backfill, after the index build, immediately before the deploy, and then
-- in a loop during the rolling deploy until it reports 0 twice in a row (old binaries write
-- only messages_fts, so they keep producing work until the last node has rolled).
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE fts_v2_catchup(
    p_from_id bigint DEFAULT 0, p_batch int DEFAULT 20000, p_sleep_ms int DEFAULT 200
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
        WITH missing AS (
            SELECT DISTINCT m.content_hash, m.account_id
            FROM messages m
            WHERE m.id > v_id AND m.id <= v_id + p_batch
              AND NOT EXISTS (SELECT 1 FROM messages_fts_v2 v
                              WHERE v.content_hash = m.content_hash AND v.account_id = m.account_id)
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
        END IF;
        PERFORM pg_sleep(p_sleep_ms / 1000.0);
    END LOOP;
    RAISE NOTICE 'catchup: done, % rows up to id %', v_total, v_max;
END $$;

-- ---------------------------------------------------------------------------------------
-- Verification. Run before deploying.
-- ---------------------------------------------------------------------------------------
CREATE OR REPLACE VIEW fts_v2_verification AS
SELECT
    (SELECT count(*) FROM messages_fts)                                        AS v1_rows,
    (SELECT count(*) FROM messages_fts_v2)                                     AS v2_rows,
    (SELECT count(*) FROM messages_fts_v2 WHERE text_body_tsv IS NULL)         AS v2_queued,
    (SELECT count(*) FROM messages_fts_v2
      WHERE text_body_tsv IS NULL AND created_at < now() - interval '10 min')  AS v2_queue_backlog,
    (SELECT count(*) FROM (
        SELECT DISTINCT m.content_hash, m.account_id
        FROM messages m JOIN messages_fts f ON f.content_hash = m.content_hash
     ) want
     WHERE NOT EXISTS (SELECT 1 FROM messages_fts_v2 v
                       WHERE v.content_hash = want.content_hash AND v.account_id = want.account_id))
                                                                               AS missing_pairs,
    pg_size_pretty(pg_total_relation_size('messages_fts'))                     AS v1_total,
    pg_size_pretty(pg_total_relation_size('messages_fts_v2'))                  AS v2_total;
