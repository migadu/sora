-- Per-account FTS rows + composite GIN: scope body search to the mailbox owner.
--
-- PROBLEM
--   messages_fts is keyed by content_hash alone and deduplicated across ALL accounts, so
--   the mailbox predicate (on `messages`) and the tsvector (on `messages_fts`) live in
--   different tables. No index can combine predicates across two tables, so the planner has
--   only two plans for a BODY/TEXT search:
--     1. drive from messages(mailbox_id): one PK probe + TOAST detoast + @@ per message in
--        the mailbox -- cost proportional to mailbox size, whatever the term;
--     2. drive from the GIN: heap-fetch every row in the WHOLE corpus containing the term,
--        then join down to the mailbox -- cost proportional to global term frequency.
--   The dictionary is 'simple' with no stop words, so a common word pulls a large slice of
--   the corpus. Both plans blow through the 30s SEARCH timeout on large mailboxes.
--
-- FIX
--   One FTS row per (content_hash, account_id) and one multicolumn GIN over
--   (account_id, text_body_tsv), using btree_gin. PostgreSQL then intersects the account's
--   posting list with each lexeme's posting list inside the index, so the work is
--   proportional to that ACCOUNT's hits for the term. This is the case btree_gin documents:
--   "for queries that test both a GIN-indexable column and a B-tree-indexable column, it
--   might be more efficient to create a multicolumn GIN index that uses one of these
--   operator classes than to create two separate indexes that would have to be combined via
--   bitmap ANDing."
--
--   Per-mailbox or per-domain PARTIAL indexes cannot do this: there is no column to
--   predicate on, one CREATE INDEX per tenant is unbounded, the planner examines every index
--   of a table at plan time, and a prepared statement would need a custom plan per literal.
--
-- GRANULARITY is the ACCOUNT, not the mailbox: a hash lives in several mailboxes of one
--   account (COPY, multi-alias delivery), and MOVE must stay an FTS no-op. Intra-account
--   dedup is kept; only cross-account dedup is given up. account_id is the mailbox OWNER
--   (shared mailboxes included), the account every search scopes to. messages.account_id
--   holds the same for mail delivered since June 2026, but not for older mail that someone
--   else added to a shared mailbox, so the population below keys on the mailbox.
--
-- PK ORDER is (content_hash, account_id): the hot paths -- the worker's fan-out across
--   sibling rows, the delivery-time sibling probe, and the orphan sweep's content_hash > $1
--   windowing -- are all hash-first.
--
-- The GIN is PARTIAL on text_body_tsv IS NOT NULL. Queued rows (NULL vector) would otherwise
--   be indexed as placeholder nulls and then re-indexed when the worker fills the vector.
--   Every FTS predicate the query builders emit already carries `text_body_tsv IS NOT NULL`
--   (db/search.go), so the partial predicate is matchable.
--
-- ON A LIVE PRODUCTION DATABASE, DO ALL OF THIS OUT-OF-BAND FIRST so this migration no-ops
-- (every statement below is IF NOT EXISTS). Full runbook in docs/fts-v2-rollout.md.
-- Short form, all on the primary, direct (not via a transaction pooler):
--
--   1. CREATE EXTENSION IF NOT EXISTS btree_gin;
--   2. the CREATE TABLE below, plus ONLY the _queue and _sent_date indexes.
--      Do NOT create the composite GIN yet: the GIN documentation is explicit that for bulk
--      insertion it is better to load first and build the index afterwards.
--   3. run scripts/fts_v2_backfill.sql (batched, paced, resumable, recency-first), then its
--      catch-up procedure until it reports 0 rows twice.
--   4. SET maintenance_work_mem = '2GB';  -- GIN build time is very sensitive to this
--      then the two remaining CREATE INDEX statements below, WITHOUT CONCURRENTLY.
--      Nothing reads or writes this table until the new binary is deployed, so a plain build
--      takes a ShareLock that costs users nothing -- and it is one table scan instead of
--      CONCURRENTLY's two plus its two wait phases. (GIN has no parallel build: the
--      documentation states only B-tree supports it, so this is single-threaded either way.)
--      Do not run a large import or `sora-admin messages restore` during the build: those are
--      the only long xid-holding transactions in the system.
--   5. ANALYZE messages_fts_v2;  -- not optional: without stats the planner has no @@
--      selectivity and can pick the very plan this migration exists to escape.
--   6. verify all replicas have caught up and carry the table and index, then deploy.
--
-- A CONCURRENTLY build must NOT be put in a migration file here: migrations run under the
-- leader advisory lock while every other instance polls with a 3 x migration_timeout
-- deadline (6 minutes by default), so a multi-hour build inside a migration fails every
-- other node's startup.
--
-- messages_fts is NOT dropped here. text_body is nulled the moment its vector is computed
-- (db/fts.go), so the tsvector is the ONLY copy of that data -- it cannot be recomputed
-- without re-fetching and re-parsing every body from S3. The old table stays, dual-written
-- by the new binary, until a later migration retires it after a soak.

CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE IF NOT EXISTS messages_fts_v2 (
    content_hash  VARCHAR(64)  NOT NULL,
    account_id    BIGINT       NOT NULL,
    text_body     TEXT,
    text_body_tsv tsvector,
    sent_date     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (content_hash, account_id)
);

-- Population. The new binary answers every body search from this table alone, so applying
-- this migration to a database whose messages_fts holds vectors while this table is empty or
-- only partly filled would make body search miss existing mail -- silently.
--
--   - messages_fts holds at most 25,000 rows (dev, tests, small installs): populate here. The
--     insert is idempotent, so it also fills the gaps of a partial copy. It runs before the
--     GIN below exists, so it does not pay per-row GIN maintenance. 25,000 keeps it to
--     seconds: 250,000 took 90 s on a laptop, against the 2-minute migration_timeout.
--   - Larger: the out-of-band backfill must have completed. scripts/fts_v2_backfill.sql records
--     that in fts_v2_backfill_state ('rest'), or an operator recorded 'accept_partial' after
--     deliberately backfilling only recent mail. Anything else is refused: a table that is
--     merely non-empty may hold one interrupted pass.
--
-- The pair logic mirrors the backfill's catch-up: one row per (hash, mailbox owner), no
-- expunged_at filter (restore relies on the row), falling back to messages.account_id for a
-- message whose mailbox is gone. Queued v1 rows copy their text for the worker to tokenise.
DO $$
DECLARE
    v1_rows bigint;
    backfilled boolean := false;
BEGIN
    SELECT count(*) INTO v1_rows FROM (SELECT 1 FROM messages_fts LIMIT 25001) s;

    IF v1_rows <= 25000 THEN
        INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
        SELECT f.content_hash, p.account_id, f.text_body, f.text_body_tsv, f.sent_date, f.created_at
        FROM messages_fts f
        CROSS JOIN LATERAL (
            SELECT DISTINCT COALESCE(mb.account_id, m.account_id) AS account_id
            FROM messages m LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
            WHERE m.content_hash = f.content_hash
        ) p
        ON CONFLICT (content_hash, account_id) DO NOTHING;
        RETURN;
    END IF;

    IF to_regclass('fts_v2_backfill_state') IS NOT NULL THEN
        SELECT EXISTS (SELECT 1 FROM fts_v2_backfill_state WHERE step IN ('rest', 'accept_partial'))
          INTO backfilled;
    END IF;
    IF NOT backfilled THEN
        RAISE EXCEPTION 'messages_fts has more than 25000 rows and the out-of-band backfill has not completed (no ''rest'' or ''accept_partial'' in fts_v2_backfill_state). Run it first (docs/fts-v2-rollout.md): applying this migration now would leave body search missing existing mail.';
    END IF;
END $$;

-- Indexes. On production they already exist (built out-of-band, see the runbook), and a
-- plain CREATE INDEX IF NOT EXISTS still takes a ShareLock on the table before noticing, and
-- ALTER INDEX ... SET takes an AccessExclusiveLock on the index, so either would queue
-- behind a running catch-up. Each statement therefore runs only when there is work to do.
DO $$
BEGIN
    -- The search index. See the PARTIAL note above.
    IF to_regclass('idx_messages_fts_v2_account_tsv') IS NULL THEN
        CREATE INDEX idx_messages_fts_v2_account_tsv ON messages_fts_v2
            USING gin (account_id, text_body_tsv) WHERE text_body_tsv IS NOT NULL;
    END IF;

    -- fastupdate off, matching migrations 000020 / 000033 / 000034: the pending list turns a
    -- predictable per-insert cost into an unpredictable flush on whichever transaction
    -- happens to cross gin_pending_list_limit.
    IF NOT EXISTS (SELECT 1 FROM pg_class
                   WHERE oid = 'idx_messages_fts_v2_account_tsv'::regclass
                     AND 'fastupdate=off' = ANY (COALESCE(reloptions, '{}'))) THEN
        ALTER INDEX idx_messages_fts_v2_account_tsv SET (fastupdate = off);
    END IF;

    -- Batched per-account purge (account delete, purge-domain). Without it those deletes have
    -- no access path but a full scan, since the PK leads with content_hash.
    IF to_regclass('idx_messages_fts_v2_account_id') IS NULL THEN
        CREATE INDEX idx_messages_fts_v2_account_id ON messages_fts_v2 (account_id);
    END IF;

    -- The FTS worker's queue.
    IF to_regclass('idx_messages_fts_v2_queue') IS NULL THEN
        CREATE INDEX idx_messages_fts_v2_queue ON messages_fts_v2 (created_at)
            WHERE text_body_tsv IS NULL;
    END IF;

    -- Retention pruning range scan, mirroring idx_messages_fts_sent_date: rows with a NULL
    -- sent_date are deliberately never selected for pruning.
    IF to_regclass('idx_messages_fts_v2_sent_date') IS NULL THEN
        CREATE INDEX idx_messages_fts_v2_sent_date ON messages_fts_v2 (sent_date)
            WHERE sent_date IS NOT NULL;
    END IF;
END $$;

-- Shape guard. Everything above is IF NOT EXISTS, which silently accepts a pre-existing
-- table created out-of-band with a DIFFERENT shape -- a divergent PK column order or a
-- non-partial GIN would both be silently wrong (the first makes the fan-out and sweep do
-- full scans, the second makes searches unable to use the index). Fail loudly instead.
-- Precedent: migration 000041's collision guard.
DO $$
DECLARE
    pk_cols text;
    gin_def text;
BEGIN
    SELECT string_agg(a.attname, ',' ORDER BY k.ord)
      INTO pk_cols
      FROM pg_constraint c
      JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord) ON true
      JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
     WHERE c.conrelid = 'messages_fts_v2'::regclass AND c.contype = 'p';

    IF pk_cols IS DISTINCT FROM 'content_hash,account_id' THEN
        RAISE EXCEPTION
            'messages_fts_v2 primary key is (%), expected (content_hash,account_id). The table was created out-of-band with a different shape; drop it and re-create it with the DDL in this migration.',
            pk_cols;
    END IF;

    SELECT indexdef INTO gin_def
      FROM pg_indexes
     WHERE tablename = 'messages_fts_v2' AND indexname = 'idx_messages_fts_v2_account_tsv';

    IF gin_def IS NULL THEN
        RAISE EXCEPTION 'idx_messages_fts_v2_account_tsv is missing.';
    END IF;

    IF gin_def NOT LIKE '%account_id%' OR gin_def NOT LIKE '%text_body_tsv%'
       OR gin_def NOT LIKE '%WHERE (text_body_tsv IS NOT NULL)%' THEN
        RAISE EXCEPTION
            'idx_messages_fts_v2_account_tsv has the wrong definition (%). It must be a multicolumn GIN on (account_id, text_body_tsv) partial on text_body_tsv IS NOT NULL.',
            gin_def;
    END IF;
END $$;

-- Re-apply migration 000049 (purge non-atom IMAP keywords). This migration was numbered 000049
-- on its branch before #84 took that number, so a database that ran the branch recorded
-- version 49 without ever running the purge, and golang-migrate would never run it there.
-- The purge is idempotent and only touches mailboxes whose keyword registry still holds an
-- invalid keyword, so on every other database it reads mailbox_stats once and changes
-- nothing. See 000049 for the reasoning.
CREATE OR REPLACE FUNCTION sora_is_valid_imap_keyword(kw text) RETURNS boolean AS $$
    SELECT kw <> ''
       AND kw ~ '^[\x21-\x7e]+$'
       AND kw !~ '[()\{%*"\\\]]';
$$ LANGUAGE sql IMMUTABLE;

UPDATE message_state ms
SET custom_flags = (
        SELECT COALESCE(jsonb_agg(flag ORDER BY flag), '[]'::jsonb)
        FROM jsonb_array_elements_text(ms.custom_flags) AS elem(flag)
        WHERE sora_is_valid_imap_keyword(flag)
    )
WHERE ms.mailbox_id = ANY (ARRAY(
        SELECT mstats.mailbox_id
        FROM mailbox_stats mstats
        WHERE mstats.custom_flags_cache IS NOT NULL
          AND EXISTS (
                SELECT 1 FROM jsonb_array_elements_text(mstats.custom_flags_cache) AS elem(flag)
                WHERE left(flag, 1) <> '\' AND NOT sora_is_valid_imap_keyword(flag)
            )
    ))
  AND ms.custom_flags IS NOT NULL
  AND ms.custom_flags <> '[]'::jsonb
  AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(ms.custom_flags) AS elem(flag)
        WHERE NOT sora_is_valid_imap_keyword(flag)
    );

UPDATE mailbox_stats
SET custom_flags_cache = (
        SELECT COALESCE(jsonb_agg(flag ORDER BY flag), '[]'::jsonb)
        FROM jsonb_array_elements_text(custom_flags_cache) AS elem(flag)
        WHERE left(flag, 1) = '\' OR sora_is_valid_imap_keyword(flag)
    ),
    updated_at = now()
WHERE custom_flags_cache IS NOT NULL
  AND EXISTS (
        SELECT 1 FROM jsonb_array_elements_text(custom_flags_cache) AS elem(flag)
        WHERE left(flag, 1) <> '\' AND NOT sora_is_valid_imap_keyword(flag)
    );

DROP FUNCTION sora_is_valid_imap_keyword(text);
