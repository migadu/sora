-- Recover body search for mail stored before migration 000023.
--
-- WHY. Up to 000022 a body's search vector lived in message_contents, and the vector was the
-- only copy of its searchable text (the 000016 trigger nulled text_body once it had computed
-- it). 000023 moved full-text search to messages_fts, but until #791 it did not copy those
-- vectors, and nothing has read message_contents since. On a database that ran 23 that way,
-- body search (IMAP SEARCH BODY/TEXT, the User API search) finds none of the mail that was
-- there before the upgrade. The vectors are still in message_contents: no migration drops it.
--
-- This copies them into messages_fts_v2, one row per (body, mailbox owner) as 000050 does,
-- for every body some message holds, together with any text an older binary stored in
-- message_contents after 23 ran (text without a vector), which the FTS worker then tokenises.
-- A row that already exists is left as it is. It needs messages_fts_v2: on a database between
-- 23 and 49, migrate first.
--
-- WHO NEEDS IT. A database that ran 23 before #791, unless the vectors were copied out of
-- band at the time. This counts, in a sample of message_contents, the bodies that a message's
-- mailbox owner has no messages_fts_v2 row for. A nonzero result confirms missing rows;
-- zero in a sample is not proof that every row has been recovered. Include queued text as
-- well as vectors. For an exhaustive check, remove LIMIT 10000. With
-- fts_retention set, rows older than it are missing from messages_fts_v2 on purpose, so add
-- AND (sent_date IS NULL OR sent_date > now() - interval '<retention>') to the sample:
--   SELECT count(*) FROM (SELECT content_hash FROM message_contents
--                         WHERE text_body_tsv IS NOT NULL OR text_body IS NOT NULL LIMIT 10000) mc
--   WHERE EXISTS (SELECT 1 FROM messages m LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
--                 WHERE m.content_hash = mc.content_hash
--                   AND NOT EXISTS (SELECT 1 FROM messages_fts_v2 v
--                                   WHERE v.content_hash = m.content_hash
--                                     AND v.account_id = COALESCE(mb.account_id, m.account_id)));
--
-- HOW TO RUN, on a running system:
--   psql -h <primary> -d <db> -f scripts/fts_recover_message_contents.sql   -- defines the functions
--   psql -h <primary> -d <db> -c 'CALL sora_fts_recover_message_contents()'
-- Connect directly to the primary, never through a transaction pooler: the procedure COMMITs
-- after every batch, and the CALL must be its own statement. It walks message_contents in
-- content_hash order and prints after each batch the CALL that resumes after it. Re-running is
-- a no-op for rows already copied. Arguments: (after_hash, batch_bodies, sleep_ms), default
-- (NULL, 5000, 100); raise sleep_ms if replica lag grows, since replicas serve searches.
-- An older binary can write a hash or a new owner behind the current cursor. Before treating
-- recovery as complete, stop/drain every binary that still writes message_contents, then
-- run the procedure again from NULL and perform the exhaustive missing-row check above.
-- Resuming from a printed cursor alone cannot recover such late writes behind it.
--
-- COST. Every message_contents row with a vector or text is read once, and every messages row
-- holding its body (to find the mailbox owner). A copied row is a messages_fts_v2 insert with
-- its GIN maintenance. Rows past fts_retention are copied too; the cleaner's next prune
-- deletes them again.
--
-- Afterwards: DROP PROCEDURE sora_fts_recover_message_contents(varchar, int, int);
--             DROP FUNCTION sora_fts_recover_batch(varchar, int);
-- Only after old writers are drained and the final full pass/check succeeds can
-- message_contents be dropped to free its space. Do not drop it during a rolling upgrade.

-- One batch: the next p_batch bodies after p_after that have a vector or text. Returns the rows
-- added, the bodies read and the last of them, where the next batch starts.
--
-- The cursor is a single comparison, not "p_after IS NULL OR content_hash > p_after": in a
-- generic plan the OR cannot be an index condition, and every batch would rescan the table from
-- the start. '' sorts before every hash.
CREATE OR REPLACE FUNCTION sora_fts_recover_batch(p_after varchar(64), p_batch int)
RETURNS TABLE (inserted bigint, bodies bigint, last_hash varchar(64))
LANGUAGE sql AS $$
	WITH batch AS MATERIALIZED (
		SELECT content_hash FROM message_contents
		WHERE content_hash > COALESCE(p_after, '')
		  AND (text_body_tsv IS NOT NULL OR text_body IS NOT NULL)
		ORDER BY content_hash
		LIMIT p_batch
	), ins AS (
		INSERT INTO messages_fts_v2 (content_hash, account_id, text_body, text_body_tsv, sent_date, created_at)
		SELECT mc.content_hash, p.account_id,
		       CASE WHEN mc.text_body_tsv IS NULL THEN mc.text_body END,
		       mc.text_body_tsv, mc.sent_date, mc.created_at
		FROM batch b
		JOIN message_contents mc ON mc.content_hash = b.content_hash
		CROSS JOIN LATERAL (
			SELECT DISTINCT COALESCE(mb.account_id, m.account_id) AS account_id
			FROM messages m LEFT JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE m.content_hash = b.content_hash
		) p
		ON CONFLICT (content_hash, account_id) DO NOTHING
		RETURNING 1
	)
	SELECT (SELECT count(*) FROM ins), (SELECT count(*) FROM batch),
	       (SELECT max(content_hash) FROM batch)::varchar(64)
$$;

CREATE OR REPLACE PROCEDURE sora_fts_recover_message_contents(
	p_after varchar(64) DEFAULT NULL, p_batch int DEFAULT 5000, p_sleep_ms int DEFAULT 100)
LANGUAGE plpgsql AS $$
DECLARE
	r record;
	cur varchar(64) := p_after;
	total bigint := 0;
BEGIN
	IF p_batch IS NULL OR p_batch <= 0 THEN
		RAISE EXCEPTION 'p_batch must be positive, got %', p_batch;
	END IF;
	IF p_sleep_ms IS NULL OR p_sleep_ms < 0 THEN
		RAISE EXCEPTION 'p_sleep_ms must not be negative, got %', p_sleep_ms;
	END IF;
	LOOP
		SELECT * INTO r FROM sora_fts_recover_batch(cur, p_batch);
		EXIT WHEN r.bodies = 0;
		total := total + r.inserted;
		cur := r.last_hash;
		COMMIT;
		RAISE NOTICE '% bodies up to %: % rows added, % in this run. Resume with: CALL sora_fts_recover_message_contents(%, %, %)',
			r.bodies, cur, r.inserted, total, quote_literal(cur), p_batch, p_sleep_ms;
		PERFORM pg_sleep(p_sleep_ms / 1000.0);
	END LOOP;
	RAISE NOTICE 'done: % rows added in this run', total;
END
$$;
