-- Give every live message a message_state row, ahead of migration 000063 (#1151).
--
-- Needed only where message ids span more than 1,000,000: migration 000063 checks that
-- many by itself and refuses a larger database unless this script has run. A live message
-- without a row gets one with no flags and no keywords, which is what every reader already
-- showed for it, and its mailbox's unseen_count is counted again (see UNSEEN in migration
-- 000063 for why it is not just incremented). Safe to run while any release serves mail:
-- every release reads the row, every insert path already writes one, and a batch takes
-- the mailbox locks first and in ascending order, as every other path does.
--
-- HOW TO RUN, on the primary over a direct connection, never through a transaction pooler
-- (the procedure COMMITs after every batch, and the CALL must be its own statement):
--   psql -h <primary> -d <db> -f scripts/message_state_backfill.sql   -- defines the procedure
--   psql -h <primary> -d <db> -c 'CALL sora_backfill_message_state()'
-- Then upgrade. The procedure walks the ids up to the highest one at its start and records
-- how far it got in message_state_backfill after every batch; migration 000063 checks the
-- ids above that and drops the table. Stopped or re-run, it continues from the recorded id,
-- so a second CALL just before the upgrade keeps that last check short. Arguments:
-- (batch_ids, sleep_ms), default (10000, 100); raise sleep_ms if replica lag grows.
--
-- COST. A batch reads the ids of its range from the primary keys of messages and
-- message_state (index-only where the pages are all-visible) and then only the messages
-- without a row, so the whole walk reads about the size of those two indexes. A batch
-- without such messages writes nothing. One that has some locks their mailboxes for the
-- rest of its transaction (deliveries and flag changes there wait) and counts their unseen
-- messages again, as RecomputeMailboxUnseen does.
--
-- Afterwards, once migration 000063 has run:
--   DROP PROCEDURE sora_backfill_message_state(int, int);
--   DROP FUNCTION sora_backfill_message_state_batch(bigint, bigint);

CREATE TABLE IF NOT EXISTS message_state_backfill (
    singleton       boolean PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    checked_through bigint NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Migration 000063 reads this table and drops it as Sora's database user, the owner of
-- messages, but a table belongs to the role that created it. Created by a superuser, it
-- would stop the migration with "permission denied" and leave the version dirty, so hand
-- it to the owner of messages, whoever runs this script.
DO $$
BEGIN
	EXECUTE format('ALTER TABLE message_state_backfill OWNER TO %s',
		(SELECT relowner::regrole FROM pg_class WHERE oid = 'messages'::regclass));
END
$$;

-- One batch: give the live messages with ids in (p_lo, p_hi] that have no row one, and
-- count the unseen messages of their mailboxes again. Returns the number of rows added. The
-- same statements as in migration 000063. ARRAY(subquery) is evaluated ahead of the scan
-- that uses it, which keeps that on the primary key, and the range is repeated on
-- message_state so its index is read for the batch's ids only, not from the start every
-- time.
CREATE OR REPLACE FUNCTION sora_backfill_message_state_batch(p_lo bigint, p_hi bigint) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
	ids bigint[];
	boxes bigint[];
	n bigint;
BEGIN
	ids := ARRAY(
		SELECT x.id FROM messages x
		WHERE x.id > p_lo AND x.id <= p_hi
		  AND NOT EXISTS (SELECT 1 FROM message_state ms
		                  WHERE ms.message_id = x.id AND ms.message_id > p_lo AND ms.message_id <= p_hi));
	boxes := ARRAY(
		SELECT DISTINCT m.mailbox_id FROM messages m
		WHERE m.id = ANY (ids) AND m.expunged_at IS NULL AND m.mailbox_id IS NOT NULL
		ORDER BY 1);
	IF cardinality(boxes) = 0 THEN
		RETURN 0;
	END IF;
	PERFORM 1 FROM mailboxes WHERE id = ANY (boxes) ORDER BY id FOR UPDATE;
	INSERT INTO message_state (message_id, mailbox_id)
	SELECT m.id, m.mailbox_id
	FROM messages m
	WHERE m.id = ANY (ids)
	  AND m.expunged_at IS NULL
	  AND m.mailbox_id = ANY (boxes)
	ON CONFLICT (message_id) DO NOTHING;
	GET DIAGNOSTICS n = ROW_COUNT;
	WITH unseen AS (
		SELECT ms.mailbox_id, count(*) AS unseen
		FROM message_state ms
		JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
		WHERE ms.mailbox_id = ANY (boxes) AND (ms.flags & 1) = 0 AND m.expunged_at IS NULL
		GROUP BY ms.mailbox_id
	)
	UPDATE mailbox_stats s
	SET unseen_count = COALESCE(u.unseen, 0), updated_at = now()
	FROM unnest(boxes) AS b(id) LEFT JOIN unseen u ON u.mailbox_id = b.id
	WHERE s.mailbox_id = b.id;
	RETURN n;
END
$$;

CREATE OR REPLACE PROCEDURE sora_backfill_message_state(p_batch int DEFAULT 10000, p_sleep_ms int DEFAULT 100)
LANGUAGE plpgsql AS $$
DECLARE
	lo bigint;
	hi bigint;
	top bigint;
	n bigint;
	total bigint := 0;
BEGIN
	IF p_batch IS NULL OR p_batch <= 0 THEN
		RAISE EXCEPTION 'p_batch must be positive, got %', p_batch;
	END IF;
	IF p_sleep_ms IS NULL OR p_sleep_ms < 0 THEN
		RAISE EXCEPTION 'p_sleep_ms must not be negative, got %', p_sleep_ms;
	END IF;
	SELECT COALESCE(max(checked_through), 0) INTO lo FROM message_state_backfill;
	SELECT COALESCE(max(id), 0) INTO top FROM messages;
	WHILE lo < top LOOP
		hi := least(lo + p_batch, top);
		n := sora_backfill_message_state_batch(lo, hi);
		total := total + n;
		INSERT INTO message_state_backfill (checked_through) VALUES (hi)
		ON CONFLICT (singleton) DO UPDATE SET checked_through = EXCLUDED.checked_through, updated_at = now();
		COMMIT;
		RAISE NOTICE 'ids % to %: % rows added, % in this run', lo + 1, hi, n, total;
		lo := hi;
		PERFORM pg_sleep(p_sleep_ms / 1000.0);
	END LOOP;
	RAISE NOTICE 'done: ids checked through %, % rows added in this run', lo, total;
END
$$;
