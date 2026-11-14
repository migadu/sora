-- Backfill messages.extra_addresses (migration 000059) for rows written before it.
--
-- Optional. Until a row is filled, SEARCH FROM/TO/CC (and the header part of TEXT) match its
-- first From/To/Cc address only, exactly as before the migration. Every row written by a
-- binary with the migration is filled at insert.
--
-- The value is computed from recipients_json, which holds every address the application
-- extracted, so nothing is fetched from S3. It must equal what sortColumnsFor in db/append.go
-- writes, bound included (TestExtraAddressesBackfillMatchesWriter loads this file and checks
-- that). One difference: lower() here follows the database's collation, strings.ToLower in Go
-- follows Unicode; they agree for ASCII.
--
-- HOW TO RUN, after every node runs a binary with migration 000059 (rows written by older
-- binaries during the rollout are NULL too):
--   psql -h <primary> -d <db> -f scripts/backfill_extra_addresses.sql   -- defines the functions
--   psql -h <primary> -d <db> -c 'CALL sora_backfill_extra_addresses()'
-- Connect directly to the primary, never through a transaction pooler: the procedure COMMITs
-- after every batch, and the CALL must be its own statement. It walks the table by id, newest
-- first, and prints after each batch the CALL that resumes after it. Re-running is a no-op
-- for rows already filled. Arguments: (from_id, batch_rows, sleep_ms), default
-- (max(id), 5000, 100); raise sleep_ms if replica lag grows, since replicas serve searches.
--
-- COST. Every row in the id range is read (recipients_json is usually inline; nothing else
-- large is), and a row is written only when it has something to store: a message with one
-- From, one To and no Cc keeps NULL, which the search reads as "nothing further". A written
-- row is a non-HOT update (extra_addresses is in idx_messages_mailbox_headers_v2), so it gets
-- a new heap tuple and a new entry in every index on messages, and its page loses its
-- all-visible bit until the next vacuum (index-only scans fetch from the heap meanwhile). Count
-- the rows first on a sample, e.g. the newest million ids:
--   SELECT count(*) FILTER (WHERE sora_extra_addresses(recipients_json, from_name_sort, from_email_sort,
--                                   to_name_sort, to_email_sort, cc_email_sort) <> '') AS to_write, count(*)
--   FROM messages WHERE id > (SELECT max(id) - 1000000 FROM messages) AND expunged_at IS NULL;
-- Expunged rows are skipped: `sora-admin messages restore` brings one back with its first
-- addresses searchable, as before.
--
-- Afterwards: DROP PROCEDURE sora_backfill_extra_addresses(bigint, int, int);
--             DROP FUNCTION sora_backfill_extra_addresses_batch(bigint, bigint);
--             DROP FUNCTION sora_extra_addresses(jsonb, text, text, text, text, text);
--             DROP FUNCTION sora_trunc_utf8(text, int);   -- unless scripts/fix_oversized_header_columns.sql still needs it

-- UTF-8-safe byte truncation, as helpers.TruncateUTF8Safe (identical to the function in
-- scripts/fix_oversized_header_columns.sql): cut at max_bytes, then back off past any
-- continuation bytes (10xxxxxx) so a multibyte character is never split.
CREATE OR REPLACE FUNCTION sora_trunc_utf8(s text, max_bytes int) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
	b bytea;
	n int;
BEGIN
	IF s IS NULL OR octet_length(s) <= max_bytes THEN
		RETURN s;
	END IF;
	b := convert_to(s, 'UTF8');
	n := max_bytes;
	WHILE n > 0 AND (get_byte(b, n) & 192) = 128 LOOP
		n := n - 1;
	END LOOP;
	RETURN convert_from(substring(b from 1 for n), 'UTF8');
END
$$;

-- The extra_addresses value for a row, from its recipients_json and its five first-address
-- sort columns: sections From, To, Cc separated by a newline; in each, the lowercased names and
-- addresses the sort columns do not hold (every address after the first, and the first Cc's
-- name), in header order, separated by a tab; tabs and newlines inside a value become spaces;
-- trailing empty sections dropped; cut to what the sort columns leave of 1300 bytes
-- (helpers.MaxAddressColumnsBytes).
CREATE OR REPLACE FUNCTION sora_extra_addresses(
	recipients jsonb, from_name text, from_email text, to_name text, to_email text, cc_email text
) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
	WITH r AS (
		SELECT e->>'type' AS kind, ord,
		       row_number() OVER (PARTITION BY e->>'type' ORDER BY ord) AS nth,
		       translate(lower(COALESCE(e->>'name', '')), E'\t\n', '  ') AS name,
		       translate(lower(COALESCE(e->>'email', '')), E'\t\n', '  ') AS email
		FROM jsonb_array_elements(CASE WHEN jsonb_typeof(recipients) = 'array' THEN recipients ELSE '[]'::jsonb END)
		     WITH ORDINALITY AS a(e, ord)
		WHERE e->>'type' IN ('from', 'to', 'cc')
	), v AS (
		SELECT kind, ord, 1 AS part, name AS val FROM r WHERE name <> '' AND (nth > 1 OR kind = 'cc')
		UNION ALL
		SELECT kind, ord, 2, email FROM r WHERE email <> '' AND nth > 1
	), s AS (
		SELECT COALESCE(string_agg(val, E'\t' ORDER BY ord, part) FILTER (WHERE kind = 'from'), '') AS f,
		       COALESCE(string_agg(val, E'\t' ORDER BY ord, part) FILTER (WHERE kind = 'to'), '') AS t,
		       COALESCE(string_agg(val, E'\t' ORDER BY ord, part) FILTER (WHERE kind = 'cc'), '') AS c
		FROM v
	)
	SELECT sora_trunc_utf8(rtrim(f || E'\n' || t || E'\n' || c, E'\n'),
	                       greatest(1300 - octet_length(COALESCE(from_name, '')) - octet_length(COALESCE(from_email, ''))
	                                     - octet_length(COALESCE(to_name, '')) - octet_length(COALESCE(to_email, ''))
	                                     - octet_length(COALESCE(cc_email, '')), 0))
	FROM s
$$;

-- One batch: fill the live rows with ids in [p_lo, p_hi] that are still NULL and have
-- something to store. Returns the number of rows written.
CREATE OR REPLACE FUNCTION sora_backfill_extra_addresses_batch(p_lo bigint, p_hi bigint) RETURNS bigint
LANGUAGE sql AS $$
	WITH computed AS (
		SELECT id, sora_extra_addresses(recipients_json, from_name_sort, from_email_sort,
		                                to_name_sort, to_email_sort, cc_email_sort) AS v
		FROM messages
		WHERE id BETWEEN p_lo AND p_hi AND expunged_at IS NULL AND extra_addresses IS NULL
	), written AS (
		UPDATE messages m SET extra_addresses = c.v
		FROM computed c
		WHERE m.id = c.id AND c.v <> '' AND m.extra_addresses IS NULL
		RETURNING 1
	)
	SELECT count(*) FROM written
$$;

CREATE OR REPLACE PROCEDURE sora_backfill_extra_addresses(p_from_id bigint DEFAULT NULL, p_batch int DEFAULT 5000, p_sleep_ms int DEFAULT 100)
LANGUAGE plpgsql AS $$
DECLARE
	hi bigint := p_from_id;
	lo_bound bigint;
	lo bigint;
	n bigint;
	total bigint := 0;
BEGIN
	SELECT min(id), COALESCE(hi, max(id)) INTO lo_bound, hi FROM messages;
	WHILE hi >= lo_bound LOOP
		lo := greatest(hi - p_batch + 1, lo_bound);
		n := sora_backfill_extra_addresses_batch(lo, hi);
		total := total + n;
		COMMIT;
		RAISE NOTICE 'ids % to %: % rows filled, % in this run. Resume with: CALL sora_backfill_extra_addresses(%, %, %)',
			lo, hi, n, total, lo - 1, p_batch, p_sleep_ms;
		hi := lo - 1;
		PERFORM pg_sleep(p_sleep_ms / 1000.0);
	END LOOP;
	RAISE NOTICE 'done: % rows filled in this run', total;
END
$$;
