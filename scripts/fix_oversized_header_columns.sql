-- Bound existing rows' header columns before building idx_messages_mailbox_headers
-- (migration 000052). A btree tuple cannot exceed 2704 bytes; CREATE INDEX fails on the
-- first row over it ("index row size 3360 exceeds btree version 4 maximum 2704", seen on
-- production 2026-10-02), and a failed CREATE INDEX CONCURRENTLY leaves an INVALID index.
--
-- The bounds here MUST match helpers.MaxSubjectBytes (600) and helpers.MaxSortColumnBytes
-- (200), which sortColumnsFor in db/append.go applies to new rows (TestSortColumnsAreBounded
-- checks this file against the constants). Truncation is UTF-8 safe and keeps the prefix, as
-- helpers.TruncateUTF8Safe does.
--
-- Run on the primary (not through pgbouncer transaction mode: step 2 is a long statement
-- and step 3 is a multi-statement transaction), off-peak. Step 2 is a full heap scan of
-- messages (~387 GB in production): one pass, parallel, expect it to take a while.

-- 0. If a build has already failed, drop the invalid index it left behind.
--    SELECT indisvalid FROM pg_index WHERE indexrelid = 'idx_messages_mailbox_headers'::regclass;
--    DROP INDEX CONCURRENTLY idx_messages_mailbox_headers;

-- 1. UTF-8-safe byte truncation: cut at max_bytes, then back off past any continuation
--    bytes (10xxxxxx) so a multibyte character is never split. get_byte is 0-based, so
--    byte n is the first byte NOT kept; if it continues a character, the cut is inside it.
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

-- 2. List every row over a bound, expunged ones included. The index is partial on
--    expunged_at IS NULL, so only live rows can fail the BUILD, but `sora-admin messages
--    restore` sets expunged_at back to NULL in place (db/restore.go), which would pull an
--    oversized expunged row into the index later and fail the restore. The scan is a full
--    heap pass either way. Keep the list in a table: the UPDATE and the verification below
--    reuse it instead of scanning again.
SET statement_timeout = 0;
DROP TABLE IF EXISTS sora_oversized_header_rows;
CREATE TABLE sora_oversized_header_rows AS
SELECT id,
       octet_length(subject)         AS subject_bytes,
       octet_length(subject_sort)    AS subject_sort_bytes,
       octet_length(from_email_sort) AS from_email_bytes,
       octet_length(from_name_sort)  AS from_name_bytes,
       octet_length(to_email_sort)   AS to_email_bytes,
       octet_length(to_name_sort)    AS to_name_bytes,
       octet_length(cc_email_sort)   AS cc_email_bytes
FROM messages
WHERE octet_length(subject) > 600 OR octet_length(subject_sort) > 600
   OR octet_length(from_email_sort) > 200 OR octet_length(from_name_sort) > 200
   OR octet_length(to_email_sort) > 200 OR octet_length(to_name_sort) > 200
   OR octet_length(cc_email_sort) > 200;
SELECT count(*) AS rows_to_fix,
       count(*) FILTER (WHERE subject_bytes > 600 OR subject_sort_bytes > 600) AS long_subject,
       count(*) FILTER (WHERE from_email_bytes > 200 OR from_name_bytes > 200 OR to_email_bytes > 200
                        OR to_name_bytes > 200 OR cc_email_bytes > 200) AS long_sort,
       max(subject_bytes) AS max_subject_bytes
FROM sora_oversized_header_rows;

-- 3. Truncate exactly those rows. The columns are in the trigram GINs, so the UPDATE is
--    not HOT and touches every index on messages; fine for the handful of rows expected,
--    batch by id range if the count above is in the hundreds of thousands.
BEGIN;
UPDATE messages m
SET subject         = sora_trunc_utf8(m.subject, 600),
    subject_sort    = sora_trunc_utf8(m.subject_sort, 600),
    from_email_sort = sora_trunc_utf8(m.from_email_sort, 200),
    from_name_sort  = sora_trunc_utf8(m.from_name_sort, 200),
    to_email_sort   = sora_trunc_utf8(m.to_email_sort, 200),
    to_name_sort    = sora_trunc_utf8(m.to_name_sort, 200),
    cc_email_sort   = sora_trunc_utf8(m.cc_email_sort, 200)
FROM sora_oversized_header_rows o
WHERE m.id = o.id;
COMMIT;

-- 4. Verify on the listed rows only (no second full scan), then clean up.
SELECT count(*) AS still_over
FROM messages m JOIN sora_oversized_header_rows o ON o.id = m.id
WHERE octet_length(m.subject) > 600 OR octet_length(m.subject_sort) > 600
   OR octet_length(m.from_email_sort) > 200 OR octet_length(m.from_name_sort) > 200
   OR octet_length(m.to_email_sort) > 200 OR octet_length(m.to_name_sort) > 200
   OR octet_length(m.cc_email_sort) > 200;
-- expect 0, then:
-- DROP TABLE sora_oversized_header_rows;
-- DROP FUNCTION sora_trunc_utf8(text, int);

-- 5. Build the header covering index with CREATE INDEX CONCURRENTLY, using the definition of
--    idx_messages_mailbox_headers_v3 in db/migrations/000001_baseline.up.sql.
