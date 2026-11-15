-- Fold METADATA (RFC 5464) entry names stored before IMAP case-folded them.
--
-- RFC 5464 §3.2: "Entry names are case-insensitive." The IMAP commands fold
-- every entry name to lower case before they read or write the metadata table,
-- and entry_name compares case-sensitively. Before that folding was added the
-- name was stored as the client sent it, so a row such as /private/Comment can
-- no longer be read by GETMETADATA nor deleted by SETMETADATA, but still counts
-- toward the account's [metadata] entry and size limits. A later SETMETADATA of
-- the same entry stores a second row next to it.
--
-- The names are folded with translate() over A-Z, not lower(): the IMAP side
-- folds only ASCII letters, and lower() follows the database's LC_CTYPE (under
-- a Turkish locale it maps "I" to the non-ASCII dotless i, a name no client can
-- address).
--
-- The table is locked against writes for the two statements, so a SETMETADATA
-- committed between them cannot create a row that the rename then collides with.

BEGIN;

LOCK TABLE metadata IN SHARE ROW EXCLUSIVE MODE;

-- 1. Where several rows of one account and scope (server, or one mailbox) fold
--    to the same name, keep the most recently updated one (ties broken by the
--    highest id, as migration 000044 did for server-scope duplicates). Only
--    accounts holding a name that is not folded yet are ranked.
DELETE FROM metadata m
USING (
    SELECT id,
           row_number() OVER (
               PARTITION BY account_id, mailbox_id,
                            translate(entry_name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
               ORDER BY updated_at DESC, id DESC) AS rank
    FROM metadata
    WHERE account_id IN (
        SELECT account_id FROM metadata
        WHERE entry_name <> translate(entry_name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
) ranked
WHERE m.id = ranked.id
  AND ranked.rank > 1;

-- 2. Every folded name is now unique within its scope: rename the rest.
UPDATE metadata
SET entry_name = translate(entry_name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
WHERE entry_name <> translate(entry_name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');

COMMIT;
