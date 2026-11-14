-- Mailbox names are case-insensitive (Option A): INBOX is reserved/case-insensitive
-- per RFC 3501 §5.1, and Sora's read path (GetMailboxByName, special-use detection,
-- RenameMailbox collision check) already compares names case-insensitively. This
-- migration makes uniqueness agree with that behavior by replacing the
-- case-sensitive UNIQUE(account_id, name) constraint with a case-insensitive
-- UNIQUE(account_id, LOWER(name)) index, so two mailboxes that differ only in case
-- (e.g. "INBOX"/"Inbox", "Archive"/"archive") can no longer coexist.
--
-- PREREQUISITE: existing case-variant duplicates must be resolved first, otherwise the
-- unique index cannot be built. The guard below aborts the migration with a clear message
-- if any collision remains, rather than failing obscurely on index creation. The cleanup
-- script its message names was a one-off and is not in this repository; resolve the
-- duplicates by hand instead, with the Sora nodes stopped (before starting the version
-- that runs this migration):
--
--   1. List the collision groups:
--        SELECT account_id, array_agg(id ORDER BY id) AS ids, array_agg(name ORDER BY id) AS names
--        FROM mailboxes GROUP BY account_id, LOWER(name) HAVING count(*) > 1;
--   2. In each group keep one mailbox (for INBOX the one spelled "INBOX") and rename every
--      other one, together with its child mailboxes, to a name of its own by appending its
--      id, e.g. "archive" -> "archive (4)" and "archive/2024" -> "archive (4)/2024":
--        UPDATE mailboxes AS m
--        SET name = d.name || ' (' || d.id || ')' || substr(m.name, length(d.name) + 1)
--        FROM mailboxes AS d
--        WHERE d.id = <id to rename> AND m.account_id = d.account_id AND m.path LIKE d.path || '%';
--      Only names change; messages, flags and subscriptions stay with their mailbox ids.
--   3. Repeat 1 and 2 until 1 returns no rows: renaming a parent also resolves its
--      children's collisions.
--   4. After the upgrade the renamed folders appear next to the kept ones; move their
--      messages over with any IMAP client and delete them.

DO $$
DECLARE
    collision_groups integer;
BEGIN
    SELECT count(*) INTO collision_groups
    FROM (
        SELECT 1 FROM mailboxes
        GROUP BY account_id, LOWER(name)
        HAVING count(*) > 1
    ) d;

    IF collision_groups > 0 THEN
        RAISE EXCEPTION
            'Cannot enforce case-insensitive mailbox names: % case-collision group(s) still exist. Run scripts/fix_mailbox_case_duplicates.sql first, then re-run this migration.',
            collision_groups;
    END IF;
END $$;

-- Replace the case-sensitive constraint and the redundant non-unique lower(name)
-- index with a single case-insensitive unique index. The new index also backs the
-- case-insensitive lookups (GetMailboxByName, get-or-create) and ON CONFLICT
-- (account_id, LOWER(name)) upserts in the application.
--
-- All three statements are idempotent (IF EXISTS / IF NOT EXISTS) so this migration
-- is a safe no-op if an operator pre-applied the change by hand — e.g. to build the
-- index with CREATE UNIQUE INDEX CONCURRENTLY (which cannot run inside this migration's
-- transaction). If you pre-build it, use exactly the index name below and confirm
-- pg_index.indisvalid is true before relying on it.
ALTER TABLE mailboxes DROP CONSTRAINT IF EXISTS mailboxes_account_id_name_unique;
DROP INDEX IF EXISTS idx_mailboxes_lower_name;
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_account_id_lower_name_unique ON mailboxes (account_id, LOWER(name));
