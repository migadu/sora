-- Index each mailbox's direct-parent path to make the has_children check in
-- db.GetMailboxes index-backed.
--
-- mailboxes.path is a concatenation of 16-char hex ancestor-ID segments, so a mailbox's
-- direct parent is its path minus the final 16-char segment: LEFT(path, LENGTH(path)-16).
-- Listing previously derived this per row with `child.path LIKE m.path || '%'`, whose LIKE
-- pattern is a column expression -- PostgreSQL cannot use a prefix index for that, so it
-- sequentially scanned the account's mailboxes once per accessible mailbox (O(N^2)). For
-- accounts with tens of thousands of mailboxes this exceeded the read query_timeout.
--
-- An expression index on the parent path makes `LEFT(child.path, LENGTH(child.path)-16) =
-- m.path` an equality semi-join. It is derived purely from `path`, so unlike a maintained
-- column it can never drift, is COPY-safe, and needs no trigger or backfill.
--
-- NOTE: this CREATE INDEX takes a SHARE lock that blocks writes to `mailboxes` while the
-- index builds. On a large table, pre-build it out-of-band first so this no-ops:
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mailboxes_account_parent_path
--     ON mailboxes (account_id, (LEFT(path, LENGTH(path) - 16)));
CREATE INDEX IF NOT EXISTS idx_mailboxes_account_parent_path
ON mailboxes (account_id, (LEFT(path, LENGTH(path) - 16)));
