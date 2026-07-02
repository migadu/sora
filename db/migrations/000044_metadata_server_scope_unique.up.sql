-- Fix server-scope METADATA (RFC 5464) uniqueness.
--
-- metadata.mailbox_id is NULL for server-scope entries. The existing
-- UNIQUE(account_id, mailbox_id, entry_name) constraint treats NULLs as distinct
-- (PostgreSQL default NULLS DISTINCT; PG14 has no NULLS NOT DISTINCT option), so
-- it never deduplicates server entries: SetMetadata's INSERT ... ON CONFLICT
-- (account_id, mailbox_id, entry_name) never fired for NULL mailbox_id, and each
-- SETMETADATA on the same server entry inserted a NEW row, accumulating
-- duplicates. GETMETADATA then returned an arbitrary one.
--
-- Add a partial unique index enforcing one row per (account_id, entry_name) for
-- server scope. The base constraint continues to cover mailbox scope (mailbox_id
-- IS NOT NULL), where it works correctly.

-- 1. Collapse any existing server-scope duplicates, keeping the most recently
--    updated row (ties broken by highest id).
DELETE FROM metadata a
USING metadata b
WHERE a.mailbox_id IS NULL
  AND b.mailbox_id IS NULL
  AND a.account_id = b.account_id
  AND a.entry_name = b.entry_name
  AND (a.updated_at < b.updated_at
       OR (a.updated_at = b.updated_at AND a.id < b.id));

-- 2. Enforce a single server-scope entry per (account_id, entry_name).
CREATE UNIQUE INDEX IF NOT EXISTS metadata_unique_server_entry
  ON metadata (account_id, entry_name)
  WHERE mailbox_id IS NULL;
