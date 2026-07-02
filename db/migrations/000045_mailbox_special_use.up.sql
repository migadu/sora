-- Persist IMAP special-use (RFC 6154) per mailbox instead of deriving it from the
-- folder name at LIST time. Name-derivation lost the attribute on RENAME, never
-- applied to localized/renamed folders, ignored CREATE ... USE, and spuriously
-- tagged any folder literally named "Junk"/"Sent"/etc. This column is now the
-- single source of truth; server/imap/list.go reads it instead of the name.
--
-- special_use holds a single attribute (e.g. '\Sent'); NULL means no special use.
ALTER TABLE mailboxes ADD COLUMN special_use TEXT;

-- Backfill existing top-level default folders from the previous name-based logic
-- so they retain their attribute (and now survive rename). Notes:
--   * LOWER(name): mailbox names are case-insensitive (migration 000041) and the
--     old derivation uppercased the name, so match case-insensitively.
--   * name NOT LIKE '%/%': top-level only, so a nested "Work/Junk" is NOT tagged.
--   * deleted_at IS NULL: skip soft-deleted tombstones (migration 000042).
-- This UPDATE touches one row per default folder per account (~5 x accounts).
-- It performs HOT updates (special_use is unindexed) and should run before the
-- application code that reads the column is deployed.
UPDATE mailboxes
SET special_use = CASE LOWER(name)
        WHEN 'sent'    THEN '\Sent'
        WHEN 'drafts'  THEN '\Drafts'
        WHEN 'archive' THEN '\Archive'
        WHEN 'junk'    THEN '\Junk'
        WHEN 'trash'   THEN '\Trash'
    END
WHERE deleted_at IS NULL
  AND name NOT LIKE '%/%'
  AND LOWER(name) IN ('sent', 'drafts', 'archive', 'junk', 'trash');

-- RFC 6154 §5: a special-use attribute identifies at most one mailbox per account.
-- Enforce it structurally with a partial unique index over live rows. The backfill
-- above is one-per-name, so no duplicates exist at build time. NOTE: this is a plain
-- (non-CONCURRENT) index — it briefly locks writes to `mailboxes` while it builds
-- (~one entry per default folder per account). To avoid the write lock on a large
-- live table, build it out-of-band with CREATE UNIQUE INDEX CONCURRENTLY before
-- deploying (CONCURRENTLY cannot run inside this migration's transaction).
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_account_special_use_unique
    ON mailboxes (account_id, special_use)
    WHERE special_use IS NOT NULL AND deleted_at IS NULL;