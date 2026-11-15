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
-- (non-CONCURRENT) index. The migration file runs as one transaction, so the ACCESS
-- EXCLUSIVE lock taken by the ADD COLUMN above is held through the backfill and this
-- build, which reads all of `mailboxes` once (it indexes only ~one entry per default
-- folder per account): every query on `mailboxes`, logins and deliveries included, waits
-- until the migration commits. The index cannot be built ahead of this migration:
-- special_use does not exist before it, and adding the column by hand makes the ADD
-- COLUMN above fail. On a large deployment, run this migration off-peak.
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_account_special_use_unique
    ON mailboxes (account_id, special_use)
    WHERE special_use IS NOT NULL AND deleted_at IS NULL;