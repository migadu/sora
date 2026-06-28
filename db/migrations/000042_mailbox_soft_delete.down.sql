-- Reverse two-phase mailbox deletion.
--
-- NOTE: restoring the non-partial unique index requires that no soft-deleted
-- tombstone shares a (account_id, LOWER(name)) with a live mailbox. Hard-delete any
-- remaining tombstones first so the unique index can be rebuilt.

BEGIN;

-- Tombstones are about to be hard-deleted. messages.mailbox_id is ON DELETE SET NULL,
-- so a bare DELETE would leave each tombstone's messages active-but-orphaned
-- (mailbox_id NULL, expunged_at NULL): never expunged, never S3-cleaned, permanently
-- inflating quota/storage. Replicate DeleteMailbox's expunge step first so those messages
-- end up properly expunged with mailbox_path preserved (restorable, eventually purged by
-- the cleaner) — exactly as if the mailbox had been deleted the old synchronous way.
UPDATE messages m
SET mailbox_path = mb.name,
    expunged_at = now(),
    expunged_modseq = nextval('messages_modseq')
FROM mailboxes mb
WHERE m.mailbox_id = mb.id
  AND mb.deleted_at IS NOT NULL
  AND m.expunged_at IS NULL;

-- Now drop the tombstones (they would collide with live rows under the non-partial index).
DELETE FROM mailboxes WHERE deleted_at IS NOT NULL;

DROP INDEX IF EXISTS idx_mailboxes_deleted_at;

DROP INDEX IF EXISTS mailboxes_account_id_lower_name_unique;
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_account_id_lower_name_unique
    ON mailboxes (account_id, LOWER(name));

-- Restore the original (migration 000001) function body without the deleted_at filter.
CREATE OR REPLACE FUNCTION get_accessible_mailboxes(
    p_account_id BIGINT
) RETURNS TABLE (
    mailbox_id BIGINT,
    mailbox_name TEXT,
    is_shared BOOLEAN,
    access_rights TEXT
) AS $$
DECLARE
    v_user_domain TEXT;
BEGIN
    SELECT SPLIT_PART(address, '@', 2) INTO v_user_domain
    FROM credentials
    WHERE account_id = p_account_id AND primary_identity = TRUE;

    RETURN QUERY
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        'lrswipkxtea'::TEXT as access_rights
    FROM mailboxes m
    WHERE m.account_id = p_account_id
      AND NOT COALESCE(m.is_shared, FALSE)

    UNION ALL

    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.account_id = p_account_id
      AND COALESCE(m.is_shared, FALSE) = TRUE

    UNION ALL

    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.identifier = 'anyone'
      AND COALESCE(m.is_shared, FALSE) = TRUE
      AND m.owner_domain = v_user_domain;
END;
$$ LANGUAGE plpgsql STABLE;

ALTER TABLE mailboxes DROP COLUMN IF EXISTS deleted_at;

COMMIT;
