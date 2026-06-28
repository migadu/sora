-- Two-phase mailbox deletion.
--
-- IMAP DELETE of a non-empty folder used to synchronously mark every message
-- expunged and hard-delete the mailbox row (plus FK ON DELETE SET NULL rewriting
-- every message row and a message_state CASCADE), all under the per-mailbox
-- serialization lock -- O(N) on the client command path, with P99 up to ~1 minute.
--
-- Now DELETE just stamps `deleted_at` (one row write) and returns; the background
-- cleaner performs the existing hard-delete later. A soft-deleted mailbox
-- (deleted_at IS NOT NULL) MUST be invisible to every normal read path.

BEGIN;

ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL;

-- The case-insensitive name-uniqueness index must constrain only LIVE mailboxes, so
-- that DELETE "Foo" immediately followed by CREATE "Foo" succeeds while the tombstone
-- row still exists. Replace the full unique index (migration 000041) with a partial
-- one. mailboxes is small (one row per folder) so a transactional rebuild is cheap;
-- no CONCURRENTLY needed.
DROP INDEX IF EXISTS mailboxes_account_id_lower_name_unique;
CREATE UNIQUE INDEX IF NOT EXISTS mailboxes_account_id_lower_name_unique
    ON mailboxes (account_id, LOWER(name)) WHERE deleted_at IS NULL;

-- Lets the background purge sweep find tombstones without scanning live rows.
CREATE INDEX IF NOT EXISTS idx_mailboxes_deleted_at
    ON mailboxes (deleted_at) WHERE deleted_at IS NOT NULL;

-- Shared-mailbox accessibility runs through this stored function, so it must hide
-- soft-deleted mailboxes too. Identical to migration 000001 except every branch
-- adds `AND m.deleted_at IS NULL`.
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
    -- Personal mailboxes (owned by user)
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        'lrswipkxtea'::TEXT as access_rights
    FROM mailboxes m
    WHERE m.account_id = p_account_id
      AND NOT COALESCE(m.is_shared, FALSE)
      AND m.deleted_at IS NULL

    UNION ALL

    -- Shared mailboxes with direct ACL access
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.account_id = p_account_id
      AND COALESCE(m.is_shared, FALSE) = TRUE
      AND m.deleted_at IS NULL

    UNION ALL

    -- Shared mailboxes with "anyone" access (same domain only)
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.identifier = 'anyone'
      AND COALESCE(m.is_shared, FALSE) = TRUE
      AND m.owner_domain = v_user_domain
      AND m.deleted_at IS NULL;
END;
$$ LANGUAGE plpgsql STABLE;

COMMIT;
