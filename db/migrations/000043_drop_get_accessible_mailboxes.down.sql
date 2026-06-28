-- Restore get_accessible_mailboxes() to its post-000042 form (deleted_at-aware), so the
-- rollback chain is consistent (000042's down expects this function to exist before it
-- reverts it to the pre-soft-delete body and drops the column).

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
