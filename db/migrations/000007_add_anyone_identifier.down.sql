-- Revert "anyone" identifier support

-- Drop new constraints
ALTER TABLE mailbox_acls DROP CONSTRAINT IF EXISTS mailbox_acls_unique_identifier;
ALTER TABLE mailbox_acls DROP CONSTRAINT IF EXISTS mailbox_acls_identifier_not_null;
ALTER TABLE mailbox_acls DROP CONSTRAINT IF EXISTS mailbox_acls_anyone_null_account;

-- Drop index
DROP INDEX IF EXISTS idx_mailbox_acls_identifier;

-- Delete "anyone" entries (they have NULL account_id)
DELETE FROM mailbox_acls WHERE account_id IS NULL;

-- Make account_id NOT NULL again
ALTER TABLE mailbox_acls ALTER COLUMN account_id SET NOT NULL;

-- Restore old unique constraint
ALTER TABLE mailbox_acls ADD CONSTRAINT mailbox_acls_unique_account
    UNIQUE (mailbox_id, account_id);

-- Drop identifier column
ALTER TABLE mailbox_acls DROP COLUMN identifier;

-- Restore original has_mailbox_right function
CREATE OR REPLACE FUNCTION has_mailbox_right(
    p_mailbox_id BIGINT,
    p_account_id BIGINT,
    p_right CHAR(1)
) RETURNS BOOLEAN AS $$
DECLARE
    v_rights TEXT;
    v_is_owner BOOLEAN;
BEGIN
    -- Check if user is the owner of a non-shared mailbox
    SELECT (account_id = p_account_id AND NOT COALESCE(is_shared, FALSE))
    INTO v_is_owner
    FROM mailboxes
    WHERE id = p_mailbox_id;

    -- Owners of non-shared mailboxes have all rights
    IF v_is_owner THEN
        RETURN TRUE;
    END IF;

    -- Check ACL table for shared mailboxes
    SELECT rights INTO v_rights
    FROM mailbox_acls
    WHERE mailbox_id = p_mailbox_id AND account_id = p_account_id;

    IF v_rights IS NULL THEN
        RETURN FALSE;
    END IF;

    -- Check if the specific right is present in the rights string
    RETURN position(p_right IN v_rights) > 0;
END;
$$ LANGUAGE plpgsql STABLE;

-- Restore original get_accessible_mailboxes function
CREATE OR REPLACE FUNCTION get_accessible_mailboxes(
    p_account_id BIGINT
) RETURNS TABLE (
    mailbox_id BIGINT,
    mailbox_name TEXT,
    is_shared BOOLEAN,
    access_rights TEXT
) AS $$
BEGIN
    RETURN QUERY
    -- Personal mailboxes (owned by user)
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        'lrswipkxtea'::TEXT as access_rights  -- Full rights for owned mailboxes
    FROM mailboxes m
    WHERE m.account_id = p_account_id
      AND NOT COALESCE(m.is_shared, FALSE)

    UNION ALL

    -- Shared mailboxes with ACL access
    SELECT
        m.id,
        m.name,
        COALESCE(m.is_shared, FALSE),
        acl.rights
    FROM mailboxes m
    INNER JOIN mailbox_acls acl ON m.id = acl.mailbox_id
    WHERE acl.account_id = p_account_id
      AND COALESCE(m.is_shared, FALSE) = TRUE;
END;
$$ LANGUAGE plpgsql STABLE;
