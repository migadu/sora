-- Fix has_mailbox_right function to grant owners full rights on their shared mailboxes
-- The previous version incorrectly excluded shared mailbox owners

CREATE OR REPLACE FUNCTION has_mailbox_right(
    p_mailbox_id BIGINT,
    p_account_id BIGINT,
    p_right CHAR(1)
) RETURNS BOOLEAN AS $$
DECLARE
    v_rights TEXT;
    v_is_owner BOOLEAN;
    v_owner_domain TEXT;
    v_user_domain TEXT;
BEGIN
    -- Check if user is the owner (both shared and non-shared mailboxes)
    -- FIXED: Removed "AND NOT COALESCE(is_shared, FALSE)" condition
    SELECT
        (account_id = p_account_id),
        owner_domain
    INTO v_is_owner, v_owner_domain
    FROM mailboxes
    WHERE id = p_mailbox_id;

    -- Owners have all rights (both shared and non-shared mailboxes)
    IF v_is_owner THEN
        RETURN TRUE;
    END IF;

    -- Check direct ACL entry for this user
    SELECT rights INTO v_rights
    FROM mailbox_acls
    WHERE mailbox_id = p_mailbox_id AND account_id = p_account_id;

    IF v_rights IS NOT NULL AND position(p_right IN v_rights) > 0 THEN
        RETURN TRUE;
    END IF;

    -- Check "anyone" ACL entry (only for shared mailboxes in same domain)
    IF v_owner_domain IS NOT NULL THEN
        -- Get user's domain
        SELECT SPLIT_PART(address, '@', 2) INTO v_user_domain
        FROM credentials
        WHERE account_id = p_account_id AND primary_identity = TRUE;

        -- If user is in same domain as mailbox owner, check "anyone" rights
        IF v_user_domain = v_owner_domain THEN
            SELECT rights INTO v_rights
            FROM mailbox_acls
            WHERE mailbox_id = p_mailbox_id AND identifier = 'anyone';

            IF v_rights IS NOT NULL AND position(p_right IN v_rights) > 0 THEN
                RETURN TRUE;
            END IF;
        END IF;
    END IF;

    RETURN FALSE;
END;
$$ LANGUAGE plpgsql STABLE;
