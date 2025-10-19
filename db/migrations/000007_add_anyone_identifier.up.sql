-- Add support for "anyone" identifier in ACLs (RFC 4314)
-- "anyone" is represented by account_id = NULL and identifier = 'anyone'

-- Add identifier column to store the actual identifier string
ALTER TABLE mailbox_acls ADD COLUMN identifier TEXT;

-- Backfill identifier column for existing rows
-- For existing rows, set identifier to the email address from credentials table
UPDATE mailbox_acls acl
SET identifier = (
    SELECT c.address
    FROM credentials c
    WHERE c.account_id = acl.account_id AND c.primary_identity = TRUE
);

-- Make account_id nullable to support "anyone" (NULL account_id = anyone)
ALTER TABLE mailbox_acls ALTER COLUMN account_id DROP NOT NULL;

-- Drop old unique constraint
ALTER TABLE mailbox_acls DROP CONSTRAINT mailbox_acls_unique_account;

-- Add new unique constraint that works with both specific users and "anyone"
-- This prevents duplicate ACL entries for the same mailbox+identifier
ALTER TABLE mailbox_acls ADD CONSTRAINT mailbox_acls_unique_identifier
    UNIQUE (mailbox_id, identifier);

-- Add constraint to ensure identifier is always set
ALTER TABLE mailbox_acls ADD CONSTRAINT mailbox_acls_identifier_not_null
    CHECK (identifier IS NOT NULL AND identifier != '');

-- Add constraint: if identifier = 'anyone', then account_id must be NULL
ALTER TABLE mailbox_acls ADD CONSTRAINT mailbox_acls_anyone_null_account
    CHECK ((identifier = 'anyone' AND account_id IS NULL) OR (identifier != 'anyone' AND account_id IS NOT NULL));

-- Add index for identifier lookups
CREATE INDEX idx_mailbox_acls_identifier ON mailbox_acls (identifier);

-- Update the helper function to check for "anyone" rights
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
    -- Check if user is the owner of a non-shared mailbox
    SELECT
        (account_id = p_account_id AND NOT COALESCE(is_shared, FALSE)),
        owner_domain
    INTO v_is_owner, v_owner_domain
    FROM mailboxes
    WHERE id = p_mailbox_id;

    -- Owners of non-shared mailboxes have all rights
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

-- Update the get_accessible_mailboxes function to include "anyone" mailboxes
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
    -- Get user's domain
    SELECT SPLIT_PART(address, '@', 2) INTO v_user_domain
    FROM credentials
    WHERE account_id = p_account_id AND primary_identity = TRUE;

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
      AND m.owner_domain = v_user_domain;  -- Same domain restriction
END;
$$ LANGUAGE plpgsql STABLE;
