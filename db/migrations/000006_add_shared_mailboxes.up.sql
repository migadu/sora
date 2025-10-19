-- Add shared mailbox support to mailboxes table
ALTER TABLE mailboxes ADD COLUMN is_shared BOOLEAN DEFAULT FALSE;
ALTER TABLE mailboxes ADD COLUMN owner_domain TEXT;

-- Create indexes for shared mailbox lookups
CREATE INDEX idx_mailboxes_is_shared ON mailboxes (is_shared) WHERE is_shared = TRUE;
CREATE INDEX idx_mailboxes_owner_domain ON mailboxes (owner_domain) WHERE owner_domain IS NOT NULL;

-- ACL table for mailbox permissions (RFC 4314)
-- Stores access control entries for shared mailboxes
CREATE TABLE mailbox_acls (
    id BIGSERIAL PRIMARY KEY,
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    rights VARCHAR(20) NOT NULL, -- IMAP ACL rights: lrswipkxtea
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now() NOT NULL,
    CONSTRAINT mailbox_acls_unique_account UNIQUE (mailbox_id, account_id),
    CONSTRAINT mailbox_acls_valid_rights CHECK (rights ~ '^[lrswipkxtea]+$')
);

CREATE INDEX idx_mailbox_acls_mailbox_id ON mailbox_acls (mailbox_id);
CREATE INDEX idx_mailbox_acls_account_id ON mailbox_acls (account_id);

-- Function to check if an account has a specific right on a mailbox
-- Returns TRUE if:
--   1. User owns the mailbox (non-shared), OR
--   2. User has an ACL entry with the requested right
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

-- Helper function to get all mailboxes accessible to a user
-- Returns both owned mailboxes and shared mailboxes with ACL access
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
