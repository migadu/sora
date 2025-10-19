-- Drop helper functions
DROP FUNCTION IF EXISTS get_accessible_mailboxes(BIGINT);
DROP FUNCTION IF EXISTS has_mailbox_right(BIGINT, BIGINT, CHAR);

-- Drop ACL table
DROP TABLE IF EXISTS mailbox_acls;

-- Drop indexes
DROP INDEX IF EXISTS idx_mailboxes_owner_domain;
DROP INDEX IF EXISTS idx_mailboxes_is_shared;

-- Remove columns from mailboxes table
ALTER TABLE mailboxes DROP COLUMN IF EXISTS owner_domain;
ALTER TABLE mailboxes DROP COLUMN IF EXISTS is_shared;
