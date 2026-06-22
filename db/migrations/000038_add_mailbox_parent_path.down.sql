-- Rollback the mailbox parent-path expression index.
DROP INDEX IF EXISTS idx_mailboxes_account_parent_path;
