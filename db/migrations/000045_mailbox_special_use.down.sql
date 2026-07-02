DROP INDEX IF EXISTS mailboxes_account_special_use_unique;
ALTER TABLE mailboxes DROP COLUMN IF EXISTS special_use;
