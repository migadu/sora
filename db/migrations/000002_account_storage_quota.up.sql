-- Per-account storage limit in bytes, reported by IMAP QUOTA (RFC 9208) as the STORAGE
-- resource of the account's quota root. NULL is unlimited. Set through the Admin API;
-- new accounts get [quota] default_storage_quota. The column is nullable without a
-- default, so existing rows are not rewritten: they stay unlimited.
ALTER TABLE accounts ADD COLUMN storage_quota bigint
    CONSTRAINT accounts_storage_quota_positive CHECK (storage_quota > 0);
