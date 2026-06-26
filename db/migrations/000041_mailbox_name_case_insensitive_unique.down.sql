-- Revert to case-sensitive mailbox-name uniqueness. The case-sensitive constraint
-- is weaker than the case-insensitive index, so any data that satisfied the index
-- also satisfies the constraint; this rollback cannot fail on existing rows.
DROP INDEX IF EXISTS mailboxes_account_id_lower_name_unique;
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_account_id_name_unique UNIQUE (account_id, name);
CREATE INDEX idx_mailboxes_lower_name ON mailboxes (account_id, LOWER(name));
