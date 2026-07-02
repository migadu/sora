-- The mailboxes.subscribed column was left intact by the up migration and kept in
-- sync is NOT guaranteed after cut-over, but it still holds the pre-migration state
-- plus default-mailbox subscriptions, so dropping this table reverts to the legacy
-- per-row model with no data loss for the common case.
DROP TABLE IF EXISTS subscriptions;
