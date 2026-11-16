-- Drop the index of the messages without a Date: header. Binaries that search SENT* keys
-- through it must be gone first: without it they read the whole mailbox's rows. DROP INDEX
-- takes an ACCESS EXCLUSIVE lock on messages; on a large live database drop it out-of-band
-- with DROP INDEX CONCURRENTLY IF EXISTS idx_messages_mailbox_sent_date_unknown; first, and
-- this migration then has nothing left to do.

DROP INDEX IF EXISTS idx_messages_mailbox_sent_date_unknown;
