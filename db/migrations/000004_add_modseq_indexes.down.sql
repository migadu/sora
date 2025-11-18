-- Remove modseq indexes added for PollMailbox optimization

DROP INDEX IF EXISTS idx_messages_mailbox_modseqs;
DROP INDEX IF EXISTS idx_messages_expunged_modseq;
DROP INDEX IF EXISTS idx_messages_created_modseq;
DROP INDEX IF EXISTS idx_messages_updated_modseq;
