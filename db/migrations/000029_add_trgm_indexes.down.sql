-- Remove trigram indexes

DROP INDEX IF EXISTS idx_messages_from_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_from_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_cc_email_sort_trgm;
