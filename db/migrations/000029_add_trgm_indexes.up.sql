-- Add trigram indexes for LIKE '%...%' searches on names and emails

CREATE INDEX IF NOT EXISTS idx_messages_from_email_sort_trgm ON messages USING gin (from_email_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_from_name_sort_trgm ON messages USING gin (from_name_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_to_email_sort_trgm ON messages USING gin (to_email_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_to_name_sort_trgm ON messages USING gin (to_name_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_cc_email_sort_trgm ON messages USING gin (cc_email_sort gin_trgm_ops);
