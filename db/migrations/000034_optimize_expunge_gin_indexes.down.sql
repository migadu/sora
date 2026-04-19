-- Revert optimization: Drop partial GIN indexes and recreate full GIN indexes

-- 1. Create full GIN indexes concurrently
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm_full ON messages USING gin (LOWER(subject) gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_recipients_json_full ON messages USING GIN (recipients_json jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_messages_from_email_sort_trgm_full ON messages USING gin (from_email_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_from_name_sort_trgm_full ON messages USING gin (from_name_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_to_email_sort_trgm_full ON messages USING gin (to_email_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_to_name_sort_trgm_full ON messages USING gin (to_name_sort gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_cc_email_sort_trgm_full ON messages USING gin (cc_email_sort gin_trgm_ops);

-- 2. Drop the partial indexes concurrently
DROP INDEX IF EXISTS idx_messages_subject_trgm;
DROP INDEX IF EXISTS idx_messages_recipients_json;
DROP INDEX IF EXISTS idx_messages_from_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_from_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_cc_email_sort_trgm;

-- 3. Rename the new full indexes back to original names
ALTER INDEX idx_messages_subject_trgm_full RENAME TO idx_messages_subject_trgm;
ALTER INDEX idx_messages_recipients_json_full RENAME TO idx_messages_recipients_json;
ALTER INDEX idx_messages_from_email_sort_trgm_full RENAME TO idx_messages_from_email_sort_trgm;
ALTER INDEX idx_messages_from_name_sort_trgm_full RENAME TO idx_messages_from_name_sort_trgm;
ALTER INDEX idx_messages_to_email_sort_trgm_full RENAME TO idx_messages_to_email_sort_trgm;
ALTER INDEX idx_messages_to_name_sort_trgm_full RENAME TO idx_messages_to_name_sort_trgm;
ALTER INDEX idx_messages_cc_email_sort_trgm_full RENAME TO idx_messages_cc_email_sort_trgm;

-- 4. Re-apply fastupdate = off as was established in migration 000033
ALTER INDEX idx_messages_subject_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_recipients_json SET (fastupdate = off);
ALTER INDEX idx_messages_from_email_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_from_name_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_to_email_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_to_name_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_cc_email_sort_trgm SET (fastupdate = off);
