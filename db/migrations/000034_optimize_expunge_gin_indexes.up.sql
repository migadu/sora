-- Migration: Optimize expunge latency by making GIN indexes partial
-- Expunging a message updates `expunged_at`, causing a non-HOT update.
-- This forces PostgreSQL to insert the new tuple into all GIN indexes.
-- By adding `WHERE expunged_at IS NULL` to these indexes, expunged
-- messages will bypass GIN insertion completely, eliminating latency spikes.

-- 1. Create partial GIN indexes concurrently
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm_partial ON messages USING gin (LOWER(subject) gin_trgm_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_recipients_json_partial ON messages USING GIN (recipients_json jsonb_path_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_from_email_sort_trgm_partial ON messages USING gin (from_email_sort gin_trgm_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_from_name_sort_trgm_partial ON messages USING gin (from_name_sort gin_trgm_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_to_email_sort_trgm_partial ON messages USING gin (to_email_sort gin_trgm_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_to_name_sort_trgm_partial ON messages USING gin (to_name_sort gin_trgm_ops) WHERE expunged_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_messages_cc_email_sort_trgm_partial ON messages USING gin (cc_email_sort gin_trgm_ops) WHERE expunged_at IS NULL;

-- 2. Drop the old full indexes concurrently
DROP INDEX IF EXISTS idx_messages_subject_trgm;
DROP INDEX IF EXISTS idx_messages_recipients_json;
DROP INDEX IF EXISTS idx_messages_from_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_from_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_email_sort_trgm;
DROP INDEX IF EXISTS idx_messages_to_name_sort_trgm;
DROP INDEX IF EXISTS idx_messages_cc_email_sort_trgm;

-- 3. Rename the new partial indexes to match the expected schema names
ALTER INDEX idx_messages_subject_trgm_partial RENAME TO idx_messages_subject_trgm;
ALTER INDEX idx_messages_recipients_json_partial RENAME TO idx_messages_recipients_json;
ALTER INDEX idx_messages_from_email_sort_trgm_partial RENAME TO idx_messages_from_email_sort_trgm;
ALTER INDEX idx_messages_from_name_sort_trgm_partial RENAME TO idx_messages_from_name_sort_trgm;
ALTER INDEX idx_messages_to_email_sort_trgm_partial RENAME TO idx_messages_to_email_sort_trgm;
ALTER INDEX idx_messages_to_name_sort_trgm_partial RENAME TO idx_messages_to_name_sort_trgm;
ALTER INDEX idx_messages_cc_email_sort_trgm_partial RENAME TO idx_messages_cc_email_sort_trgm;

-- 4. Re-apply fastupdate = off since the new indexes will default to fastupdate = on
ALTER INDEX idx_messages_subject_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_recipients_json SET (fastupdate = off);
ALTER INDEX idx_messages_from_email_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_from_name_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_to_email_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_to_name_sort_trgm SET (fastupdate = off);
ALTER INDEX idx_messages_cc_email_sort_trgm SET (fastupdate = off);
