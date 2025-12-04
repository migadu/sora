-- Rollback: Remove to_name_sort column

-- Drop the index first
DROP INDEX IF EXISTS idx_messages_to_display_sort;

-- Drop the column
ALTER TABLE messages DROP COLUMN IF EXISTS to_name_sort;
