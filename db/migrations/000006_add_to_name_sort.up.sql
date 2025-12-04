-- Migration: Add to_name_sort column for RFC 5256 DISPLAYTO support
-- This enables proper sorting by TO display name (with fallback to email)

-- Add to_name_sort column to messages table
ALTER TABLE messages ADD COLUMN IF NOT EXISTS to_name_sort TEXT;

-- Create index for DISPLAYTO sorting (with COALESCE fallback)
-- This matches the pattern used for DISPLAYFROM
CREATE INDEX IF NOT EXISTS idx_messages_to_display_sort
ON messages (mailbox_id, COALESCE(to_name_sort, to_email_sort))
WHERE expunged_at IS NULL;

-- Add comment explaining the column
COMMENT ON COLUMN messages.to_name_sort IS 'Normalized TO display name for RFC 5256 DISPLAYTO sorting. NULL if no display name available.';
