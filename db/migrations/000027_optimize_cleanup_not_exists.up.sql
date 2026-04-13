-- Migration 000027: Optimize cleanup NOT EXISTS queries
--
-- Problem: GetUserScopedObjectsForCleanup has two NOT EXISTS subqueries that check:
-- 1. Are there any active (non-expunged) messages with this (account_id, content_hash)?
-- 2. Are there any recently expunged messages with this (account_id, content_hash)?
--
-- The second query was doing a range scan on idx_messages_expunged_range, scanning
-- 400K+ rows to filter by expunged_at >= threshold.
--
-- Solution: Create a covering index with (account_id, content_hash) as leading columns,
-- so the NOT EXISTS can do an index-only scan on the specific (account_id, content_hash)
-- pair, then check expunged_at in the index without scanning the heap.

CREATE INDEX IF NOT EXISTS idx_messages_account_hash_expunged
ON messages (account_id, content_hash, expunged_at)
WHERE expunged_at IS NOT NULL;

-- This index supports:
-- 1. Fast lookup by (account_id, content_hash) in NOT EXISTS queries
-- 2. Direct filtering on expunged_at >= threshold without heap access
-- 3. Partial index keeps it small (only expunged messages)

-- Also optimize the FIRST NOT EXISTS query: (active messages check)
-- Without this, finding if a globally popular hash (like a corporate logo)
-- is active for a specific account requires scanning ALL active occurrences 
-- of that logo globally on the heap.
CREATE INDEX IF NOT EXISTS idx_messages_account_hash_active
ON messages (account_id, content_hash)
WHERE expunged_at IS NULL;
