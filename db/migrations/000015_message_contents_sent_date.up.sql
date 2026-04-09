-- Add sent_date to message_contents so FTS/header retention can be determined
-- from a single table without joining back to messages.
--
-- The value is populated at INSERT time from the message's sent_date (Date header).
-- Because the INSERT uses ON CONFLICT (content_hash) DO NOTHING, shared content
-- (same bytes delivered to multiple users, e.g. newsletters) retains the sent_date
-- of the first copy — which is correct since the Date header is identical across
-- all copies of the same message.
--
-- ── LOCKING / PERFORMANCE NOTES ────────────────────────────────────────────
-- This migration is intentionally split into two safe, fast operations:
--
-- 1. ALTER TABLE ADD COLUMN: PostgreSQL 11+ adds a nullable column with no
--    DEFAULT as a catalog-only change — instant, with only a brief
--    ACCESS EXCLUSIVE lock on the system catalog. No table rewrite, no row scan.
--
-- 2. CREATE INDEX (partial, WHERE sent_date IS NOT NULL): Because all existing
--    rows have sent_date = NULL immediately after the ADD COLUMN, the partial
--    index has ZERO qualifying rows to scan. The SHARE lock held during index
--    build is therefore released in milliseconds even on a table with millions
--    of rows. New rows inserted after this migration will be indexed as they
--    arrive.
--
-- ── BACK-FILL ───────────────────────────────────────────────────────────────
-- The inline UPDATE back-fill was deliberately removed.
-- Reason: a single UPDATE joining message_contents × messages in a transaction
-- takes minutes-to-hours on large tables and holds ROW EXCLUSIVE locks on every
-- row for the entire duration, blocking concurrent writes.
--
-- Existing rows (sent_date = NULL) are silently excluded from
-- PruneOldMessageVectors (NULL < threshold evaluates to NULL, i.e. false), so
-- they are never accidentally pruned. This is safe: those rows existed before
-- this retention feature and will remain until they become orphaned and are
-- removed by GetUnusedContentHashes.
--
-- If you want to back-fill existing rows (to make them eligible for future
-- pruning), run the following OUTSIDE sora, in small batches during a
-- maintenance window:
--
-- #!/usr/bin/env bash
-- set -euo pipefail

-- # Connection — set these or use PGPASSWORD + command-line args
-- DB_HOST="${PGHOST:-localhost}"
-- DB_NAME="${PGDATABASE:-sora}"
-- DB_USER="${PGUSER:-sora}"
-- PSQL="psql -h $DB_HOST -U $DB_USER -d $DB_NAME -qtAX"

-- BATCH=50000
-- CUR=0
-- TOTAL=0
-- N=0

-- MAX=$($PSQL -c "SELECT COALESCE(MAX(id),0) FROM messages")
-- echo "Max message ID: $MAX"
-- [ "$MAX" -eq 0 ] && { echo "Nothing to do."; exit 0; }

-- while [ "$CUR" -lt "$MAX" ]; do
--   NEXT=$((CUR + BATCH))
--   N=$((N + 1))

--   ROWS=$($PSQL <<SQL
--     WITH batch AS (
--       SELECT content_hash, MIN(sent_date) AS sd
--       FROM messages
--       WHERE id > $CUR AND id <= $NEXT
--       GROUP BY content_hash
--     )
--     UPDATE message_contents mc
--     SET sent_date = batch.sd
--     FROM batch
--     WHERE mc.content_hash = batch.content_hash
--       AND mc.sent_date IS NULL
--     RETURNING 1;
-- SQL
--   )
--   ROWS=$(echo "$ROWS" | grep -c '1' || true)

--   TOTAL=$((TOTAL + ROWS))
--   CUR=$NEXT
--   echo "Batch $N (IDs ≤ $CUR): $ROWS rows. Total: $TOTAL"
--   sleep 0.01
-- done

-- echo "Done. Total updated: $TOTAL"


ALTER TABLE message_contents ADD COLUMN IF NOT EXISTS sent_date timestamptz;

-- Index used by PruneOldMessageVectors: range scan on sent_date for expired rows.
-- Partial index (WHERE sent_date IS NOT NULL) excludes null rows (existing rows
-- without a back-fill) so they are never accidentally deleted.
-- Because all existing rows have sent_date = NULL immediately after ADD COLUMN,
-- the initial index build scans zero rows and completes in milliseconds.
CREATE INDEX IF NOT EXISTS idx_message_contents_sent_date
    ON message_contents (sent_date)
    WHERE sent_date IS NOT NULL;
