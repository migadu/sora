-- Drop server_affinity table and index
-- This table was used for database-based affinity tracking, which has been replaced
-- by gossip-based cluster affinity (in-memory only, no database storage needed).

DROP INDEX IF EXISTS idx_server_affinity_last_server_addr;
DROP TABLE IF EXISTS server_affinity;
