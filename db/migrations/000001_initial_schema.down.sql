-- WARNING: This migration is DANGEROUS and will cause DATA LOSS!
-- It drops all tables and destroys the entire database schema.
--
-- This down migration is intentionally COMMENTED OUT to prevent accidental data loss.
-- If you really need to tear down the database, uncomment the statements below.
--
-- RECOMMENDED: Instead of using this migration, manually drop the database and recreate it.

/*
-- Drop all functions
DROP FUNCTION IF EXISTS get_accessible_mailboxes(BIGINT);
DROP FUNCTION IF EXISTS has_mailbox_right(BIGINT, BIGINT, CHAR);
DROP FUNCTION IF EXISTS maintain_mailbox_stats();
DROP FUNCTION IF EXISTS maintain_message_sequences();

-- Drop all triggers
DROP TRIGGER IF EXISTS trigger_messages_stats_update ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_delete ON messages;
DROP TRIGGER IF EXISTS trigger_messages_stats_insert ON messages;
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_delete ON messages;
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_update ON messages;
DROP TRIGGER IF EXISTS trigger_maintain_message_sequences_insert ON messages;

-- Drop all tables (in reverse dependency order)
DROP TABLE IF EXISTS mailbox_acls CASCADE;
DROP TABLE IF EXISTS metadata CASCADE;
DROP TABLE IF EXISTS cache_metrics CASCADE;
DROP TABLE IF EXISTS health_status CASCADE;
DROP TABLE IF EXISTS active_connections CASCADE;
DROP TABLE IF EXISTS locks CASCADE;
DROP TABLE IF EXISTS auth_attempts CASCADE;
DROP TABLE IF EXISTS vacation_responses CASCADE;
DROP TABLE IF EXISTS sieve_scripts CASCADE;
DROP TABLE IF EXISTS pending_uploads CASCADE;
DROP TABLE IF EXISTS message_contents CASCADE;
DROP TABLE IF EXISTS mailbox_stats CASCADE;
DROP TABLE IF EXISTS message_sequences CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS mailboxes CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;

-- Drop sequences
DROP SEQUENCE IF EXISTS messages_modseq;

-- Drop extensions
DROP EXTENSION IF EXISTS pg_trgm;
*/

-- Migration down blocked to prevent accidental data loss.
-- To tear down the schema, uncomment the statements above or drop the database manually.
