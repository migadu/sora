-- Drop tables in reverse order of creation to respect foreign key constraints.
-- Using CASCADE simplifies this by automatically dropping dependent objects.
DROP TABLE IF EXISTS cache_metrics CASCADE;
DROP TABLE IF EXISTS health_status CASCADE;
DROP TABLE IF EXISTS active_connections CASCADE;
DROP TABLE IF EXISTS locks CASCADE;
DROP TABLE IF EXISTS auth_attempts CASCADE;
DROP TABLE IF EXISTS vacation_responses CASCADE;
DROP TABLE IF EXISTS sieve_scripts CASCADE;
DROP TABLE IF EXISTS pending_uploads CASCADE;
DROP TABLE IF EXISTS message_contents CASCADE;
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS mailboxes CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS server_affinity CASCADE;
DROP TABLE IF EXISTS accounts CASCADE;

-- Drop the sequence used for modseq
DROP SEQUENCE IF EXISTS messages_modseq;

-- Drop the extension if it's no longer needed by other parts of the database
DROP EXTENSION IF EXISTS pg_trgm;
