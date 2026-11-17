-- Track the immutable version installed when a message_state row is created.
-- Adding a nullable column without a default leaves existing states unknown:
-- no historical row rewrite or backfill is needed. Their flag updates continue
-- to be reported conservatively. Every writer, including an older server, gets
-- the initial version from its actual INSERT, not from a guessed sequence gap.
--
-- Production runbook. ADD COLUMN and DROP TRIGGER take an ACCESS EXCLUSIVE lock, and CREATE
-- TRIGGER a SHARE ROW EXCLUSIVE lock, on message_state, which every flag change writes. All
-- are brief, but a lock request queued behind a long query holds up every query on
-- message_state behind it. ADD COLUMN IF NOT EXISTS takes its lock even when the column is
-- there, so the column is checked in the catalog instead. On a live database run this file's
-- statements out-of-band first, on the primary, not through pgbouncer, in a session with
--   SET lock_timeout = '3s';
-- and retry on a lock timeout. Running binaries ignore the column; the trigger stamps rows
-- they insert from then on. This migration then only inspects the catalog: it skips a
-- trigger that already exists with the same name, function, timing and events, and replaces
-- any other trigger of that name.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                   WHERE attrelid = 'message_state'::regclass AND attname = 'initial_modseq' AND NOT attisdropped) THEN
        ALTER TABLE message_state ADD COLUMN initial_modseq BIGINT;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION preserve_message_state_initial_modseq()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.initial_modseq := NEW.updated_modseq;
    ELSE
        -- Preserve NULL too: a later UPDATE cannot reconstruct a legacy birth.
        NEW.initial_modseq := OLD.initial_modseq;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- tgtype bits (pg_trigger.h): ROW 1 + BEFORE 2 + INSERT 4 + UPDATE 16 = 23.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid = 'message_state'::regclass AND tgname = 'trigger_message_state_initial_modseq'
                     AND NOT tgisinternal AND tgfoid = 'preserve_message_state_initial_modseq()'::regprocedure
                     AND tgtype = 23) THEN
        DROP TRIGGER IF EXISTS trigger_message_state_initial_modseq ON message_state;
        CREATE TRIGGER trigger_message_state_initial_modseq
            BEFORE INSERT OR UPDATE ON message_state
            FOR EACH ROW EXECUTE FUNCTION preserve_message_state_initial_modseq();
    END IF;
END $$;
