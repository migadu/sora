-- Credential revocations are transactionally recorded for every node. A change
-- is not ordered by its timestamp or BIGSERIAL id: transactions can commit out
-- of order, including after SET CONSTRAINTS has run a deferred trigger early.
-- writer_xid records the full writing transaction id. Readers use a primary
-- snapshot's xmin as a safe inclusive boundary and read ALL visible changes at
-- or above their acknowledged boundary, so late commits cannot be skipped.
--
-- changed_at is diagnostic only. first_observed_at is stamped by a primary
-- observer after the row is committed and visible; only that stamp permits
-- retention pruning. An arbitrarily old transaction must still get a full
-- retention interval once its event can actually be observed.
--
-- Production runbook. DROP TRIGGER takes an ACCESS EXCLUSIVE lock and CREATE TRIGGER a
-- SHARE ROW EXCLUSIVE lock on accounts and credentials. Both are brief, but a lock request
-- queued behind a long transaction on either table holds up every login behind it. On a
-- live database install the triggers out-of-band first, on the primary, not through
-- pgbouncer: run this file's statements in a session with
--   SET lock_timeout = '3s';
-- and retry on a lock timeout. Running binaries ignore the table; their credential writes
-- are recorded from then on. This migration then only inspects the catalog: it skips a
-- trigger that already exists on its table with the same name, function, timing, events
-- and deferral, and replaces any other trigger of that name.
CREATE TABLE IF NOT EXISTS credential_changes (
    id                BIGSERIAL PRIMARY KEY,
    account_id        BIGINT NOT NULL,
    ends_sessions     BOOLEAN NOT NULL,
    changed_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    writer_xid        BIGINT NOT NULL DEFAULT (pg_current_xact_id()::text::bigint),
    first_observed_at TIMESTAMPTZ
);

-- CREATE INDEX IF NOT EXISTS locks the table before it finds the index: check the catalog.
DO $$
BEGIN
    IF to_regclass('idx_credential_changes_writer_xid') IS NULL THEN
        CREATE INDEX idx_credential_changes_writer_xid ON credential_changes (writer_xid);
    END IF;
    IF to_regclass('idx_credential_changes_observed') IS NULL THEN
        CREATE INDEX idx_credential_changes_observed ON credential_changes (first_observed_at);
    END IF;
END $$;

CREATE OR REPLACE FUNCTION record_credential_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'accounts' THEN
        IF TG_OP = 'DELETE' THEN
            INSERT INTO credential_changes (account_id, ends_sessions) VALUES (OLD.id, TRUE);
        ELSE
            INSERT INTO credential_changes (account_id, ends_sessions) VALUES (NEW.id, TRUE);
        END IF;
    ELSE
        INSERT INTO credential_changes (account_id, ends_sessions) VALUES (OLD.account_id, FALSE);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- tgtype bits (pg_trigger.h): ROW 1, BEFORE 2, INSERT 4, DELETE 8, UPDATE 16.
-- AFTER UPDATE FOR EACH ROW is 17; AFTER DELETE FOR EACH ROW is 9.
DO $$
DECLARE
    fn oid := 'record_credential_change()'::regprocedure;
BEGIN
    -- A new password, or the address (or account) a credential signs in to.
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid = 'credentials'::regclass AND tgname = 'trigger_credentials_changed' AND NOT tgisinternal
                     AND tgfoid = fn AND tgtype = 17 AND tgdeferrable AND tginitdeferred) THEN
        DROP TRIGGER IF EXISTS trigger_credentials_changed ON credentials;
        CREATE CONSTRAINT TRIGGER trigger_credentials_changed
            AFTER UPDATE OF password, address, account_id ON credentials
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            WHEN (OLD.password IS DISTINCT FROM NEW.password
                  OR OLD.address IS DISTINCT FROM NEW.address
                  OR OLD.account_id IS DISTINCT FROM NEW.account_id)
            EXECUTE FUNCTION record_credential_change();
    END IF;

    -- A removed credential, including those an account purge or hard delete removes.
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid = 'credentials'::regclass AND tgname = 'trigger_credentials_removed' AND NOT tgisinternal
                     AND tgfoid = fn AND tgtype = 9 AND tgdeferrable AND tginitdeferred) THEN
        DROP TRIGGER IF EXISTS trigger_credentials_removed ON credentials;
        CREATE CONSTRAINT TRIGGER trigger_credentials_removed
            AFTER DELETE ON credentials
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION record_credential_change();
    END IF;

    -- An account taken out of service: soft-deleted, or marked for purging (which sets
    -- deleted_at as well).
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid = 'accounts'::regclass AND tgname = 'trigger_accounts_out_of_service' AND NOT tgisinternal
                     AND tgfoid = fn AND tgtype = 17 AND tgdeferrable AND tginitdeferred) THEN
        DROP TRIGGER IF EXISTS trigger_accounts_out_of_service ON accounts;
        CREATE CONSTRAINT TRIGGER trigger_accounts_out_of_service
            AFTER UPDATE OF deleted_at ON accounts
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
            EXECUTE FUNCTION record_credential_change();
    END IF;

    -- Direct SQL can hard-delete an active account without a soft-delete update.
    -- Cascaded credential deletions alone invalidate caches but do not end sessions.
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                   WHERE tgrelid = 'accounts'::regclass AND tgname = 'trigger_accounts_removed' AND NOT tgisinternal
                     AND tgfoid = fn AND tgtype = 9 AND tgdeferrable AND tginitdeferred) THEN
        DROP TRIGGER IF EXISTS trigger_accounts_removed ON accounts;
        CREATE CONSTRAINT TRIGGER trigger_accounts_removed
            AFTER DELETE ON accounts
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW
            EXECUTE FUNCTION record_credential_change();
    END IF;
END $$;
