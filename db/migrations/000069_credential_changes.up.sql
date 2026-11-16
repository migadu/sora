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
CREATE TABLE IF NOT EXISTS credential_changes (
    id                BIGSERIAL PRIMARY KEY,
    account_id        BIGINT NOT NULL,
    ends_sessions     BOOLEAN NOT NULL,
    changed_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    writer_xid        BIGINT NOT NULL DEFAULT (pg_current_xact_id()::text::bigint),
    first_observed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_credential_changes_writer_xid ON credential_changes (writer_xid);
CREATE INDEX IF NOT EXISTS idx_credential_changes_observed ON credential_changes (first_observed_at);

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

-- A new password, or the address (or account) a credential signs in to.
DROP TRIGGER IF EXISTS trigger_credentials_changed ON credentials;
CREATE CONSTRAINT TRIGGER trigger_credentials_changed
    AFTER UPDATE OF password, address, account_id ON credentials
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.password IS DISTINCT FROM NEW.password
          OR OLD.address IS DISTINCT FROM NEW.address
          OR OLD.account_id IS DISTINCT FROM NEW.account_id)
    EXECUTE FUNCTION record_credential_change();

-- A removed credential, including those an account purge or hard delete removes.
DROP TRIGGER IF EXISTS trigger_credentials_removed ON credentials;
CREATE CONSTRAINT TRIGGER trigger_credentials_removed
    AFTER DELETE ON credentials
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION record_credential_change();

-- An account taken out of service: soft-deleted, or marked for purging (which sets
-- deleted_at as well).
DROP TRIGGER IF EXISTS trigger_accounts_out_of_service ON accounts;
CREATE CONSTRAINT TRIGGER trigger_accounts_out_of_service
    AFTER UPDATE OF deleted_at ON accounts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION record_credential_change();

-- Direct SQL can hard-delete an active account without a soft-delete update.
-- Cascaded credential deletions alone invalidate caches but do not end sessions.
DROP TRIGGER IF EXISTS trigger_accounts_removed ON accounts;
CREATE CONSTRAINT TRIGGER trigger_accounts_removed
    AFTER DELETE ON accounts
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION record_credential_change();
