-- Every way a login stops working, recorded where every node can read it. Nodes cache
-- logins (the proxies' persistent auth cache, the in-memory lookup caches) and hold
-- sessions; each reads this table every few seconds and drops what it cached of a changed
-- account, and ends the sessions of an account taken out of service. Triggers write the
-- rows, so a change counts however it is made: the Admin API on any node, sora-admin,
-- or plain SQL.
--
--   account_id     the account whose cached logins are stale. No foreign key: the row
--                  must outlive the account it names.
--   ends_sessions  the account was taken out of service (deleted, or marked for
--                  purging): its open sessions end too. A password change or a removed
--                  credential leaves sessions alone, as the Admin API always has.
--   changed_at     clock_timestamp() rather than now(): a reader that has already moved
--                  past a row's time can only miss it while the writing transaction is
--                  still open, so the earlier the time, the wider the gap. Readers go
--                  back a window on every read to cover it.
--
-- Any change of the stored hash is recorded, a transparent rehash at login included:
-- telling a rehash from a real change would mean trusting every writer to say which it
-- is, and a rehash costs the account no more than one uncached login.
--
-- Rows are pruned after a week (credchanges.Retention), which bounds the persistent
-- auth cache's max_age: a node that restarts reads back as far as that cache reaches.
CREATE TABLE IF NOT EXISTS credential_changes (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL,
    ends_sessions BOOLEAN NOT NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_credential_changes_changed_at ON credential_changes (changed_at);

CREATE OR REPLACE FUNCTION record_credential_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'accounts' THEN
        INSERT INTO credential_changes (account_id, ends_sessions) VALUES (NEW.id, TRUE);
    ELSE
        INSERT INTO credential_changes (account_id, ends_sessions) VALUES (OLD.account_id, FALSE);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- A new password, or the address (or account) a credential signs in to.
DROP TRIGGER IF EXISTS trigger_credentials_changed ON credentials;
CREATE TRIGGER trigger_credentials_changed
    AFTER UPDATE OF password, address, account_id ON credentials
    FOR EACH ROW
    WHEN (OLD.password IS DISTINCT FROM NEW.password
          OR OLD.address IS DISTINCT FROM NEW.address
          OR OLD.account_id IS DISTINCT FROM NEW.account_id)
    EXECUTE FUNCTION record_credential_change();

-- A removed credential, including those an account purge or hard delete removes.
DROP TRIGGER IF EXISTS trigger_credentials_removed ON credentials;
CREATE TRIGGER trigger_credentials_removed
    AFTER DELETE ON credentials
    FOR EACH ROW
    EXECUTE FUNCTION record_credential_change();

-- An account taken out of service: soft-deleted, or marked for purging (which sets
-- deleted_at as well).
DROP TRIGGER IF EXISTS trigger_accounts_out_of_service ON accounts;
CREATE TRIGGER trigger_accounts_out_of_service
    AFTER UPDATE OF deleted_at ON accounts
    FOR EACH ROW
    WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
    EXECUTE FUNCTION record_credential_change();
