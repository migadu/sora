-- Builds that predate the table drop cached logins only through connection trackers
-- (cluster gossip, or servers on the node that made the change).
DROP TRIGGER IF EXISTS trigger_accounts_out_of_service ON accounts;
DROP TRIGGER IF EXISTS trigger_credentials_removed ON credentials;
DROP TRIGGER IF EXISTS trigger_credentials_changed ON credentials;
DROP FUNCTION IF EXISTS record_credential_change();
DROP TABLE IF EXISTS credential_changes;
