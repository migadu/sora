-- A backend host taken out of rotation for maintenance. An operator marks it with
-- `sora-admin backends maintenance on`; every proxy polls this table and stops routing
-- new sessions to a listed host, while the host itself keeps running.
--
-- It keeps running because it cannot simply be stopped: a pending_upload is leased only
-- by the instance that created it (its body sits on that node's local disk), so the host
-- must stay up until its own upload backlog has drained. instance_id names that backlog
-- (the host's uploader instance id, which is not necessarily its hostname), and the CLI
-- reads pending_uploads by it to report when the host is safe to stop.
--
--   host        the backend as proxies address it, normalized by the caller (lower case,
--               no port), so one row covers every protocol port on the host.
--   created_at  when maintenance began; marking a host again keeps it, so a repeated
--               `on` does not reset how long the host has been draining.
--
-- A handful of rows at most, read whole by every proxy: the primary key is the only index.
CREATE TABLE IF NOT EXISTS backend_maintenance (
    host        TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
