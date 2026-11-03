-- What each node reports about its own sessions that must finish before it stops: IMAP
-- sessions that have authenticated (APPEND, COPY and MOVE stage uploads), LMTP transactions and
-- Admin API deliveries in flight, and POP3 sessions that have authenticated (a POP3 session
-- applies its deletions at QUIT). Keyed by the uploader instance id, the owner of every upload
-- such a session stages (see instance_heartbeats).
--
-- `sora-admin backends ... --wait` reads it to decide when a backend in maintenance is
-- safe to stop. An empty upload queue alone proves nothing while a session that can still
-- APPEND is open, and only the node itself sees every such session, including those that
-- did not come through a proxy.
--
--   open_sessions     open when the row was written.
--   started_sessions  started since counting_since: a counter, so a session that started
--                     and ended between two reports still shows.
--   counting_since    when the reporting process started counting; a restart begins a new
--                     count.
--   reported_at       written every few seconds by the node (database clock). A row that
--                     stopped advancing comes from a node that stopped reporting, and an
--                     instance with no row at all runs a build that does not report.
--
-- One row per instance, rewritten in place.
CREATE TABLE IF NOT EXISTS instance_sessions (
    instance_id      TEXT PRIMARY KEY,
    open_sessions    BIGINT NOT NULL,
    started_sessions BIGINT NOT NULL,
    counting_since   TIMESTAMPTZ NOT NULL,
    reported_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
