-- Liveness signal for the instances that own local upload spool files.
--
-- A pending_upload is leased only by the instance that created it
-- (db/upload_worker.go: "WHERE instance_id = $1"), because the message body sits on
-- that node's local disk and no other node can upload it. An unfinished upload
-- therefore means one of two opposite things, and the reaper in
-- db.CleanupFailedUploads must tell them apart:
--
--   * the owning instance is alive and still retrying (attempts < max_attempts):
--     the bytes are recoverable once S3 returns, so the message must NEVER be
--     reaped, however old it is;
--   * the owning instance is gone (decommissioned, renamed, disk destroyed):
--     nothing will ever upload those bytes, so the message rows and their
--     pending_uploads rows may be reaped once past the cleanup grace period.
--
-- Every uploader refreshes its own row here (server/uploader/worker.go). A row that
-- has not been refreshed within cleanup.instance_liveness_threshold is positive
-- proof of the second case. The ABSENCE of a row proves nothing (the instance may
-- predate this table, or run an older build) and never permits reaping.
CREATE TABLE IF NOT EXISTS instance_heartbeats (
    instance_id TEXT PRIMARY KEY,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
