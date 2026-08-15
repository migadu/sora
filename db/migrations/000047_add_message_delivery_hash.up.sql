-- Identify an MTA redelivery of the same upstream queue entry.
--
-- content_hash MUST remain BLAKE3(the exact bytes stored in S3): it is the S3 object
-- key, the local cache key, the upload-dedup key and what verify-content-hash re-hashes.
-- Both ingress paths (LMTP, Admin API) stamp their own Received: trace -- carrying a
-- per-attempt id and timestamp -- onto the message before hashing, so content_hash
-- necessarily differs between two attempts at the same mail and cannot detect a retry.
--
-- delivery_hash is BLAKE3 of the message bytes as received, before any local stamping,
-- and is therefore stable across attempts. For ingress that passes through an MTA, those
-- bytes still carry every upstream Received: header, so an exact match in one mailbox
-- means the same queue entry rather than merely similar mail. Ingress with no MTA hop in
-- front (the Admin API deliver endpoint, an application speaking LMTP directly) can
-- legitimately submit byte-identical mail twice; for those, delivery becomes idempotent.
--
-- NULL on every path that is not an MTA delivery (IMAP APPEND, importer, User API);
-- those keep their previous duplicate semantics.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivery_hash VARCHAR(64);

-- Backs the duplicate lookup in db.InsertMessage.
--
-- NOTE: migrations run as a single implicit transaction, so CONCURRENTLY cannot be used
-- here, and the ACCESS EXCLUSIVE lock taken by the ALTER above is held until COMMIT --
-- that is, across this whole index build, blocking reads as well as writes on `messages`.
-- The build scans the entire table even though the predicate matches no existing row.
-- On a large live table, do both steps out-of-band first so this migration no-ops
-- (both statements are IF NOT EXISTS):
--   ALTER TABLE messages ADD COLUMN IF NOT EXISTS delivery_hash VARCHAR(64);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_mailbox_delivery_hash
--     ON messages (mailbox_id, delivery_hash)
--     WHERE expunged_at IS NULL AND delivery_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_messages_mailbox_delivery_hash
    ON messages (mailbox_id, delivery_hash)
    WHERE expunged_at IS NULL AND delivery_hash IS NOT NULL;
