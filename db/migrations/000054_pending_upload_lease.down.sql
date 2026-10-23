-- Uploads in flight lose their lease; account deletion and the worker's lease go back to
-- ignoring whether an upload is in flight.

ALTER TABLE pending_uploads
    DROP COLUMN IF EXISTS lease_owner,
    DROP COLUMN IF EXISTS lease_until;
