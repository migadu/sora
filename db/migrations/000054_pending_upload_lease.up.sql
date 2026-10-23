-- An upload writes its body to S3 without holding the object's lock (it passes a one-
-- statement gate first), so while the body is in flight its pending_uploads row is the
-- only thing keeping every deleter away from it: the orphan re-check refuses any body
-- that still has a pending row. lease_until marks the row as owned by an upload in
-- flight. The uploader sets it when it passes the gate, extends it while the transfer
-- runs, and clears it if the upload fails; account deletion leaves a leased row alone,
-- and the worker does not lease it a second time.
--
-- Nullable with no default: a catalog-only change, no table rewrite.

ALTER TABLE pending_uploads ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ;
