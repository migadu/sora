-- An upload writes its body to S3 without holding the object's lock (it passes a one-
-- statement gate first), so while the body is in flight its pending_uploads row is the
-- only thing keeping every deleter away from it: the orphan re-check refuses any body
-- that still has a pending row. The row is therefore leased to the upload in flight:
--
--   lease_until  until when the lease holds; the upload extends it while the transfer
--                runs, and clears it when it finishes or fails.
--   lease_owner  the one upload attempt holding it. The gate grants a lease only when no
--                other is live, and renewal, release and the finalize act only for the
--                owner, so two workers that leased the same row (a re-armed delivery on
--                another node) can never both write, or one finalize under the other.
--
-- Account deletion leaves a row with a live lease alone, and the worker does not lease
-- it a second time.
--
-- Nullable with no default: a catalog-only change, no table rewrite.

ALTER TABLE pending_uploads
    ADD COLUMN IF NOT EXISTS lease_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS lease_owner TEXT;
