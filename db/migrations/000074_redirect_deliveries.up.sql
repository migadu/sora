-- The redirect targets each MTA delivery has handed to the relay queue (#1912).
--
-- An MTA that does not see the 250 of a delivery (the connection is lost after the reply)
-- delivers the same message again, possibly to another node. Its stored copy is absorbed by
-- messages.delivery_hash (migration 47); a Sieve redirect is not stored anywhere a retry
-- could find it, so it was queued once per attempt. A row here says "this account's
-- delivery of these bytes has already been queued for this target": a retry skips that
-- target. delivery_hash is the same identity as messages.delivery_hash, BLAKE3 of the
-- message bytes exactly as received, so a different message that merely shares a
-- Message-ID is redirected as usual, and a message without one is still recognised.
--
-- Rows are written after the redirect is handed over and age out with redirect_log's
-- retention (the cleaner, CleanupOldRedirects). No foreign key, as for redirect_log: the
-- rows of a deleted account expire with the rest. A new, empty table: no lock concerns.
CREATE TABLE IF NOT EXISTS redirect_deliveries (
    account_id BIGINT NOT NULL,
    delivery_hash VARCHAR(64) NOT NULL,
    redirect_to TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, delivery_hash, redirect_to)
);

CREATE INDEX IF NOT EXISTS redirect_deliveries_created_at_idx ON redirect_deliveries (created_at);
