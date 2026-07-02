-- RFC 3501 §6.3.6 / RFC 9051 §6.3.7: mailbox subscriptions are NAME-based and
-- decoupled from mailbox existence. Previously subscription was a BOOLEAN
-- `subscribed` column on the `mailboxes` row, which conflated the two: SUBSCRIBE
-- to a nonexistent name persisted nothing, and a subscription could not survive
-- its mailbox's deletion (so LSUB / LIST (SUBSCRIBED) could not report it, with
-- \NonExistent). This table is the authoritative subscription store going forward.
--
-- The `mailboxes.subscribed` column is intentionally LEFT IN PLACE (vestigial) for
-- rollback safety; a later migration drops it once this is proven.
--
-- Case-insensitive to agree with mailbox-name uniqueness (migration 000041 uses
-- UNIQUE(account_id, LOWER(name))). No prod pre-step is needed: mailbox names are
-- already case-unique per account, so the backfill below cannot collide.

CREATE TABLE IF NOT EXISTS subscriptions (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id   BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_name TEXT   NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One subscription per (account, case-insensitive name).
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_account_lname_unique
    ON subscriptions (account_id, LOWER(mailbox_name));

-- Backfill from the existing per-row subscription flag so current subscriptions
-- (including the auto-subscribed default mailboxes) are preserved.
INSERT INTO subscriptions (account_id, mailbox_name)
SELECT account_id, name
FROM mailboxes
WHERE subscribed = TRUE AND deleted_at IS NULL
ON CONFLICT DO NOTHING;
