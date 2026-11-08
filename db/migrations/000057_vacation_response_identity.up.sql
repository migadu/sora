-- Historical rows have no recoverable response identity. Retain them under an
-- empty legacy sentinel; new identities are nonempty opaque keys from go-sieve.
ALTER TABLE vacation_responses
    ADD COLUMN response_identity TEXT NOT NULL DEFAULT '';

ALTER TABLE vacation_responses
    DROP CONSTRAINT vacation_responses_account_id_sender_address_response_date_key,
    ADD CONSTRAINT vacation_responses_identity_date_key
        UNIQUE (account_id, sender_address, response_identity, response_date);
