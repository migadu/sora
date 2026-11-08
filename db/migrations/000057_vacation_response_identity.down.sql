-- Distinct identities may have identical response timestamps. The old schema
-- cannot represent those duplicates, so retain one historical record per key.
DELETE FROM vacation_responses old
USING vacation_responses newer
WHERE old.account_id = newer.account_id
  AND old.sender_address = newer.sender_address
  AND old.response_date = newer.response_date
  AND old.id < newer.id;
ALTER TABLE vacation_responses
    DROP CONSTRAINT vacation_responses_identity_date_key,
    ADD CONSTRAINT vacation_responses_account_id_sender_address_response_date_key
        UNIQUE (account_id, sender_address, response_date);
ALTER TABLE vacation_responses DROP COLUMN response_identity;
