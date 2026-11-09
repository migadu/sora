-- idx_vacation_responses_account_sender on (account_id, sender_address), from the
-- initial schema, is a strict prefix of the unique constraint
-- vacation_responses_identity_date_key added in 000057 on
-- (account_id, sender_address, response_identity, response_date). Every lookup it
-- served is answered by the unique index; it only cost a write per row.
DROP INDEX IF EXISTS idx_vacation_responses_account_sender;
