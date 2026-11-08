-- Index for faster lookups by account_id and sender_address
CREATE INDEX idx_vacation_responses_account_sender ON vacation_responses (account_id, sender_address);
