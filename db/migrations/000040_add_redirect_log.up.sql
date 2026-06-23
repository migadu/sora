CREATE TABLE redirect_log (
    account_id BIGINT NOT NULL,
    redirect_date TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX redirect_log_account_date_idx ON redirect_log (account_id, redirect_date);
