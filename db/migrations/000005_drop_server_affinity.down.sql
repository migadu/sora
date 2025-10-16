-- Recreate server_affinity table (rollback migration)
-- Note: This recreates the table structure, but historical affinity data will be lost.

CREATE TABLE server_affinity (
    account_id BIGINT NOT NULL,
    is_prelookup_account BOOLEAN NOT NULL DEFAULT FALSE,
    last_server_addr VARCHAR(255) NOT NULL,
    last_server_time TIMESTAMP WITH TIME ZONE NOT NULL,
    PRIMARY KEY (account_id, is_prelookup_account)
);

-- Index for faster lookups by last_server_addr (e.g., for maintenance)
CREATE INDEX idx_server_affinity_last_server_addr ON server_affinity(last_server_addr);
