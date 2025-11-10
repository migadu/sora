CREATE TABLE IF NOT EXISTS auth_attempts (
    id BIGSERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    username VARCHAR(255),
    protocol VARCHAR(20) NOT NULL,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip ON auth_attempts(ip_address, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_username ON auth_attempts(username, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_time ON auth_attempts(attempted_at DESC);
