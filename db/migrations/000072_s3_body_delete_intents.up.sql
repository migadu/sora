-- A storage DELETE cannot be retracted when its PostgreSQL lock connection dies.
-- Persist its admission fence before sending the request. Unknown outcomes remain
-- quarantined until an operator has drained storage operations and reconciled them;
-- timestamps and leases are diagnostic, never permission to clear this fence.
CREATE TABLE s3_body_delete_intents (
    content_hash TEXT PRIMARY KEY CHECK (content_hash <> ''),
    operation_id UUID NOT NULL,
    object_keys TEXT[] NOT NULL CHECK (cardinality(object_keys) > 0),
    retire_snapshot JSONB NOT NULL CHECK (jsonb_typeof(retire_snapshot) = 'array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_error TEXT
);
