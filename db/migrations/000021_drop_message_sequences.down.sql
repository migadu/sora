-- Drop the partial index added in the up migration
DROP INDEX IF EXISTS idx_messages_mailbox_uid_active;

-- Re-create the message_sequences table
CREATE TABLE message_sequences (
    mailbox_id BIGINT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid BIGINT NOT NULL,
    seqnum INT NOT NULL,
    PRIMARY KEY (mailbox_id, uid),
    UNIQUE (mailbox_id, seqnum)
);

-- Repopulate it
INSERT INTO message_sequences (mailbox_id, uid, seqnum)
SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (PARTITION BY m.mailbox_id ORDER BY m.uid)
FROM messages m
WHERE m.expunged_at IS NULL AND m.mailbox_id IS NOT NULL;

CREATE OR REPLACE FUNCTION maintain_message_sequences()
RETURNS TRIGGER AS
$$
DECLARE
    v_mailbox_id BIGINT;
    affected_mailboxes_query TEXT;
    should_run BOOLEAN;
    v_insert_count INT;
    v_has_expunged BOOLEAN;
    v_new_uid BIGINT;
    v_max_existing_uid BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT COUNT(*), bool_or(expunged_at IS NOT NULL)
        INTO v_insert_count, v_has_expunged
        FROM new_table;

        IF v_insert_count = 1 AND NOT COALESCE(v_has_expunged, FALSE) THEN
            SELECT mailbox_id, uid INTO v_mailbox_id, v_new_uid
            FROM new_table WHERE mailbox_id IS NOT NULL;

            IF v_mailbox_id IS NOT NULL THEN
                PERFORM pg_advisory_xact_lock(v_mailbox_id);

                SELECT MAX(uid) INTO v_max_existing_uid
                FROM message_sequences WHERE mailbox_id = v_mailbox_id;

                IF v_new_uid > COALESCE(v_max_existing_uid, 0) THEN
                    INSERT INTO message_sequences (mailbox_id, uid, seqnum)
                    VALUES (v_mailbox_id, v_new_uid,
                            COALESCE((SELECT MAX(seqnum) FROM message_sequences WHERE mailbox_id = v_mailbox_id), 0) + 1)
                    ON CONFLICT (mailbox_id, uid) DO NOTHING;
                    RETURN NULL;
                END IF;
            END IF;
        END IF;

        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL';

    ELSIF TG_OP = 'DELETE' THEN
        affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';

    ELSE -- TG_OP = 'UPDATE'
        EXECUTE '
            SELECT EXISTS (
                SELECT 1 FROM old_table o JOIN new_table n ON o.id = n.id
                WHERE o.mailbox_id IS DISTINCT FROM n.mailbox_id
                   OR (o.expunged_at IS NULL) IS DISTINCT FROM (n.expunged_at IS NULL)
            )' INTO should_run;

        IF NOT should_run THEN RETURN NULL; END IF;

        EXECUTE '
            SELECT EXISTS (
                SELECT 1 FROM old_table o JOIN new_table n ON o.id = n.id
                WHERE o.mailbox_id IS DISTINCT FROM n.mailbox_id
            )' INTO should_run;

        IF NOT should_run THEN
            FOR v_mailbox_id IN SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL LOOP
                PERFORM pg_advisory_xact_lock(v_mailbox_id);

                EXECUTE '
                    SELECT EXISTS (
                        SELECT 1 FROM old_table o JOIN new_table n ON o.id = n.id
                        WHERE o.mailbox_id = $1 AND o.expunged_at IS NOT NULL AND n.expunged_at IS NULL
                    )' INTO should_run USING v_mailbox_id;

                IF should_run THEN
                    DELETE FROM message_sequences WHERE mailbox_id = v_mailbox_id;
                    INSERT INTO message_sequences (mailbox_id, uid, seqnum)
                    SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (ORDER BY m.uid)
                    FROM messages m WHERE m.mailbox_id = v_mailbox_id AND m.expunged_at IS NULL;
                    CONTINUE;
                END IF;

                DELETE FROM message_sequences ms USING old_table o, new_table n
                WHERE ms.mailbox_id = v_mailbox_id AND o.mailbox_id = v_mailbox_id AND ms.uid = o.uid AND o.id = n.id AND o.expunged_at IS NULL AND n.expunged_at IS NOT NULL;

                WITH shift_offsets AS (
                    SELECT ms.uid, ms.seqnum - ROW_NUMBER() OVER (ORDER BY ms.seqnum) AS shift_amount
                    FROM message_sequences ms WHERE ms.mailbox_id = v_mailbox_id
                )
                UPDATE message_sequences ms SET seqnum = -(ms.seqnum - so.shift_amount)
                FROM shift_offsets so WHERE ms.mailbox_id = v_mailbox_id AND ms.uid = so.uid AND so.shift_amount > 0;

                UPDATE message_sequences SET seqnum = -seqnum WHERE mailbox_id = v_mailbox_id AND seqnum < 0;
            END LOOP;
            RETURN NULL;
        END IF;

        affected_mailboxes_query := '
            SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL
            UNION
            SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
    END IF;

    FOR v_mailbox_id IN EXECUTE affected_mailboxes_query LOOP
        PERFORM pg_advisory_xact_lock(v_mailbox_id);
        DELETE FROM message_sequences WHERE mailbox_id = v_mailbox_id;
        INSERT INTO message_sequences (mailbox_id, uid, seqnum)
        SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (ORDER BY m.uid)
        FROM messages m WHERE m.mailbox_id = v_mailbox_id AND m.expunged_at IS NULL;
    END LOOP;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_maintain_message_sequences_insert
AFTER INSERT ON messages
REFERENCING NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();

CREATE TRIGGER trigger_maintain_message_sequences_update
AFTER UPDATE ON messages
REFERENCING OLD TABLE AS old_table NEW TABLE AS new_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();

CREATE TRIGGER trigger_maintain_message_sequences_delete
AFTER DELETE ON messages
REFERENCING OLD TABLE AS old_table
FOR EACH STATEMENT
EXECUTE FUNCTION maintain_message_sequences();
