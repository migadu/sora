-- Simplify the maintain_message_sequences trigger function
-- Remove unnecessary EXECUTE wrapper for direct SELECT statements

CREATE OR REPLACE FUNCTION maintain_message_sequences()
RETURNS TRIGGER AS
$$
DECLARE
    v_mailbox_id BIGINT;
    affected_mailboxes_query TEXT;
    should_run BOOLEAN;
BEGIN
    -- This trigger function rebuilds the sequence numbers for affected mailboxes.

    IF TG_OP = 'INSERT' OR TG_OP = 'DELETE' THEN
        should_run := TRUE;
        IF TG_OP = 'INSERT' THEN
            affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL';
        ELSE -- TG_OP = 'DELETE'
            affected_mailboxes_query := 'SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
        END IF;
    ELSE -- TG_OP = 'UPDATE'
        -- For UPDATE, we only run the rebuild if sequencing-related columns have changed.
        -- This avoids expensive rebuilds for simple flag changes.
        -- Note: We don't check uid because it's immutable (part of UNIQUE INDEX on mailbox_id, uid).
        SELECT EXISTS (
            SELECT 1
            FROM old_table o
            JOIN new_table n ON o.id = n.id
            WHERE o.mailbox_id IS DISTINCT FROM n.mailbox_id
               OR (o.expunged_at IS NULL) IS DISTINCT FROM (n.expunged_at IS NULL)
        )
        INTO should_run;

        IF should_run THEN
            -- If relevant columns changed, we need to rebuild for both old and new mailboxes (in case of a move).
            affected_mailboxes_query := '
                SELECT DISTINCT mailbox_id FROM new_table WHERE mailbox_id IS NOT NULL
                UNION
                SELECT DISTINCT mailbox_id FROM old_table WHERE mailbox_id IS NOT NULL';
        END IF;
    END IF;

    -- If no relevant changes occurred, exit.
    IF NOT should_run THEN
        RETURN NULL;
    END IF;

    -- Process all affected mailboxes
    FOR v_mailbox_id IN EXECUTE affected_mailboxes_query LOOP
        -- Lock the mailbox to prevent concurrent modifications from other transactions.
        PERFORM pg_advisory_xact_lock(v_mailbox_id);

        -- Atomically rebuild the sequence numbers for the entire mailbox.
        -- This is more robust and often faster for bulk operations than per-row adjustments.
        DELETE FROM message_sequences WHERE mailbox_id = v_mailbox_id;
        INSERT INTO message_sequences (mailbox_id, uid, seqnum)
        SELECT m.mailbox_id, m.uid, ROW_NUMBER() OVER (ORDER BY m.uid)
        FROM messages m
        WHERE m.mailbox_id = v_mailbox_id AND m.expunged_at IS NULL;
    END LOOP;

    RETURN NULL; -- Result is ignored for AFTER STATEMENT triggers.
END;
$$ LANGUAGE plpgsql;
