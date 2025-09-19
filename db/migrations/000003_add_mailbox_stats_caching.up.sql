-- This migration introduces a caching table for mailbox statistics
-- to avoid expensive COUNT(*) and SUM() queries on large mailboxes.

-- 1. Create the mailbox_stats table
-- This table will store pre-calculated statistics for each mailbox.
CREATE TABLE mailbox_stats (
    mailbox_id BIGINT PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
    message_count INT NOT NULL DEFAULT 0,
    unseen_count INT NOT NULL DEFAULT 0,
    total_size BIGINT NOT NULL DEFAULT 0,
    highest_modseq BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL
);

-- 2. Create the trigger function to maintain the cache
CREATE OR REPLACE FUNCTION maintain_mailbox_stats()
RETURNS TRIGGER AS $$
DECLARE
    v_mailbox_id BIGINT;
    count_delta INT := 0;
    unseen_delta INT := 0;
    size_delta BIGINT := 0;
    modseq_val BIGINT := 0;
BEGIN
    -- Determine which mailbox_id to use
    IF TG_OP = 'INSERT' THEN
        v_mailbox_id := NEW.mailbox_id;
    ELSE -- DELETE or UPDATE
        v_mailbox_id := OLD.mailbox_id;
    END IF;

    -- If mailbox_id is NULL, do nothing (e.g., message moved out of a deleted mailbox)
    IF v_mailbox_id IS NULL THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Calculate deltas based on operation
    IF TG_OP = 'INSERT' AND NEW.expunged_at IS NULL THEN
        count_delta := 1;
        size_delta := NEW.size;
        unseen_delta := 1 - (NEW.flags & 1); -- 1 if unseen, 0 if seen
        modseq_val := NEW.created_modseq;

    ELSIF TG_OP = 'DELETE' AND OLD.expunged_at IS NULL THEN
        count_delta := -1;
        size_delta := -OLD.size;
        unseen_delta := -(1 - (OLD.flags & 1));
        -- modseq is a high-water mark, not decreased on delete

    ELSIF TG_OP = 'UPDATE' THEN
        -- Case 1: Message is expunged (soft delete)
        IF OLD.expunged_at IS NULL AND NEW.expunged_at IS NOT NULL THEN
            count_delta := -1;
            size_delta := -OLD.size;
            unseen_delta := -(1 - (OLD.flags & 1));
            modseq_val := COALESCE(NEW.expunged_modseq, 0);
        -- Case 2: Message is restored (un-expunged)
        ELSIF OLD.expunged_at IS NOT NULL AND NEW.expunged_at IS NULL THEN
            count_delta := 1;
            size_delta := NEW.size;
            unseen_delta := 1 - (NEW.flags & 1);
            -- modseq is not changed on restore, it's a new state
        -- Case 3: Flags changed on an active message
        ELSIF OLD.expunged_at IS NULL AND NEW.expunged_at IS NULL AND OLD.flags != NEW.flags THEN
            unseen_delta := (1 - (NEW.flags & 1)) - (1 - (OLD.flags & 1));
            modseq_val := COALESCE(NEW.updated_modseq, 0);
        END IF;
    END IF;

    -- Apply the deltas if any change occurred
    IF count_delta != 0 OR size_delta != 0 OR unseen_delta != 0 OR modseq_val != 0 THEN
        INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
        VALUES (v_mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now())
        ON CONFLICT (mailbox_id) DO UPDATE SET
            message_count = mailbox_stats.message_count + count_delta,
            unseen_count = mailbox_stats.unseen_count + unseen_delta,
            total_size = mailbox_stats.total_size + size_delta,
            highest_modseq = GREATEST(mailbox_stats.highest_modseq, modseq_val),
            updated_at = now();
    END IF;

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;

-- 3. Create the triggers on the messages table
CREATE TRIGGER trigger_messages_stats_insert AFTER INSERT ON messages FOR EACH ROW EXECUTE FUNCTION maintain_mailbox_stats();
CREATE TRIGGER trigger_messages_stats_delete AFTER DELETE ON messages FOR EACH ROW EXECUTE FUNCTION maintain_mailbox_stats();
CREATE TRIGGER trigger_messages_stats_update AFTER UPDATE ON messages FOR EACH ROW WHEN (OLD.flags IS DISTINCT FROM NEW.flags OR OLD.expunged_at IS DISTINCT FROM NEW.expunged_at) EXECUTE FUNCTION maintain_mailbox_stats();

-- 4. Populate the mailbox_stats table for all existing mailboxes
-- This is a one-time operation to bootstrap the cache.
INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
SELECT
    m.mailbox_id,
    COUNT(m.id),
    COUNT(m.id) FILTER (WHERE (m.flags & 1) = 0),
    COALESCE(SUM(m.size), 0),
    COALESCE((SELECT MAX(modseq) FROM (SELECT created_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id UNION ALL SELECT updated_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id AND updated_modseq IS NOT NULL UNION ALL SELECT expunged_modseq as modseq FROM messages WHERE mailbox_id = m.mailbox_id AND expunged_modseq IS NOT NULL) as modseqs), 0),
    now()
FROM messages m
WHERE m.mailbox_id IS NOT NULL AND m.expunged_at IS NULL
GROUP BY m.mailbox_id;