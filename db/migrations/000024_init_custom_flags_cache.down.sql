-- Revert migration 024: Remove custom_flags_cache initialization from trigger
--
-- This reverts the trigger back to not initializing custom_flags_cache,
-- but does NOT remove the backfilled data (that would be destructive).

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

    ELSIF TG_OP = 'UPDATE' THEN
        -- Track changes in message count (expunge status changes)
        IF (OLD.expunged_at IS NULL) != (NEW.expunged_at IS NULL) THEN
            IF NEW.expunged_at IS NULL THEN
                count_delta := 1;
                size_delta := NEW.size;
            ELSE
                count_delta := -1;
                size_delta := -NEW.size;
            END IF;
        END IF;

        -- Track changes in unseen count (flags changes)
        IF (OLD.flags & 1) != (NEW.flags & 1) AND NEW.expunged_at IS NULL THEN
            IF (NEW.flags & 1) = 0 THEN
                unseen_delta := 1; -- became unseen
            ELSE
                unseen_delta := -1; -- became seen
            END IF;
        END IF;
    END IF;

    -- No changes to track
    IF count_delta = 0 AND unseen_delta = 0 AND size_delta = 0 THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
    END IF;

    -- Insert or update mailbox_stats (without custom_flags_cache initialization)
    INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
    VALUES (v_mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now())
    ON CONFLICT (mailbox_id) DO UPDATE SET
        message_count = mailbox_stats.message_count + count_delta,
        unseen_count = mailbox_stats.unseen_count + unseen_delta,
        total_size = mailbox_stats.total_size + size_delta,
        highest_modseq = GREATEST(mailbox_stats.highest_modseq, modseq_val),
        updated_at = now();

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
