-- Migration 024: Initialize custom_flags_cache for new mailbox_stats rows
--
-- Problem: The maintain_mailbox_stats() trigger creates new mailbox_stats rows
-- with custom_flags_cache = NULL, causing expensive LATERAL queries to run
-- on every SELECT until the custom_flags_cache trigger populates it.
--
-- Solution: Change column default to '[]'::jsonb so all new rows are initialized automatically.

-- First, backfill existing NULL entries
UPDATE mailbox_stats
SET custom_flags_cache = '[]'::jsonb
WHERE custom_flags_cache IS NULL;

-- Change column default from NULL to '[]'::jsonb
-- This ensures ALL future INSERTs get '[]' automatically, even outside the trigger
ALTER TABLE mailbox_stats
ALTER COLUMN custom_flags_cache SET DEFAULT '[]'::jsonb;

-- Now modify the trigger to use COALESCE on conflict (for pre-existing rows)
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

    -- Insert or update mailbox_stats
    -- NOTE: custom_flags_cache now has DEFAULT '[]'::jsonb, so we don't need to set it explicitly
    -- We only need COALESCE in the ON CONFLICT to catch pre-existing NULL rows
    INSERT INTO mailbox_stats (mailbox_id, message_count, unseen_count, total_size, highest_modseq, updated_at)
    VALUES (v_mailbox_id, count_delta, unseen_delta, size_delta, modseq_val, now())
    ON CONFLICT (mailbox_id) DO UPDATE SET
        message_count = mailbox_stats.message_count + count_delta,
        unseen_count = mailbox_stats.unseen_count + unseen_delta,
        total_size = mailbox_stats.total_size + size_delta,
        highest_modseq = GREATEST(mailbox_stats.highest_modseq, modseq_val),
        updated_at = now(),
        custom_flags_cache = COALESCE(mailbox_stats.custom_flags_cache, '[]'::jsonb);

    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$ LANGUAGE plpgsql;
