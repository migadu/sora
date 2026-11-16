-- Track the immutable version installed when a message_state row is created.
-- Adding a nullable column without a default leaves existing states unknown:
-- no historical row rewrite or backfill is needed. Their flag updates continue
-- to be reported conservatively. Every writer, including an older server, gets
-- the initial version from its actual INSERT, not from a guessed sequence gap.
ALTER TABLE message_state ADD COLUMN IF NOT EXISTS initial_modseq BIGINT;

CREATE OR REPLACE FUNCTION preserve_message_state_initial_modseq()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.initial_modseq := NEW.updated_modseq;
    ELSE
        -- Preserve NULL too: a later UPDATE cannot reconstruct a legacy birth.
        NEW.initial_modseq := OLD.initial_modseq;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_message_state_initial_modseq ON message_state;
CREATE TRIGGER trigger_message_state_initial_modseq
    BEFORE INSERT OR UPDATE ON message_state
    FOR EACH ROW EXECUTE FUNCTION preserve_message_state_initial_modseq();
