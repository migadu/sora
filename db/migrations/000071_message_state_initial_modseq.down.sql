DROP TRIGGER IF EXISTS trigger_message_state_initial_modseq ON message_state;
DROP FUNCTION IF EXISTS preserve_message_state_initial_modseq();
ALTER TABLE message_state DROP COLUMN IF EXISTS initial_modseq;
