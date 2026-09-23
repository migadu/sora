-- Irreversible by design: the removed keywords were not encodable as IMAP flags,
-- so there is no correct state to restore them to, and restoring them would make
-- the affected mailboxes unopenable again. Nothing to undo.
SELECT 1;
