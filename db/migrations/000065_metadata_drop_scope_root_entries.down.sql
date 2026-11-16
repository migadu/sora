-- Irreversible by design: the deleted rows were named by no valid entry name,
-- so no command could read or delete them, and the current IMAP parser refuses them.
SELECT 1;
