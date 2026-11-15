-- Irreversible by design: the original spelling of a folded name is not kept,
-- and the rows deleted as duplicates were unreachable through IMAP. The folded
-- names are what every binary since IMAP case folding writes, so there is
-- nothing to undo.
SELECT 1;
