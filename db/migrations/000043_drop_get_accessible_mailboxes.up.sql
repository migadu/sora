-- Remove the dead get_accessible_mailboxes() stored function.
--
-- It was introduced with the original ACL feature as a helper to list a user's
-- accessible mailboxes + rights, but was never wired to any handler. The live LIST
-- path uses db.GetMailboxes (an inline CTE with corrected semantics: it requires the
-- 'l' lookup right and includes shared mailboxes the user owns). The Go method
-- GetAccessibleMailboxes and its resilient wrapper — equally unused — are removed in
-- the same change. Drop the function so the schema no longer carries an orphaned,
-- slightly divergent copy of the accessibility logic.

DROP FUNCTION IF EXISTS get_accessible_mailboxes(BIGINT);
