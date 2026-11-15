-- Delete METADATA (RFC 5464) rows stored under the scope roots /private/ and
-- /shared/ before IMAP refused those names.
--
-- RFC 5464 §3.2: an entry name "MUST NOT end with a "/" character", and
-- "Invalid entry names result in a BAD response in any IMAP command in which
-- they are used". Older binaries accepted the two scope roots as entry names
-- (go-imap's parser exempted them from the trailing-slash rule), so SETMETADATA
-- stored rows literally named /private/ or /shared/, in either scope. No
-- command can read or delete such a row any more, yet it counts toward the
-- account's [metadata] entry and size limits. There is no valid name to move
-- the value to, so the row is deleted.
--
-- These are the only invalid names that could have been stored: every binary
-- refused names outside /private/ and /shared/, "//", any other trailing "/",
-- and "*" or "%", and migration 000064 folded the upper-case ones.

DELETE FROM metadata
WHERE entry_name IN ('/private/', '/shared/');
