package helpers

import (
	"strings"
	"unicode/utf8"

	"github.com/migadu/sora/consts"
)

// CanonicalMailboxName normalizes the reserved INBOX name to its canonical
// spelling. Per RFC 3501 §5.1, "INBOX" is reserved and case-insensitive, so a
// freshly-created inbox must always be stored as exactly "INBOX" regardless of
// the case the client used.
//
// Sora treats all mailbox names case-insensitively (Option A): the
// UNIQUE(account_id, LOWER(name)) index and the LOWER(name) lookups guarantee a
// request in any case resolves to the single existing mailbox. This function does
// not lowercase non-INBOX names — their as-typed case is preserved for display
// (e.g. "Archive" stays "Archive"); only the reserved INBOX spelling is forced to
// the canonical form. Hierarchical children (e.g. "Inbox/Sub") are not the
// reserved name and are returned unchanged.
func CanonicalMailboxName(name string) string {
	if strings.EqualFold(name, consts.MailboxInbox) {
		return consts.MailboxInbox
	}
	return name
}

// MailboxNameHasTraversal reports whether an IMAP mailbox name contains a path
// segment that would escape its on-disk representation during maildir
// import/export.
//
// The IMAP hierarchy delimiter is '/', so each '/'-delimited segment maps to a
// directory component when a mailbox is materialised on the filesystem (e.g. by
// the maildir exporter). A segment that is exactly "." or ".." is rejected
// because filepath.Join would interpret it as the current or parent directory,
// letting a name like "../../etc" traverse outside the export root and write
// arbitrary files. Dots within a segment (e.g. "Foo.Bar" or "..foo") are
// harmless and remain allowed.
func MailboxNameHasTraversal(name string) bool {
	for _, segment := range strings.Split(name, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// MailboxNameStorable reports whether name can be stored as a PostgreSQL text value:
// valid UTF-8 without a NUL. No mailbox has any other name; querying with one fails
// with SQLSTATE 22021 instead of finding nothing.
func MailboxNameStorable(name string) bool {
	return utf8.ValidString(name) && strings.IndexByte(name, 0) < 0
}

// MailboxNameToCreate returns the name of the mailbox that creating name makes, or
// consts.ErrMailboxInvalidName when it makes none. Trailing hierarchy delimiters are
// dropped, as IMAP CREATE drops them: "the name created is without the trailing
// hierarchy delimiter" (RFC 3501 §6.3.3). Every level left must be non-empty and
// neither "." nor ".." (MailboxNameHasTraversal), so "x//y" or "/y" is refused
// instead of creating a parent "x/" or "" on the way. A name that is not storable
// (MailboxNameStorable) or holds a TAB, CR or LF, which db.CreateMailbox refuses, is
// refused as well.
func MailboxNameToCreate(name string) (string, error) {
	if !MailboxNameStorable(name) || strings.ContainsAny(name, "\t\r\n") {
		return "", consts.ErrMailboxInvalidName
	}
	delim := string(consts.MailboxDelimiter)
	name = strings.TrimRight(name, delim)
	if name == "" {
		return "", consts.ErrMailboxInvalidName
	}
	for _, level := range strings.Split(name, delim) {
		if level == "" || level == "." || level == ".." {
			return "", consts.ErrMailboxInvalidName
		}
	}
	return name, nil
}

// MailboxNameIsBelow reports whether name is a descendant of ancestor in the
// mailbox hierarchy. Mailbox names are case-insensitive.
func MailboxNameIsBelow(name, ancestor string) bool {
	return strings.HasPrefix(strings.ToLower(name), strings.ToLower(ancestor)+"/")
}
