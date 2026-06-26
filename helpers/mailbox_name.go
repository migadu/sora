package helpers

import (
	"strings"

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
