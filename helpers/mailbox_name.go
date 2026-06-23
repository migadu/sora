package helpers

import "strings"

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
