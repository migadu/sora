package imap

import (
	"errors"
	"testing"

	"github.com/migadu/go-imap"
)

// RFC 5464 §3.2: an entry name "MUST NOT contain two consecutive "/"
// characters and MUST NOT end with a "/" character", has at least two
// components, and "Invalid entry names result in a BAD response in any IMAP
// command in which they are used". The bare scope roots are no exception.
func TestValidateMetadataEntryInvalidNamesAreBAD(t *testing.T) {
	for _, entry := range []string{
		"/private/",
		"/shared/",
		"/private",
		"/shared",
		"/private/comment/",
		"/private//comment",
		"/private/bad*name",
		"/private/\x01",
		"/private/caf\xc3\xa9",
		"/invalid/path",
		"",
	} {
		err := validateMetadataEntry(entry)
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) {
			t.Errorf("validateMetadataEntry(%q) = %v, want an *imap.Error", entry, err)
			continue
		}
		if imapErr.Type != imap.StatusResponseTypeBad {
			t.Errorf("validateMetadataEntry(%q) answered %s, want BAD", entry, imapErr.Type)
		}
	}

	for _, entry := range []string{
		"/private/comment",
		"/shared/comment",
		"/private/vendor/example.com/a_b\\c:d",
	} {
		if err := validateMetadataEntry(entry); err != nil {
			t.Errorf("validateMetadataEntry(%q) = %v, want nil", entry, err)
		}
	}
}
