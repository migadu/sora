package imap

import (
	"context"
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

// RFC 5464 §3.2: entry names "MUST NOT contain non-ASCII characters" and "are
// case-insensitive". Case folding happens before validation, so it must not
// turn a non-ASCII name into an ASCII one: Unicode lower-casing maps U+212A
// KELVIN SIGN to "k" and U+0130 to "i".
func TestCanonicalMetadataEntryKeepsNonASCIIInvalid(t *testing.T) {
	for _, entry := range []string{
		"/private/K",
		"/shared/commentİ",
		"/PRIVATE/Key",
	} {
		canon := canonicalMetadataEntry(entry)
		var imapErr *imap.Error
		if err := validateMetadataEntry(canon); !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeBad {
			t.Errorf("validateMetadataEntry(canonicalMetadataEntry(%q) = %q) = %v, want BAD", entry, canon, err)
		}
	}

	for entry, want := range map[string]string{
		"/PRIVATE/Vendor/Example.COM/X": "/private/vendor/example.com/x",
		"/shared/comment":               "/shared/comment",
	} {
		if got := canonicalMetadataEntry(entry); got != want {
			t.Errorf("canonicalMetadataEntry(%q) = %q, want %q", entry, got, want)
		}
	}
}

// RFC 5464 §3.2: "Entry names are case-insensitive." go-imap hands SETMETADATA
// entries to the session as a map keyed by the names as sent, so /private/A
// and /private/a arrive as two keys of one entry, in no order. Folding them
// into one canonical key kept whichever Go's map iteration visited last, so
// either value could be stored. Such a command is refused with BAD before
// anything is written. The test session has no database: a handler that does
// not refuse the command up front panics on it.
func TestSetMetadataSameEntryInTwoCasesIsBAD(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{})
	s := newDisabledCapsTestSession(srv)
	if !s.GetCapabilities().Has(imap.CapMetadata) {
		t.Fatal("test server does not offer METADATA")
	}

	one := []byte("1")
	for _, names := range [][]string{
		{"/private/A", "/private/a"},
		{"/SHARED/comment", "/shared/Comment"},
		{"/private/x", "/Private/Vendor/Example.com/K", "/private/vendor/example.COM/k"},
	} {
		entries := make(map[string]*[]byte, len(names))
		for i, name := range names {
			if i%2 == 0 {
				entries[name] = &one
			} else {
				entries[name] = nil
			}
		}
		for _, mailbox := range []string{"", "INBOX"} {
			err := callHandler(func() error { return s.SetMetadata(context.Background(), mailbox, entries) })
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) {
				t.Errorf("SetMetadata(%q, %q) = %v, want BAD", mailbox, names, err)
				continue
			}
			if imapErr.Type != imap.StatusResponseTypeBad || imapErr.Code != imap.ResponseCodeClientBug {
				t.Errorf("SetMetadata(%q, %q) answered %s [%s], want BAD [CLIENTBUG]", mailbox, names, imapErr.Type, imapErr.Code)
			}
		}
	}
}
