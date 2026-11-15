package imap

import (
	"context"
	"errors"
	"testing"

	"github.com/migadu/go-imap"
)

// RFC 5464 §3.2: "Invalid entry names result in a BAD response in any IMAP
// command in which they are used", even when GETMETADATA's mailbox argument
// also contains a wildcard (which for valid entries is answered NO [CLIENTBUG]).
func TestGetMetadataValidatesEntriesBeforeWildcardMailbox(t *testing.T) {
	srv := newDisabledCapsTestServer(t, IMAPServerOptions{})
	s := newDisabledCapsTestSession(srv)

	for _, mailbox := range []string{"*", "%", "INBOX/*"} {
		for _, entry := range []string{"/private/", "/shared/", "/private/comment/", "/private/\x01", "/private/K"} {
			_, err := s.GetMetadata(context.Background(), mailbox, []string{entry}, nil)
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeBad {
				t.Errorf("GetMetadata(%q, [%q]) = %v, want BAD", mailbox, entry, err)
			}
		}
		_, err := s.GetMetadata(context.Background(), mailbox, []string{"/private/comment"}, nil)
		var imapErr *imap.Error
		if !errors.As(err, &imapErr) || imapErr.Type != imap.StatusResponseTypeNo || imapErr.Code != imap.ResponseCodeClientBug {
			t.Errorf("GetMetadata(%q, [\"/private/comment\"]) = %v, want NO [CLIENTBUG]", mailbox, err)
		}
	}
}
