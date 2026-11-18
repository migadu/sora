package db

import (
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
)

// TestSortColumnsFirstAddressIsGroup checks that a group start counts as its header's
// first address, keyed by the group name (#2016; RFC 5256 §3, RFC 3501 §7.4.2).
func TestSortColumnsFirstAddressIsGroup(t *testing.T) {
	hdr := mail.HeaderFromMap(map[string][]string{
		"From": {"Team: Sender <sender@example.com>;"},
		"To":   {"undisclosed-recipients:;"},
		"Cc":   {"user2: blah@domain1.org;, other@example.com"},
	})
	_, fromName, fromEmail, toName, toEmail, ccEmail, extra := sortColumnsFor("", helpers.ExtractRecipients(hdr.Header))
	for _, c := range []struct{ column, got, want string }{
		{"from_name_sort", fromName, ""},
		{"from_email_sort", fromEmail, "team"},
		{"to_name_sort", toName, ""},
		{"to_email_sort", toEmail, "undisclosed-recipients"},
		{"cc_email_sort", ccEmail, "user2"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.column, c.got, c.want)
		}
	}
	// The group members are addresses after the first, still searchable.
	for _, v := range []string{"sender", "sender@example.com", "blah@domain1.org", "other@example.com"} {
		if !strings.Contains(extra, v) {
			t.Errorf("extra_addresses %q lacks %q", extra, v)
		}
	}
}
