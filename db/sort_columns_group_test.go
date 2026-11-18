package db

import (
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
)

// TestSortColumnsFirstAddressIsGroup checks that a group start counts as its header's
// first address, keyed by the group name (#2016; RFC 5256 §3, RFC 3501 §7.4.2): its email
// column is the name and an empty host, so SORT's split at the last '@' gives back the
// whole name, '@' included (#2080), and its name column, which DISPLAYFROM/DISPLAYTO
// read, is the name (RFC 5957 §3).
func TestSortColumnsFirstAddressIsGroup(t *testing.T) {
	hdr := mail.HeaderFromMap(map[string][]string{
		"From": {"Team: Sender <sender@example.com>;"},
		"To":   {`"Ops@Example": a@example.com;`},
		"Cc":   {"user2: blah@domain1.org;, other@example.com"},
	})
	_, fromName, fromEmail, toName, toEmail, ccEmail, extra := sortColumnsFor("", helpers.ExtractRecipients(hdr.Header))
	for _, c := range []struct{ column, got, want string }{
		{"from_name_sort", fromName, "team"},
		{"from_email_sort", fromEmail, "team@"},
		{"to_name_sort", toName, "ops@example"},
		{"to_email_sort", toEmail, "ops@example@"},
		{"cc_email_sort", ccEmail, "user2@"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.column, c.got, c.want)
		}
	}
	// The group members are addresses after the first, still searchable.
	for _, v := range []string{"sender", "sender@example.com", "a@example.com", "blah@domain1.org", "other@example.com"} {
		if !strings.Contains(extra, v) {
			t.Errorf("extra_addresses %q lacks %q", extra, v)
		}
	}
}
