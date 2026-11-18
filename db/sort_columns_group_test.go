package db

import (
	"strings"
	"testing"

	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/helpers"
)

// TestSortColumnsFirstAddressIsGroup checks that a group start counts as its header's
// first address, keyed by the group name (#2016; RFC 5256 §3, RFC 3501 §7.4.2): its email
// column is empty, which tells SORT to take the whole name, '@' included (#2080), from the
// name column (From, To; DISPLAYFROM/DISPLAYTO read it too, RFC 5957 §3) or the head of
// the Cc section of extra_addresses. Nothing but header text is stored, since SEARCH reads
// the same columns.
func TestSortColumnsFirstAddressIsGroup(t *testing.T) {
	hdr := mail.HeaderFromMap(map[string][]string{
		"From": {"Team: Sender <sender@example.com>;"},
		"To":   {`"Ops@Example": a@example.com;`},
		"Cc":   {"user2: blah@domain1.org;, other@example.com, Later Group:;"},
	})
	_, fromName, fromEmail, toName, toEmail, ccEmail, extra := sortColumnsFor("", helpers.ExtractRecipients(hdr.Header))
	for _, c := range []struct{ column, got, want string }{
		{"from_name_sort", fromName, "team"},
		{"from_email_sort", fromEmail, ""},
		{"to_name_sort", toName, "ops@example"},
		{"to_email_sort", toEmail, ""},
		{"cc_email_sort", ccEmail, ""},
		{"cc group name", strings.Split(strings.Split(extra, "\n")[2], "\t")[0], "user2"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.column, c.got, c.want)
		}
	}
	// The group members and a later group's name are addresses after the first (#2036).
	for _, v := range []string{"sender", "sender@example.com", "a@example.com", "blah@domain1.org", "other@example.com", "later group"} {
		if !strings.Contains(extra, v) {
			t.Errorf("extra_addresses %q lacks %q", extra, v)
		}
	}
}
