package db

import (
	"fmt"
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

// TestSortColumnsCcWithinAddressBudget: a long To list does not crowd the Cc section out of
// extra_addresses (#2113). Every section keeps an equal share of the budget, or all of
// itself if it is smaller, and what a short section leaves goes to the others.
func TestSortColumnsCcWithinAddressBudget(t *testing.T) {
	recipients := []helpers.Recipient{{AddressType: "from", EmailAddress: "sender@example.com"}}
	for i := range 60 {
		recipients = append(recipients, helpers.Recipient{AddressType: "to", Name: fmt.Sprintf("Recipient Number %d", i), EmailAddress: fmt.Sprintf("recipient.number.%d@example.com", i)})
	}
	recipients = append(recipients,
		helpers.Recipient{AddressType: "cc", Group: "mm-team"},
		helpers.Recipient{AddressType: "cc", EmailAddress: "member@example.org"},
		helpers.Recipient{AddressType: "cc", GroupEnd: true})
	_, fromName, fromEmail, toName, toEmail, ccEmail, extra := sortColumnsFor("", recipients)
	sections := strings.Split(extra, "\n")
	if len(sections) != 3 {
		t.Fatalf("extra_addresses has %d sections, want 3: %q", len(sections), extra)
	}
	if got, want := sections[2], "mm-team\tmember@example.org"; got != want {
		t.Errorf("Cc section = %q, want %q", got, want)
	}
	if !strings.HasPrefix(sections[1], "recipient number 1\trecipient.number.1@example.com\t") {
		t.Errorf("To section lost its start: %q", sections[1][:min(len(sections[1]), 80)])
	}
	used := len(fromName) + len(fromEmail) + len(toName) + len(toEmail) + len(ccEmail)
	if used+len(extra) > helpers.MaxAddressColumnsBytes {
		t.Errorf("address columns use %d bytes, over the %d budget", used+len(extra), helpers.MaxAddressColumnsBytes)
	}
	if used+len(extra) < helpers.MaxAddressColumnsBytes-4 {
		t.Errorf("address columns use %d bytes: the To section should take what Cc leaves", used+len(extra))
	}
}
