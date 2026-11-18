//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_CcWithinAddressBudget: the Cc addresses after the first, and a leading Cc
// group's name (the CC sort key, #2080), live in the Cc section of extra_addresses, which
// shares one byte budget with the From and To sections. A long To list used to take all
// of it, so SEARCH CC missed the Cc members and SORT (CC) keyed the message by "" (#2113).
func TestIMAP_CcWithinAddressBudget(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	var to []string
	for i := range 60 {
		to = append(to, fmt.Sprintf("Recipient Number %d <recipient.number.%d@example.com>", i, i))
	}
	for _, msg := range []string{
		"From: sender@example.com\r\nTo: " + strings.Join(to, ",\r\n ") + "\r\n" +
			"Cc: mm-team: member@example.org, other@example.org;\r\n\r\n1\r\n",
		"From: sender@example.com\r\nTo: a@example.com\r\nCc: aa@example.org\r\n\r\n2\r\n",
		"From: sender@example.com\r\nTo: a@example.com\r\nCc: zz@example.org\r\n\r\n3\r\n",
	} {
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND: %v", err)
		}
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT: %v", err)
	}

	for _, value := range []string{"member@example.org", "other@example.org", "mm-team"} {
		res, err := c.Search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Cc", Value: value}}}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH CC %q: %v", value, err)
		}
		if got, want := res.AllSeqNums(), []uint32{1}; !slices.Equal(got, want) {
			t.Errorf("SEARCH CC %q = %v, want %v", value, got, want)
		}
	}
	// The To list itself stays searchable at its start.
	res, err := c.Search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "To", Value: "recipient.number.1@example.com"}}}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH TO: %v", err)
	}
	if got, want := res.AllSeqNums(), []uint32{1}; !slices.Equal(got, want) {
		t.Errorf("SEARCH TO recipient.number.1@example.com = %v, want %v", got, want)
	}

	// RFC 5256 §3: "aa" < "mm-team" < "zz".
	sorted, err := c.Sort(&imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyCc}},
	}).Wait()
	if err != nil {
		t.Fatalf("SORT (CC): %v", err)
	}
	if want := []uint32{2, 1, 3}; !slices.Equal(sorted.SeqNums, want) {
		t.Errorf("SORT (CC) ALL = %v, want %v", sorted.SeqNums, want)
	}
}
