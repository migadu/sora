//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_FirstAddressIsGroup checks SORT when the first address of a header is a
// group (#2016). RFC 5256 §3 sorts CC by the addr-mailbox of the first "cc" address, and
// RFC 3501 §7.4.2 makes a group start an address whose addr-mailbox is the group name:
// "Cc: user2: blah@domain1.org;" sorts as "user2", not as its member "blah". The
// messages and expectations are imaptest's sort-addresses.mbox and sort-addresses.
func TestIMAP_Sort_FirstAddressIsGroup(t *testing.T) {
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

	for _, msg := range []string{
		"From: user2@domain2.org\r\nTo: foo bar <user2@domain2.org>\r\nCc: user2@domain2.org (foo bar)\r\n\r\n1\r\n",
		"From: user2@domain1.org\r\nTo: user2@domain1.org\r\nCc: user2: blah@domain1.org;\r\n\r\n2\r\n",
		"From: user1@domain1.org\r\nTo: user1@domain1.org\r\nCc: user1@domain1.org\r\n\r\n3\r\n",
	} {
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	for _, tc := range []struct {
		name     string
		criteria []imap.SortCriterion
		want     []uint32
	}{
		{"FROM", []imap.SortCriterion{{Key: imap.SortKeyFrom}}, []uint32{3, 1, 2}},
		{"TO", []imap.SortCriterion{{Key: imap.SortKeyTo}}, []uint32{3, 1, 2}},
		{"CC", []imap.SortCriterion{{Key: imap.SortKeyCc}}, []uint32{3, 1, 2}},
		{"REVERSE FROM", []imap.SortCriterion{{Key: imap.SortKeyFrom, Reverse: true}}, []uint32{1, 2, 3}},
		{"REVERSE TO", []imap.SortCriterion{{Key: imap.SortKeyTo, Reverse: true}}, []uint32{1, 2, 3}},
		{"REVERSE CC", []imap.SortCriterion{{Key: imap.SortKeyCc, Reverse: true}}, []uint32{1, 2, 3}},
		{"FROM REVERSE ARRIVAL", []imap.SortCriterion{{Key: imap.SortKeyFrom}, {Key: imap.SortKeyArrival, Reverse: true}}, []uint32{3, 2, 1}},
		{"TO REVERSE ARRIVAL", []imap.SortCriterion{{Key: imap.SortKeyTo}, {Key: imap.SortKeyArrival, Reverse: true}}, []uint32{3, 2, 1}},
		{"CC REVERSE ARRIVAL", []imap.SortCriterion{{Key: imap.SortKeyCc}, {Key: imap.SortKeyArrival, Reverse: true}}, []uint32{3, 2, 1}},
	} {
		res, err := c.Sort(&imapclient.SortOptions{
			SearchCriteria: &imap.SearchCriteria{},
			SortCriteria:   tc.criteria,
		}).Wait()
		if err != nil {
			t.Fatalf("SORT (%s) failed: %v", tc.name, err)
		}
		if !slices.Equal(res.SeqNums, tc.want) {
			t.Errorf("SORT (%s) ALL = %v, want %v", tc.name, res.SeqNums, tc.want)
		}
	}
}
