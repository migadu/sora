//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchAddressGroups checks that group names are searchable like display names
// and that an empty group makes its header present (#2036). RFC 3501 §6.4.4 defines TO
// as a substring of the envelope's TO field, which holds each group start with the group
// name as its mailbox (§7.4.2), and HEADER TO "" as every message with a To: field. The
// messages are imaptest's search-addresses.mbox (plus a Bcc group); the expected
// results are its search-addresses "groups" and "header to" assertions.
func TestIMAP_SearchAddressGroups(t *testing.T) {
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
		"From: user-from@domain.org\r\nTo: user-to@domain.org\r\nCc: user-cc@domain.org\r\nBcc: user-bcc@domain.org\r\n\r\nbody\r\n",
		"From: RealFrom <user-from@domain.org>\r\nTo: RealTo <user-to@domain.org>\r\nCc: RealCc <user-cc@domain.org>\r\nBcc: RealBcc <user-bcc@domain.org>\r\n\r\nbody2\r\n",
		"From: <user-from (comment)@ (comment) domain.org>\r\nTo: <user-to@domain.org>\r\nCc: <user-cc@domain.org>\r\nBcc: <user-bcc@domain.org>\r\n\r\nbody3\r\n",
		"From: user-from@domain.org (RealFrom)\r\nTo: user-to@domain.org (RealTo)\r\nCc: user-cc@domain.org (RealCc)\r\nBcc: user-bcc@domain.org (RealBcc)\r\n\r\nbody4\r\n",
		"From: user-from1@domain.org, user-from2@domain.org\r\nCc: user-cc@domain.org\r\n\r\nbody5\r\n",
		"From: RealFrom <user-from@domain.org>\r\nTo: groupname: groupuser1@domain.org, groupuser2@domain.org;,\r\n  groupname2: groupuser3@domain.org;\r\n\r\nbody6\r\n",
		"From: RealFrom <user-from@domain.org>\r\nTo: groupname:;\r\n\r\nbody7\r\n",
		// Not in the fixture: a group in a header without its own search column.
		"From: user-from@domain.org\r\nBcc: hidden-list: user-bcc@domain.org;\r\n\r\nbody8\r\n",
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

	to := func(value string, header bool) *imap.SearchCriteria {
		return &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "To", Value: value, IsHeader: header}}}
	}
	for _, tc := range []struct {
		name     string
		criteria *imap.SearchCriteria
		want     []uint32
	}{
		{`HEADER TO ""`, to("", true), []uint32{1, 2, 3, 4, 6, 7}},
		{"TO groupname", to("groupname", false), []uint32{6, 7}},
		{"TO groupname2", to("groupname2", false), []uint32{6}},
		{"TO groupuser1", to("groupuser1", false), []uint32{6}},
		{"TO groupuser2", to("groupuser2", false), []uint32{6}},
		{"TO groupuser3", to("groupuser3", false), []uint32{6}},
		{"TO groupuser4", to("groupuser4", false), nil},
		{"BCC hidden-list", &imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Bcc", Value: "hidden-list"}}}, []uint32{8}},
	} {
		data, err := c.Search(tc.criteria, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH %s failed: %v", tc.name, err)
		}
		if got := data.AllSeqNums(); !slices.Equal(got, tc.want) {
			t.Errorf("SEARCH %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}
