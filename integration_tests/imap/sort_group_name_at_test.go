//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_GroupNameWithAt checks that a group start sorts by its whole name even
// when the name holds an '@' (#2080). RFC 5256 §3 sorts by addr-mailbox, which for a
// group start is the group name (RFC 3501 §7.4.2); only an address is split from its
// host. With the name cut at the '@', "b@z" sorted as "b", before "b!".
func TestIMAP_Sort_GroupNameWithAt(t *testing.T) {
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
		"From: \"b@z\": x@example.com;\r\nTo: \"b@z\": x@example.com;\r\nCc: \"b@z\": x@example.com;\r\n\r\n1\r\n",
		"From: b!@example.com\r\nTo: b!@example.com\r\nCc: b!@example.com\r\n\r\n2\r\n",
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
		key  imap.SortKey
		want []uint32
	}{
		// "b!" < "b@z": '!' is 0x21, '@' 0x40.
		{imap.SortKeyFrom, []uint32{2, 1}},
		{imap.SortKeyTo, []uint32{2, 1}},
		{imap.SortKeyCc, []uint32{2, 1}},
		// RFC 5957 §3: the group has no addr-name, so its value is the addr-mailbox "b@z";
		// the address's is "b!@example.com".
		{imap.SortKeyDisplayFrom, []uint32{2, 1}},
		{imap.SortKeyDisplayTo, []uint32{2, 1}},
	} {
		res, err := c.Sort(&imapclient.SortOptions{
			SearchCriteria: &imap.SearchCriteria{},
			SortCriteria:   []imap.SortCriterion{{Key: tc.key}},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT (%s) failed: %v", tc.key, err)
		}
		if !slices.Equal(res.SeqNums, tc.want) {
			t.Errorf("SORT (%s) ALL = %v, want %v", tc.key, res.SeqNums, tc.want)
		}
	}
}
