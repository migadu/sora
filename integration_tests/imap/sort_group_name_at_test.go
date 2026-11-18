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
// host. With the name cut at the '@', "b@z" sorted as "b", before "b!". SEARCH FROM, TO,
// CC, HEADER and TEXT match the header text only: "b@z@" is not in any header of message
// 1, and a group name's own trailing '@' and a quoted local part's '@' still match.
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
		"From: \"tail@\":;\r\nTo: \"tail@\":;\r\nCc: \"tail@\":;\r\n\r\n3\r\n",
		"From: \"a@b\"@example.com\r\nTo: \"a@b\"@example.com\r\nCc: \"a@b\"@example.com\r\n\r\n4\r\n",
		"Subject: no address headers\r\n\r\n5\r\n",
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
		{imap.SortKeyFrom, []uint32{5, 4, 2, 1, 3}},
		{imap.SortKeyTo, []uint32{5, 4, 2, 1, 3}},
		{imap.SortKeyCc, []uint32{5, 4, 2, 1, 3}},
		// RFC 5957 §3: the group has no addr-name, so its value is the addr-mailbox "b@z";
		// the address's is "b!@example.com".
		{imap.SortKeyDisplayFrom, []uint32{5, 4, 2, 1, 3}},
		{imap.SortKeyDisplayTo, []uint32{5, 4, 2, 1, 3}},
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
	// The delimiter used only for SORT must not leak into SEARCH. Keep one
	// literal terminal '@' in a group name, and every '@' of a real mailbox.
	for _, key := range []string{"From", "To", "Cc"} {
		for _, tc := range []struct {
			value string
			want  []uint32
		}{
			{"b@z@", nil},
			{"b@z", []uint32{1}},
			{"tail@", []uint32{3}},
			{"tail@@", nil},
			{"a@b@", []uint32{4}},
			{"", []uint32{1, 2, 3, 4}},
		} {
			for _, header := range []bool{false, true} {
				res, err := c.Search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: key, Value: tc.value, IsHeader: header}}}, nil).Wait()
				if err != nil {
					t.Fatalf("SEARCH %s %q: %v", key, tc.value, err)
				}
				if got := res.AllSeqNums(); !slices.Equal(got, tc.want) {
					t.Errorf("SEARCH %s %q (HEADER %v) = %v, want %v", key, tc.value, header, got, tc.want)
				}
			}
		}
	}
	for _, tc := range []struct {
		value string
		want  []uint32
	}{
		{"b@z@", nil},
		{"tail@@", nil},
		{"b@z", []uint32{1}},
		{"tail@", []uint32{3}},
		{"a@b@", []uint32{4}},
	} {
		res, err := c.Search(&imap.SearchCriteria{Text: []string{tc.value}}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH TEXT %q: %v", tc.value, err)
		}
		if got := res.AllSeqNums(); !slices.Equal(got, tc.want) {
			t.Errorf("SEARCH TEXT %q = %v, want %v", tc.value, got, tc.want)
		}
	}
}
