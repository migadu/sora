//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_UnicodeCasemap checks that SORT and THREAD collate their string keys with
// i;unicode-casemap (RFC 5256 §7, RFC 5957 §7): each key is titlecased, fully decomposed
// (effectively NFKD) and then compared as octets (RFC 5051 §2), whatever collation the
// database was created with. Each message carries the same mailbox in From, To and Cc.
//
//	seq 1: "Émile" <e_x@example.com>, Subject "Émile", É precomposed (U+00C9)
//	seq 2: "Ezra" <ex@example.com>,   Subject "Ezra"
//	seq 3: a1@example.com,            Subject "a1"
//	seq 4: a@example.com,             Subject "a@"
//	seq 5: as seq 1, but É decomposed (U+0045 U+0301)
//
// Prepared keys: É becomes "E" U+0301 (0x45 0xCC 0x81), so it sorts after every
// ASCII-only key starting "E", and seq 1 and seq 5 are equal. Titlecasing puts "_"
// (0x5F) after the letters (0x41-0x5A), "1" (0x31) before "@" (0x40).
//
//	SUBJECT, DISPLAYFROM, DISPLAYTO: A1 < A@ < EZRA < ÉMILE  -> 3 4 2 1 5
//	FROM, TO, CC (addr-mailbox):     A < A1 < EX < E_X             -> 4 3 2 1 5
func TestIMAP_Sort_UnicodeCasemap(t *testing.T) {
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

	msgs := []struct{ addr, subject string }{
		{"=?UTF-8?Q?=C3=89mile?= <e_x@example.com>", "=?UTF-8?Q?=C3=89mile?="},
		{"Ezra <ex@example.com>", "Ezra"},
		{"a1@example.com", "a1"},
		{"a@example.com", "a@"},
		{"=?UTF-8?Q?E=CC=81mile?= <e_x@example.com>", "=?UTF-8?Q?E=CC=81mile?="},
	}
	for i, m := range msgs {
		msg := "From: " + m.addr + "\r\nTo: " + m.addr + "\r\nCc: " + m.addr +
			"\r\nSubject: " + m.subject +
			fmt.Sprintf("\r\nDate: Wed, 01 Jan 2020 00:0%d:00 +0000\r\n\r\nbody\r\n", i)
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND %d write failed: %v", i+1, err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("APPEND %d close failed: %v", i+1, err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i+1, err)
		}
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	// ALL takes the plain query; TEXT, which every message matches in its headers, takes
	// the TEXT UNION query, whose ORDER BY runs over a CTE.
	searches := map[string]*imap.SearchCriteria{
		"ALL":                {},
		`TEXT "example.com"`: {Text: []string{"example.com"}},
	}
	for name, criteria := range searches {
		for _, tc := range []struct {
			key  imap.SortKey
			want []uint32
		}{
			{imap.SortKeySubject, []uint32{3, 4, 2, 1, 5}},
			{imap.SortKeyDisplayFrom, []uint32{3, 4, 2, 1, 5}},
			{imap.SortKeyDisplayTo, []uint32{3, 4, 2, 1, 5}},
			{imap.SortKeyFrom, []uint32{4, 3, 2, 1, 5}},
			{imap.SortKeyTo, []uint32{4, 3, 2, 1, 5}},
			{imap.SortKeyCc, []uint32{4, 3, 2, 1, 5}},
		} {
			res, err := c.Sort(&imapclient.SortOptions{
				SearchCriteria: criteria,
				SortCriteria:   []imap.SortCriterion{{Key: tc.key}},
			}).Wait()
			if err != nil {
				t.Fatalf("SORT (%s) %s failed: %v", tc.key, name, err)
			}
			if !slices.Equal(res.SeqNums, tc.want) {
				t.Errorf("SORT (%s) %s = %v, want %v (i;unicode-casemap, RFC 5051 §2)", tc.key, name, res.SeqNums, tc.want)
			}
		}
	}

	// THREAD=ORDEREDSUBJECT groups messages whose base subjects are equal under the same
	// collation (RFC 5256 §7): the precomposed and the decomposed "Émile" are one thread.
	res, err := c.UIDThread(&imapclient.ThreadOptions{
		Algorithm:      imap.ThreadOrderedSubject,
		SearchCriteria: &imap.SearchCriteria{},
	}).Wait()
	if err != nil {
		t.Fatalf("UID THREAD ORDEREDSUBJECT failed: %v", err)
	}
	var got []string
	for _, td := range res {
		got = append(got, fmt.Sprint(td.Chain))
	}
	if want := []string{"[1 5]", "[2]", "[3]", "[4]"}; !slices.Equal(got, want) {
		t.Errorf("UID THREAD ORDEREDSUBJECT chains = %v, want %v", got, want)
	}
}
