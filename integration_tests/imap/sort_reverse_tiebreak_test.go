//go:build integration

package imap_test

import (
	"slices"
	"strconv"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_ReverseKeepsSequenceTieBreak checks that REVERSE leaves the implicit
// sequence-number criterion ascending (sora #1037). RFC 5256 §3: "If two or more messages
// exactly match according to the sorting criteria, these messages are sorted according to
// the order in which they appear in the mailbox", and "REVERSE only reverses a single
// criterion, and does not affect the implicit "sequence number" sort criterion if all other
// criteria are identical. Consequently, a sort of REVERSE SUBJECT is not the same as a
// reverse ordering of a SUBJECT sort."
//
// The three messages share From, Date and internal date; 1 and 2 also share Subject
// ("same") and size, while 3 has Subject "other" and is one octet larger.
func TestIMAP_Sort_ReverseKeepsSequenceTieBreak(t *testing.T) {
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

	arrived := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, subject := range []string{"same", "same", "other"} {
		msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject +
			"\r\nDate: Wed, 01 Jan 2020 00:00:00 +0000\r\n" +
			"Message-ID: <tiebreak-" + strconv.Itoa(i+1) + "@example.com>\r\n\r\nbody\r\n"
		ac := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Time: arrived})
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
	search, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH failed: %v", err)
	}
	uids := search.AllUIDs() // in sequence order
	if len(uids) != 3 {
		t.Fatalf("UID SEARCH ALL = %v, want 3 messages", uids)
	}

	subject := imap.SortCriterion{Key: imap.SortKeySubject}
	reverse := func(key imap.SortKey) imap.SortCriterion { return imap.SortCriterion{Key: key, Reverse: true} }
	for _, tc := range []struct {
		name string
		sort []imap.SortCriterion
		want []uint32
	}{
		{"SUBJECT", []imap.SortCriterion{subject}, []uint32{3, 1, 2}},
		{"REVERSE SUBJECT", []imap.SortCriterion{reverse(imap.SortKeySubject)}, []uint32{1, 2, 3}},
		{"REVERSE FROM", []imap.SortCriterion{reverse(imap.SortKeyFrom)}, []uint32{1, 2, 3}},
		{"REVERSE TO", []imap.SortCriterion{reverse(imap.SortKeyTo)}, []uint32{1, 2, 3}},
		{"REVERSE DISPLAYFROM", []imap.SortCriterion{reverse(imap.SortKeyDisplayFrom)}, []uint32{1, 2, 3}},
		{"REVERSE ARRIVAL", []imap.SortCriterion{reverse(imap.SortKeyArrival)}, []uint32{1, 2, 3}},
		{"REVERSE DATE", []imap.SortCriterion{reverse(imap.SortKeyDate)}, []uint32{1, 2, 3}},
		{"REVERSE SIZE", []imap.SortCriterion{reverse(imap.SortKeySize)}, []uint32{3, 1, 2}},
		{"REVERSE SUBJECT REVERSE DATE", []imap.SortCriterion{reverse(imap.SortKeySubject), reverse(imap.SortKeyDate)}, []uint32{1, 2, 3}},
		{"SUBJECT REVERSE SIZE", []imap.SortCriterion{subject, reverse(imap.SortKeySize)}, []uint32{3, 1, 2}},
	} {
		// ALL takes the plain query; TEXT takes the UNION query, whose ORDER BY runs
		// over a CTE.
		for _, criteria := range []*imap.SearchCriteria{{}, {Text: []string{"example.com"}}} {
			opts := &imapclient.SortOptions{SearchCriteria: criteria, SortCriteria: tc.sort}
			where := "ALL"
			if len(criteria.Text) > 0 {
				where = "TEXT"
			}

			res, err := c.Sort(opts).Wait()
			if err != nil {
				t.Fatalf("SORT (%s) %s failed: %v", tc.name, where, err)
			}
			if !slices.Equal(res.SeqNums, tc.want) {
				t.Errorf("SORT (%s) UTF-8 %s = %v, want %v: ties must stay in ascending sequence order (RFC 5256 §3)",
					tc.name, where, res.SeqNums, tc.want)
			}

			wantUIDs := make([]imap.UID, len(tc.want))
			for i, seq := range tc.want {
				wantUIDs[i] = uids[seq-1]
			}
			ures, err := c.UIDSort(opts).Wait()
			if err != nil {
				t.Fatalf("UID SORT (%s) %s failed: %v", tc.name, where, err)
			}
			if !slices.Equal(ures.UIDs, wantUIDs) {
				t.Errorf("UID SORT (%s) UTF-8 %s = %v, want %v: ties must stay in ascending sequence order (RFC 5256 §3)",
					tc.name, where, ures.UIDs, wantUIDs)
			}
		}
	}
}
