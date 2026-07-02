//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_From_UsesAddrMailboxNotFullEmail is a regression test for a Medium
// audit finding (Unit 9, 2026-07-01).
//
// RFC 5256 §3 defines the FROM sort key as the *addr-mailbox* of the first From
// address — i.e. the local part only. Sora populates from_email_sort with the
// full "local@domain" address and ORDER BYs on that, so ordering diverges from
// the RFC whenever local-part order and full-address order disagree.
//
// We use two messages with an IDENTICAL local part but different domains:
//
//	seq 1: From sortuser@zzz.example  (local "sortuser")
//	seq 2: From sortuser@aaa.example  (local "sortuser")
//
// RFC: both keys equal ("sortuser") -> stable order by sequence -> [1, 2].
// Bug: ORDER BY full email -> "sortuser@aaa" < "sortuser@zzz" -> [2, 1].
//
// Expected: SORT FROM -> [1, 2].
// Actual (bug): SORT FROM -> [2, 1] (ordered by domain).
func TestIMAP_Sort_From_UsesAddrMailboxNotFullEmail(t *testing.T) {
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

	appendFrom := func(from string) {
		msg := "From: " + from + "\r\nTo: " + account.Email +
			"\r\nSubject: Sort AddrMailbox Test\r\n" +
			"Date: Wed, 01 Jan 2020 00:00:00 +0000\r\n\r\nbody\r\n"
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
	appendFrom("sortuser@zzz.example") // seq 1
	appendFrom("sortuser@aaa.example") // seq 2

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	res, err := c.Sort(&imapclient.SortOptions{
		SearchCriteria: &imap.SearchCriteria{},
		SortCriteria:   []imap.SortCriterion{{Key: imap.SortKeyFrom}},
	}).Wait()
	if err != nil {
		t.Fatalf("SORT FROM failed: %v", err)
	}
	t.Logf("SORT FROM order: %v", res.SeqNums)

	want := []uint32{1, 2}
	if len(res.SeqNums) != 2 || res.SeqNums[0] != want[0] || res.SeqNums[1] != want[1] {
		t.Errorf("REGRESSION: SORT FROM returned %v; expected %v. RFC 5256 §3 sorts by "+
			"addr-mailbox (local part \"sortuser\", equal -> sequence order), but Sora orders by the full "+
			"email address (domain aaa < zzz).", res.SeqNums, want)
	}
}
