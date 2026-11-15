//go:build integration

package imap_test

import (
	"slices"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Sort_Display_FallsBackToAddress checks the RFC 5957 §3 sort value of an address
// without a display name: an empty addr-name falls back to addr-mailbox@addr-host, so such a
// message sorts among the named ones by its address instead of before all of them.
//
//	seq 1: From: Zed <zed@example.com>    To: Bea <bea@example.org>
//	seq 2: From: mike@example.com         To: nina@example.org
//	seq 3: From: Adam <adam@example.com>  To: Xavier <xavier@example.org>
//	seq 4: From: bob@example.com          To: carl@example.org
//
// DISPLAYFROM: adam, bob@example.com, mike@example.com, zed -> 3 4 2 1.
// DISPLAYTO:   bea, carl@example.org, nina@example.org, xavier -> 1 4 2 3.
func TestIMAP_Sort_Display_FallsBackToAddress(t *testing.T) {
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

	appendMsg := func(from, to string) {
		msg := "From: " + from + "\r\nTo: " + to +
			"\r\nSubject: Sort Display Fallback\r\n" +
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
	appendMsg("Zed <zed@example.com>", "Bea <bea@example.org>")
	appendMsg("mike@example.com", "nina@example.org")
	appendMsg("Adam <adam@example.com>", "Xavier <xavier@example.org>")
	appendMsg("bob@example.com", "carl@example.org")

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  imap.SortCriterion
		want []uint32
	}{
		{"DISPLAYFROM", imap.SortCriterion{Key: imap.SortKeyDisplayFrom}, []uint32{3, 4, 2, 1}},
		{"REVERSE DISPLAYFROM", imap.SortCriterion{Key: imap.SortKeyDisplayFrom, Reverse: true}, []uint32{1, 2, 4, 3}},
		{"DISPLAYTO", imap.SortCriterion{Key: imap.SortKeyDisplayTo}, []uint32{1, 4, 2, 3}},
	} {
		res, err := c.Sort(&imapclient.SortOptions{
			SearchCriteria: &imap.SearchCriteria{},
			SortCriteria:   []imap.SortCriterion{tc.key},
		}).Wait()
		if err != nil {
			t.Fatalf("SORT (%s) failed: %v", tc.name, err)
		}
		if !slices.Equal(res.SeqNums, tc.want) {
			t.Errorf("SORT (%s) = %v, want %v: an address without a display name must sort by "+
				"addr-mailbox@addr-host (RFC 5957 §3), not by the empty string", tc.name, res.SeqNums, tc.want)
		}
	}
}
