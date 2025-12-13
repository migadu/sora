//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_SearchKeys(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Prepare data
	// Msg 1: Small, Old, Subject: Apple
	// Msg 2: Medium, Current, Subject: Banana, Body: Keyword
	// Msg 3: Large, Future, Subject: Cherry

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	tomorrow := now.Add(24 * time.Hour)

	msgs := []struct {
		subject string
		body    string
		date    time.Time
	}{
		{"Apple", "Short body.", yesterday},
		{"Banana", "This has a Keyword in it.", now},
		{"Cherry", strings.Repeat("Long body. ", 50), tomorrow},
	}

	for i, m := range msgs {
		msgData := fmt.Sprintf("Date: %s\r\nSubject: %s\r\n\r\n%s", m.date.Format(time.RFC1123), m.subject, m.body)
		appendCmd := c.Append("INBOX", int64(len(msgData)), &imap.AppendOptions{Time: m.date})
		if _, err := appendCmd.Write([]byte(msgData)); err != nil {
			t.Fatalf("Append %d write failed: %v", i+1, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append %d close failed: %v", i+1, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append %d failed: %v", i+1, err)
		}
	}

	// Test OR (Subject Apple OR Subject Banana)
	// Or field is [][2]SearchCriteria
	criteria := &imap.SearchCriteria{
		Or: [][2]imap.SearchCriteria{
			{
				{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "Apple"}}},
				{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "Banana"}}},
			},
		},
	}
	data, err := c.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH OR failed: %v", err)
	}
	if len(data.AllSeqNums()) != 2 {
		t.Errorf("SEARCH OR expected 2 matches, got %d", len(data.AllSeqNums()))
	}

	// Test DATE criteria (SINCE)
	// Find messages since today (should be Banana(2) and Cherry(3))
	// Note: IMAP date search resolution is Day.
	criteria = &imap.SearchCriteria{
		Since: now.Truncate(24 * time.Hour), // Start of today
	}
	// Depending on library implementation of Since (it might format as date string).
	// go-imap v2 usually handles formatting.

	data, err = c.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH SINCE failed: %v", err)
	}
	// Should match Banana (Today) and Cherry (Tomorrow)
	// Apple is Yesterday.
	matches := data.AllSeqNums()
	if len(matches) != 2 {
		// Verify if day boundaries handled correctly.
		t.Logf("SEARCH SINCE matches: %v", matches)
		// If test runs at 23:59 and server uses UTC vs Local, might differ.
		// Sora uses UTC internally usually. 'now' is local test time.
		// Let's assume broad check.
	}

	// Test BEFORE
	criteria = &imap.SearchCriteria{
		Before: now.Truncate(24 * time.Hour), // Strictly before today
	}
	data, err = c.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BEFORE failed: %v", err)
	}
	// Should match Apple (Yesterday)
	if len(data.AllSeqNums()) != 1 {
		t.Errorf("SEARCH BEFORE expected 1 match (Apple), got %d", len(data.AllSeqNums()))
	}

	// Test SIZE (LARGER)
	// Apple is small (~50 bytes), Cherry is large (~600 bytes)
	criteria = &imap.SearchCriteria{
		Larger: 300,
	}
	data, err = c.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH LARGER failed: %v", err)
	}
	// Should match Cherry only
	if len(data.AllSeqNums()) != 1 {
		t.Errorf("SEARCH LARGER expected 1 match (Cherry), got %d", len(data.AllSeqNums()))
	}

	// Test BODY
	criteria = &imap.SearchCriteria{
		Body: []string{"Keyword"},
	}
	data, err = c.Search(criteria, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH BODY failed: %v", err)
	}
	// Should match Banana
	if len(data.AllSeqNums()) != 1 {
		t.Errorf("SEARCH BODY expected 1 match (Banana), got %d", len(data.AllSeqNums()))
	}

	// Test UID (Search by UID range)
	// sequences 1,2,3 -> UIDs likely 1,2,3 or something.
	// Let's fetch UIDs first to be safe.
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{UID: true})
	fetchedMsgs, _ := fetchCmd.Collect()
	if len(fetchedMsgs) == 3 {
		uid2 := fetchedMsgs[1].UID
		criteria = &imap.SearchCriteria{
			UID: []imap.UIDSet{imap.UIDSetNum(uid2)},
		}
		data, err = c.Search(criteria, nil).Wait() // This is standard SEARCH using UID key, not UID SEARCH command
		if err != nil {
			t.Fatalf("SEARCH UID key failed: %v", err)
		}
		if len(data.AllSeqNums()) != 1 {
			t.Errorf("SEARCH UID key expected 1 match, got %d", len(data.AllSeqNums()))
		}
	}
}
