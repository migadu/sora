//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_MultiSearch_Integration(t *testing.T) {
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

	// We need multiple mailboxes for MULTISEARCH
	mailboxes := []string{"INBOX", "Archive", "Trash"}

	for _, mbox := range mailboxes {
		if mbox != "INBOX" { // INBOX is created automatically
			if err := c.Create(mbox, nil).Wait(); err != nil {
				// Sora automatically creates default mailboxes like Archive and Trash
				if imapErr, ok := err.(*imap.Error); !ok || imapErr.Code != imap.ResponseCodeAlreadyExists {
					t.Fatalf("Create %s failed: %v", mbox, err)
				}
			}
		}

		// Append exactly 2 messages into each mailbox
		for i := 1; i <= 2; i++ {
			msgData := "Subject: test message " + mbox + "\r\n\r\nHello from " + mbox
			appendCmd := c.Append(mbox, int64(len(msgData)), nil)
			if _, err := appendCmd.Write([]byte(msgData)); err != nil {
				t.Fatalf("Append write failed: %v", err)
			}
			if err := appendCmd.Close(); err != nil {
				t.Fatalf("Append close failed: %v", err)
			}
			if _, err := appendCmd.Wait(); err != nil {
				t.Fatalf("Append wait failed: %v", err)
			}
		}
	}

	// 1. Basic multi-mailbox ESEARCH: IN (mailboxes (INBOX Archive Trash)).
	t.Run("CrossMailboxSearch", func(t *testing.T) {
		opts := &imap.SearchOptions{
			ReturnAll: true,
		}

		criteria := &imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "test message"}},
		}

		source := &imap.SearchSource{Mailboxes: mailboxes}
		results, err := c.MultiSearch(source, criteria, opts).Wait()
		if err != nil {
			t.Fatalf("ESEARCH failed: %v", err)
		}

		// One ESEARCH response per matched mailbox — we expect all 3.
		if len(results) != 3 {
			t.Fatalf("Expected 3 SearchData results, got %d", len(results))
		}
		// RFC 7377 §2.1: each result must carry its Mailbox and (non-zero)
		// UIDVALIDITY so the returned UIDs are unambiguous.
		for _, r := range results {
			if r.Mailbox == "" {
				t.Errorf("result missing Mailbox: %+v", r)
			}
			if r.UIDValidity == 0 {
				t.Errorf("result for %q missing UIDVALIDITY", r.Mailbox)
			}
		}
	})

	// 2. Test empty result suppression (RFC 7377 §2.1).
	t.Run("EmptyResultSuppression", func(t *testing.T) {
		opts := &imap.SearchOptions{
			ReturnAll: true,
		}

		// Search for something that only exists in INBOX
		criteria := &imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "test message INBOX"}},
		}

		source := &imap.SearchSource{Mailboxes: mailboxes}
		results, err := c.MultiSearch(source, criteria, opts).Wait()
		if err != nil {
			t.Fatalf("ESEARCH failed: %v", err)
		}

		if len(results) != 1 {
			t.Fatalf("Expected exactly 1 result since only INBOX matches, got %v", len(results))
		}

		if results[0].Mailbox != "INBOX" {
			t.Errorf("Expected result from INBOX, got %s", results[0].Mailbox)
		}
	})
}
