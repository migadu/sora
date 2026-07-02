//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Examine_ReadOnly_RejectsStore is a regression test for audit finding H2
// (2026-07-01 IMAP command-correctness audit).
//
// RFC 3501 §6.3.2: "The EXAMINE command is identical to SELECT and returns the
// same output; however, the selected mailbox is identified as read-only. No
// changes to the permanent state of the mailbox ... are permitted."
//
// Sora computes but never stores/enforces a read-only mode for the selected
// mailbox. The go-imap STORE/EXPUNGE handlers only checkState(ConnStateSelected),
// and the mailbox owner holds every ACL right, so a STORE issued after EXAMINE
// mutates the mailbox instead of being rejected.
//
// Expected (RFC-correct): STORE after EXAMINE is rejected (tagged NO).
// Actual   (bug):         STORE succeeds and \Deleted is persisted.
//
// Fix: track the read-only selection mode (on the session or fork Conn, set from
// EXAMINE / SelectOptions.ReadOnly) and reject STORE/EXPUNGE with NO [READ-ONLY].
func TestIMAP_Examine_ReadOnly_RejectsStore(t *testing.T) {
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

	// APPEND a message to INBOX (authenticated state, no SELECT needed).
	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Examine ReadOnly Test\r\n" +
		"\r\n" +
		"body\r\n"
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// EXAMINE opens the mailbox read-only.
	sd, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatalf("EXAMINE failed: %v", err)
	}
	if !sd.ReadOnly {
		t.Errorf("EXAMINE should report READ-ONLY on the tagged OK, got READ-WRITE")
	}

	// STORE must be rejected on a read-only (EXAMINE-opened) mailbox.
	_, storeErr := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect()

	if storeErr == nil {
		t.Errorf("REGRESSION: STORE succeeded on an EXAMINE-opened (read-only) mailbox; " +
			"RFC 3501 §6.3.2 requires it to be rejected (NO [READ-ONLY])")
	} else {
		t.Logf("STORE correctly rejected after EXAMINE: %v", storeErr)
	}
}
