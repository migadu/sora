//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_CondstoreUnsolicitedFlagsUpdate captures the RFC 7162 §3.2 conformance gap:
// when CONDSTORE is enabled, unsolicited FETCH responses containing flags updates
// must also include the MODSEQ of the message.
func TestIMAP_CondstoreUnsolicitedFlagsUpdate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// 1. Setup: Append a message first using a temporary client
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: CONDSTORE Unsolicited Test\r\n\r\nTest body.\r\n"
	appendCmd := setupClient.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write to setup client: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}
	setupClient.Logout()

	// 2. Client 1: Watched session (CONDSTORE-enabled, listens for unsolicited updates)
	fetchChan := make(chan *imapclient.FetchMessageData, 10)
	opts := &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Fetch: func(msg *imapclient.FetchMessageData) {
				fetchChan <- msg
			},
		},
	}

	client1, err := imapclient.DialInsecure(server.Address, opts)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	_, err = client1.Select("INBOX", &imap.SelectOptions{CondStore: true}).Wait()
	if err != nil {
		t.Fatalf("Client1 SELECT failed: %v", err)
	}

	// 3. Client 2: Modifier session (performs store flag operation)
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	if _, err := client2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client2 SELECT failed: %v", err)
	}

	// Trigger a flag change on client2.
	storeCmd := client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if _, err := storeCmd.Collect(); err != nil {
		t.Fatalf("Client2 STORE failed: %v", err)
	}

	// 4. Trigger a poll on client1 by sending a NOOP command
	if err := client1.Noop().Wait(); err != nil {
		t.Fatalf("Client1 NOOP failed: %v", err)
	}

	// 5. Verify client1 gets the update with a non-zero MODSEQ
	select {
	case msg := <-fetchChan:
		buf, err := msg.Collect()
		if err != nil {
			t.Fatalf("failed to collect unsolicited fetch message data: %v", err)
		}
		t.Logf("Received unsolicited update: SeqNum=%d, Flags=%v, ModSeq=%d", buf.SeqNum, buf.Flags, buf.ModSeq)
		if buf.ModSeq == 0 {
			t.Errorf("expected MODSEQ to be non-zero in unsolicited FETCH flags update, got 0 (conformance gap)")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for unsolicited FETCH flags update on client1")
	}
}
