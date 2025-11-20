//go:build integration

package imap_test

import (
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ConcurrentClose reproduces a data race where Close() is called
// concurrently from both graceful shutdown (sendGracefulShutdownBye) and
// connection cleanup (deferred Close in serve goroutine).
//
// The race occurs in connectionLimitingConn.Close():
// - Line 144: Read of c.releaseFunc (check if != nil)
// - Line 146: Write to c.releaseFunc (set to nil)
//
// This test should FAIL when run with -race flag before the fix,
// and PASS after adding proper synchronization.
func TestIMAP_ConcurrentClose(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)

	// Connect multiple clients and keep them active
	const numClients = 10
	clients := make([]*imapclient.Client, numClients)

	// Connect clients sequentially to avoid triggering lookup cache race
	// (which is a separate issue)
	for i := 0; i < numClients; i++ {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Client %d: Failed to dial: %v", i, err)
		}

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			c.Close()
			t.Fatalf("Client %d: Failed to login: %v", i, err)
		}

		clients[i] = c
	}

	// Give connections time to stabilize
	time.Sleep(100 * time.Millisecond)

	// Now trigger the race condition:
	// 1. Server.Close() will call sendGracefulShutdownBye which calls conn.Bye()
	//    which calls conn.Close() on the underlying connectionLimitingConn
	// 2. The serve goroutine has a deferred conn.Close() that will also trigger
	//
	// Both paths will try to:
	// - Read c.releaseFunc to check if != nil
	// - Write c.releaseFunc = nil
	// This is a classic data race on an unsynchronized field.

	// Close server (triggers graceful shutdown with BYE messages)
	server.Close()

	// Also close clients concurrently to increase race probability
	for i := 0; i < numClients; i++ {
		if clients[i] != nil {
			go clients[i].Close()
		}
	}

	// Wait a moment for all closes to complete
	time.Sleep(200 * time.Millisecond)

	t.Log("✓ Test completed - run with -race to detect data race before fix")
}
