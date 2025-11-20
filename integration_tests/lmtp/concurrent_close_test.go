//go:build integration

package lmtp_test

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_ConcurrentClose reproduces a data race where Close() is called
// concurrently from both server shutdown and connection cleanup paths.
//
// The race occurs in connectionLimitingConn.Close():
// - Line 90: Read of c.releaseFunc (check if != nil)
// - Line 92: Write to c.releaseFunc (set to nil)
//
// This test should FAIL when run with -race flag before the fix,
// and PASS after adding proper synchronization.
func TestLMTP_ConcurrentClose(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServer(t)

	// Connect multiple clients and start LMTP sessions
	const numClients = 5
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Logf("Client %d: Failed to dial: %v", idx, err)
				return
			}
			defer conn.Close()

			// Simple LMTP conversation
			buf := make([]byte, 1024)

			// Read greeting
			conn.Read(buf)

			// Send LHLO
			fmt.Fprintf(conn, "LHLO localhost\r\n")
			conn.Read(buf)

			// Just establish the connection, don't need full protocol
		}(i)
	}

	// Wait a bit for connections to establish
	time.Sleep(100 * time.Millisecond)

	// Close server while connections are active
	// This triggers the race condition where both the server's graceful
	// shutdown and the connection cleanup try to release the limiter slot
	server.Close()

	// Wait for goroutines
	wg.Wait()

	t.Log("✓ Test completed - run with -race to detect data race before fix")
}

// TestLMTP_ConcurrentCloseSimple is a simpler version that just sends mail
// and triggers shutdown to catch the race
func TestLMTP_ConcurrentCloseSimple(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)

	// Connect multiple clients and send mail
	const numClients = 5
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Logf("Client %d: Failed to dial: %v", idx, err)
				return
			}
			defer conn.Close()

			// Simple LMTP conversation
			buf := make([]byte, 1024)

			// Read greeting
			conn.Read(buf)

			// Send LHLO
			fmt.Fprintf(conn, "LHLO localhost\r\n")
			conn.Read(buf)

			// Send AUTH (if supported - may not be in all LMTP servers)
			// For this test, we mainly care about the connection being established

			// Send MAIL FROM
			fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", account.Email)
			n, _ := conn.Read(buf)
			response := string(buf[:n])

			if !strings.Contains(response, "250") && !strings.Contains(response, "220") {
				t.Logf("Client %d: Unexpected response to MAIL FROM: %s", idx, response)
			}
		}(i)
	}

	// Wait a bit for connections to establish
	time.Sleep(100 * time.Millisecond)

	// Close server while connections are active
	server.Close()

	// Wait for goroutines
	wg.Wait()

	t.Log("✓ Simple test completed - run with -race to detect data race before fix")
}
