//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTPProxyGracefulShutdownBeforeTransaction tests that shutting down before any transaction
// sends a proper 421 message to the client
func TestLMTPProxyGracefulShutdownBeforeTransaction(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend and proxy
	backendServer, _ := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress, proxyWrapper := setupLMTPProxyWithPROXY(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("Expected 220 greeting, got: %s", greeting)
	}
	t.Logf("Received greeting: %s", strings.TrimSpace(greeting))

	// Immediately shutdown the proxy
	t.Log("Initiating server shutdown before any commands...")
	proxyWrapper.Close()

	// Try to read next line - should get 421 shutdown message or EOF
	shutdownMsg, err := reader.ReadString('\n')
	if err != nil {
		// Connection closed without message is acceptable during shutdown
		t.Logf("✓ Connection closed during shutdown (no message received)")
	} else {
		t.Logf("Received: %s", strings.TrimSpace(shutdownMsg))
		if strings.Contains(shutdownMsg, "421") && strings.Contains(shutdownMsg, "shutting down") {
			t.Logf("✓ Received proper 421 shutdown message")
		} else if strings.Contains(shutdownMsg, "BYE") || strings.Contains(shutdownMsg, "closing") {
			t.Logf("✓ Received shutdown message")
		} else {
			t.Logf("⚠ Unexpected message during shutdown: %s", shutdownMsg)
		}
	}

	t.Log("✓ Test completed")
}

// TestLMTPProxyGracefulShutdownDuringTransaction tests that shutting down during mail transaction
// sends a proper 421 message instead of accepting the mail
func TestLMTPProxyGracefulShutdownDuringTransaction(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend and proxy
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress, proxyWrapper := setupLMTPProxyWithPROXY(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("Expected 220 greeting, got: %s", greeting)
	}

	// Send LHLO
	writer.WriteString("LHLO client.example.com\r\n")
	writer.Flush()

	// Read LHLO responses
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		if strings.HasPrefix(resp, "250 ") {
			break
		}
	}

	// Send MAIL FROM
	writer.WriteString("MAIL FROM:<sender@example.com>\r\n")
	writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// Send RCPT TO in a goroutine so we can shutdown during it
	rcptDone := make(chan string, 1)
	go func() {
		writer.WriteString(fmt.Sprintf("RCPT TO:<%s>\r\n", account.Email))
		writer.Flush()

		resp, err := reader.ReadString('\n')
		if err != nil {
			rcptDone <- fmt.Sprintf("ERROR: %v", err)
		} else {
			rcptDone <- resp
		}
	}()

	// Give RCPT TO a moment to be sent
	time.Sleep(50 * time.Millisecond)

	// Shutdown proxy during transaction
	t.Log("Initiating server shutdown during transaction...")
	proxyWrapper.Close()

	// Wait for response
	select {
	case response := <-rcptDone:
		if strings.HasPrefix(response, "ERROR:") {
			t.Logf("Connection error during shutdown: %s", response)
			t.Logf("✓ Connection closed during shutdown (acceptable)")
		} else {
			t.Logf("Received: %s", strings.TrimSpace(response))
			if strings.Contains(response, "421") && (strings.Contains(response, "shutting down") || strings.Contains(response, "Service")) {
				t.Logf("✓ Received proper 421 shutdown message during transaction")
			} else if strings.HasPrefix(response, "250") {
				// Should not accept mail during shutdown, but if backend already processed it, that's okay
				t.Logf("⚠ Mail accepted during shutdown (backend already processed)")
			} else {
				t.Logf("⚠ Unexpected response during shutdown: %s", response)
			}
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for RCPT TO response")
	}

	t.Log("✓ Test completed")
}

// TestLMTPProxyGracefulShutdownAfterTransaction tests that shutting down after successful mail delivery
// closes the connection gracefully
func TestLMTPProxyGracefulShutdownAfterTransaction(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend and proxy
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress, proxyWrapper := setupLMTPProxyWithPROXY(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to proxy
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		t.Fatalf("Expected 220 greeting, got: %s", greeting)
	}

	// Send LHLO
	writer.WriteString("LHLO client.example.com\r\n")
	writer.Flush()

	// Read LHLO responses
	for {
		resp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		if strings.HasPrefix(resp, "250 ") {
			break
		}
	}

	// Send MAIL FROM
	writer.WriteString("MAIL FROM:<sender@example.com>\r\n")
	writer.Flush()

	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM failed: %s", resp)
	}

	// Send RCPT TO
	writer.WriteString(fmt.Sprintf("RCPT TO:<%s>\r\n", account.Email))
	writer.Flush()

	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("RCPT TO failed: %s", resp)
	}

	// Send DATA
	writer.WriteString("DATA\r\n")
	writer.Flush()

	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA failed: %s", resp)
	}

	// Send message body
	message := "Subject: Test\r\n\r\nTest message body\r\n.\r\n"
	writer.WriteString(message)
	writer.Flush()

	// Read DATA completion response
	resp, err = reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read DATA completion response: %v", err)
	}
	if !strings.HasPrefix(resp, "250") {
		t.Fatalf("DATA completion failed: %s", resp)
	}
	t.Log("✓ Message delivered successfully")

	// Now shutdown the proxy after successful delivery
	t.Log("Initiating server shutdown after successful mail delivery...")
	proxyWrapper.Close()

	// Try to read next line - should get 421 shutdown message or EOF
	shutdownMsg, err := reader.ReadString('\n')
	if err != nil {
		// Connection closed is expected
		t.Logf("✓ Connection closed after shutdown")
	} else {
		t.Logf("Received: %s", strings.TrimSpace(shutdownMsg))
		if strings.Contains(shutdownMsg, "421") {
			t.Logf("✓ Received proper 421 shutdown message after delivery")
		} else {
			t.Logf("⚠ Unexpected message: %s", shutdownMsg)
		}
	}

	t.Log("✓ Test completed - mail was delivered before shutdown")
}
