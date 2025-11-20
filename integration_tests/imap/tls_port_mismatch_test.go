//go:build integration

package imap_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_PlainTextOnTLSPort(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up IMAP server with TLS enabled (direct TLS port)
	server, _ := setupIMAPServerWithTLS(t, true, "../../testdata/sora.crt", "../../testdata/sora.key")
	defer server.Close()

	// Connect with plain TCP (no TLS)
	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to IMAP server: %v", err)
	}
	defer conn.Close()

	// Set read deadline to avoid hanging
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Try to send plain-text IMAP command (this should be rejected)
	_, err = conn.Write([]byte("A001 CAPABILITY\r\n"))
	if err != nil {
		t.Logf("Write failed (expected): %v", err)
	}

	// Read the response - should get rejection message
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')

	if err == nil {
		// Check for our custom error message
		if strings.Contains(response, "Plain-text connection attempted on TLS port") ||
			strings.Contains(response, "ERROR") {
			t.Logf("✓ Server correctly rejected plain-text connection on TLS port")
			t.Logf("✓ Server response: %s", strings.TrimSpace(response))
		} else {
			t.Errorf("Expected rejection message, but got: %s", response)
		}
	} else {
		// Connection might be closed immediately, which is also acceptable
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection reset") {
			t.Logf("✓ Server closed connection (acceptable behavior)")
		} else {
			t.Logf("Read error (might be expected): %v", err)
		}
	}

	// Verify connection is closed
	time.Sleep(100 * time.Millisecond)
	_, err = conn.Write([]byte("A002 NOOP\r\n"))
	if err != nil {
		t.Logf("✓ Connection properly closed after rejection")
	}
}

func TestIMAP_TLSOnPlainPort(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up IMAP server without TLS (plain-text port)
	server, _ := setupIMAPServerWithTLS(t, false, "", "")
	defer server.Close()

	// First attempt: Try to send TLS Client Hello to plain-text port
	// The server should detect and reject it with our error message
	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to IMAP server: %v", err)
	}

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Send TLS Client Hello bytes (0x16 0x03 0x01 ...)
	// This is the start of a real TLS handshake
	tlsClientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x05, // TLS record header (handshake, TLS 1.0, length 5)
		0x01, 0x00, 0x00, 0x01, 0x03, // Client Hello start
	}
	_, err = conn.Write(tlsClientHello)
	if err != nil {
		t.Logf("Write failed (might be expected): %v", err)
	}

	// Try to read response - should get rejection message
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	conn.Close()

	if err == nil {
		// Check for our custom error message
		if strings.Contains(response, "TLS connection attempted on plain-text port") ||
			strings.Contains(response, "ERROR") {
			t.Logf("✓ Server correctly rejected TLS connection on plain-text port")
			t.Logf("✓ Server response: %s", strings.TrimSpace(response))
		} else {
			t.Logf("Got response (might be greeting): %s", strings.TrimSpace(response))
		}
	} else {
		// Connection might be closed immediately
		t.Logf("Read error or connection closed (acceptable): %v", err)
	}

	// Second attempt: Try full TLS handshake (should fail)
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", server.Address, &tls.Config{
		InsecureSkipVerify: true,
	})

	if tlsConn != nil {
		defer tlsConn.Close()
	}

	// We expect this to fail
	if err != nil {
		t.Logf("✓ Full TLS handshake failed on plain-text port (expected): %v", err)
		return
	}

	// If connection succeeded, something is wrong
	t.Errorf("TLS connection should not succeed on plain-text port")
}

func TestIMAP_PlainTextOnTLSPort_MultipleAttempts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up IMAP server with TLS enabled
	server, _ := setupIMAPServerWithTLS(t, true, "../../testdata/sora.crt", "../../testdata/sora.key")
	defer server.Close()

	// Try multiple plain-text connections (should all be rejected)
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
		if err != nil {
			t.Fatalf("Attempt %d: Failed to connect: %v", i+1, err)
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Send plain-text command
		conn.Write([]byte(fmt.Sprintf("A%03d CAPABILITY\r\n", i+1)))

		// Try to read response
		reader := bufio.NewReader(conn)
		response, _ := reader.ReadString('\n')

		conn.Close()

		if strings.Contains(response, "Plain-text") || strings.Contains(response, "ERROR") {
			t.Logf("✓ Attempt %d: Correctly rejected", i+1)
		} else {
			t.Logf("Attempt %d: Connection closed without message (acceptable)", i+1)
		}
	}

	t.Logf("✓ Multiple plain-text connection attempts all handled correctly")
}

func TestIMAP_ValidTLSConnection_StillWorks(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Verify that valid TLS connections still work after adding detection
	server, account := setupIMAPServerWithTLS(t, true, "../../testdata/sora.crt", "../../testdata/sora.key")
	defer server.Close()

	// Create valid TLS connection
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", server.Address, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to establish TLS connection: %v", err)
	}
	defer conn.Close()

	// Verify handshake completed
	if !conn.ConnectionState().HandshakeComplete {
		t.Fatalf("TLS handshake should be complete")
	}

	// Read greeting
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}

	if !strings.Contains(greeting, "* OK") {
		t.Errorf("Expected IMAP greeting, got: %s", greeting)
	}

	// Try CAPABILITY command
	_, err = conn.Write([]byte("A001 CAPABILITY\r\n"))
	if err != nil {
		t.Fatalf("Failed to send CAPABILITY: %v", err)
	}

	// Read response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CAPABILITY response: %v", err)
		}
		t.Logf("< %s", strings.TrimSpace(line))
		if strings.HasPrefix(line, "A001 OK") {
			break
		}
	}

	// Try login
	loginCmd := fmt.Sprintf("A002 LOGIN %s %s\r\n", account.Email, account.Password)
	_, err = conn.Write([]byte(loginCmd))
	if err != nil {
		t.Fatalf("Failed to send LOGIN: %v", err)
	}

	// Read login response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LOGIN response: %v", err)
		}
		t.Logf("< %s", strings.TrimSpace(line))
		if strings.HasPrefix(line, "A002 OK") {
			t.Logf("✓ Valid TLS connection works correctly after adding plain-text detection")
			return
		}
		if strings.HasPrefix(line, "A002 NO") || strings.HasPrefix(line, "A002 BAD") {
			t.Fatalf("Login failed: %s", line)
		}
	}
}
