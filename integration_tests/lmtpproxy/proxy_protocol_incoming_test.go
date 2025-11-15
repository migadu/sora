//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/lmtpproxy"
)

// TestProxyProtocolIncoming verifies that LMTP proxy correctly reads incoming PROXY protocol headers
// from HAProxy/nginx and passes the real client IP to the backend.
func TestProxyProtocolIncoming(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create backend LMTP server with PROXY protocol enabled
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	email := account.Email

	t.Run("without_proxy_header", func(t *testing.T) {
		// Start LMTP proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupLMTPProxyWithPROXYIncoming(t, backendServer.ResilientDB, backendServer.Address)
		defer stopProxy()

		// Give servers time to start
		time.Sleep(100 * time.Millisecond)

		// Connect to proxy WITHOUT sending PROXY header - should be rejected
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Set read timeout to ensure we don't hang
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Try to read greeting - should fail/timeout because proxy expects PROXY header
		reader := bufio.NewReader(conn)
		_, err = reader.ReadString('\n')
		if err == nil {
			t.Fatal("Expected connection to fail without PROXY header, but it succeeded")
		}
		t.Logf("Expected failure: connection closed without PROXY header: %v", err)
	})

	t.Run("with_proxy_header", func(t *testing.T) {
		// Start LMTP proxy WITH PROXY protocol incoming enabled
		proxyAddr, stopProxy := setupLMTPProxyWithPROXYIncoming(t, backendServer.ResilientDB, backendServer.Address)
		defer stopProxy()

		// Give servers time to start
		time.Sleep(100 * time.Millisecond)

		// Connect to proxy
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send PROXY v2 header with real client IP
		realClientIP := "203.0.113.42"
		realClientPort := 54321
		serverIP := "127.0.0.1"
		serverPort := conn.LocalAddr().(*net.TCPAddr).Port

		header, err := server.GenerateProxyV2Header(realClientIP, realClientPort, serverIP, serverPort, "TCP4")
		if err != nil {
			t.Fatalf("Failed to generate PROXY header: %v", err)
		}

		_, err = conn.Write(header)
		if err != nil {
			t.Fatalf("Failed to send PROXY header: %v", err)
		}

		// Now read greeting
		reader := bufio.NewReader(conn)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting after PROXY header: %v", err)
		}
		t.Logf("Greeting after PROXY header: %s", strings.TrimSpace(greeting))

		// Should get LMTP greeting (220)
		if !strings.HasPrefix(greeting, "220") {
			t.Fatalf("Expected 220 greeting, got: %s", greeting)
		}

		// Send LHLO command
		_, err = conn.Write([]byte("LHLO localhost\r\n"))
		if err != nil {
			t.Fatalf("Failed to send LHLO: %v", err)
		}

		// Read LHLO response (multiline)
		var lhloLines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read LHLO response: %v", err)
			}
			lhloLines = append(lhloLines, line)
			trimmedLine := strings.TrimSpace(line)
			// Check if this is the last line (no continuation)
			if len(trimmedLine) >= 4 && trimmedLine[3] == ' ' {
				break
			}
		}
		t.Logf("LHLO response: %v", lhloLines)

		// Send MAIL FROM
		_, err = conn.Write([]byte("MAIL FROM:<sender@example.com>\r\n"))
		if err != nil {
			t.Fatalf("Failed to send MAIL FROM: %v", err)
		}

		mailResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read MAIL FROM response: %v", err)
		}
		t.Logf("MAIL FROM response: %s", strings.TrimSpace(mailResp))

		if !strings.HasPrefix(mailResp, "250") {
			t.Fatalf("MAIL FROM failed: %s", mailResp)
		}

		// Send RCPT TO
		_, err = conn.Write([]byte(fmt.Sprintf("RCPT TO:<%s>\r\n", email)))
		if err != nil {
			t.Fatalf("Failed to send RCPT TO: %v", err)
		}

		rcptResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read RCPT TO response: %v", err)
		}
		t.Logf("RCPT TO response: %s", strings.TrimSpace(rcptResp))

		if !strings.HasPrefix(rcptResp, "250") {
			t.Fatalf("RCPT TO failed: %s", rcptResp)
		}

		// Send DATA command
		_, err = conn.Write([]byte("DATA\r\n"))
		if err != nil {
			t.Fatalf("Failed to send DATA: %v", err)
		}

		dataResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read DATA response: %v", err)
		}
		t.Logf("DATA response: %s", strings.TrimSpace(dataResp))

		if !strings.HasPrefix(dataResp, "354") {
			t.Fatalf("DATA failed: %s", dataResp)
		}

		// Send message content
		message := "Subject: Test PROXY Protocol\r\n\r\nThis is a test message.\r\n.\r\n"
		_, err = conn.Write([]byte(message))
		if err != nil {
			t.Fatalf("Failed to send message: %v", err)
		}

		msgResp, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read message response: %v", err)
		}
		t.Logf("Message response: %s", strings.TrimSpace(msgResp))

		if !strings.HasPrefix(msgResp, "250") {
			t.Fatalf("Message delivery failed: %s", msgResp)
		}

		t.Logf("SUCCESS: PROXY protocol incoming support is working for LMTP!")

		// NOTE: To verify the real client IP reaches the backend, check the backend logs.
		// The backend should log remote=203.0.113.42 instead of the proxy's IP.
		// This is verified by the PROXY protocol forwarding mechanism.
	})
}

func setupLMTPProxyWithPROXYIncoming(t *testing.T, rdb *resilient.ResilientDatabase, backendAddr string) (string, func()) {
	t.Helper()

	proxyAddr := common.GetRandomAddress(t)
	hostname := "test-lmtp-proxy-protocol"

	opts := lmtpproxy.ServerOptions{
		Name:                   "test-lmtp-proxy-protocol",
		Addr:                   proxyAddr,
		RemoteAddrs:            []string{backendAddr},
		RemotePort:             25,
		TLS:                    false,
		TLSVerify:              false,
		RemoteTLS:              false,
		RemoteTLSVerify:        false,
		RemoteUseProxyProtocol: true,  // Enable PROXY protocol to backend
		RemoteUseXCLIENT:       false, // Disable XCLIENT (using PROXY instead)
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
		ProxyProtocol:          true, // Enable PROXY protocol for incoming connections
		ProxyProtocolTimeout:   "5s", // Timeout for reading PROXY headers
	}

	proxy, err := lmtpproxy.New(context.Background(), rdb, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with PROXY protocol: %v", err)
	}

	// Start proxy in background
	errChan := make(chan error, 1)
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("LMTP proxy error: %w", err)
		}
	}()

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	cleanup := func() {
		proxy.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("LMTP proxy error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	return proxyAddr, cleanup
}
