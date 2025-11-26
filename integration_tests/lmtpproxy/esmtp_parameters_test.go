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
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/storage"
)

// TestLMTPProxyESMTPParameters tests that the LMTP proxy correctly handles
// ESMTP parameters like NOTIFY=NEVER sent by Postfix when using command_filter
func TestLMTPProxyESMTPParameters(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	testAccount := common.CreateTestAccount(t, rdb)
	t.Logf("Created test account: %s", testAccount.Email)

	// Initialize S3 storage (empty struct for testing)
	s3 := &storage.S3Storage{}

	// Start backend LMTP server
	backendAddr := "127.0.0.1:12425"
	backendServer, err := lmtp.New(ctx, "test-backend", "localhost", backendAddr, s3, rdb, nil, lmtp.LMTPServerOptions{
		Debug: true,
	})
	if err != nil {
		t.Fatalf("Failed to create backend LMTP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		backendServer.Start(errChan)
	}()
	t.Cleanup(func() {
		// Backend has no Shutdown method, just let it close when test ends
	})

	// Wait for backend to start
	time.Sleep(200 * time.Millisecond)

	// Start LMTP proxy
	proxyAddr := "127.0.0.1:12426"
	proxyOpts := lmtpproxy.ServerOptions{
		Name:           "test-proxy",
		Addr:           proxyAddr,
		RemoteAddrs:    []string{backendAddr},
		TrustedProxies: []string{"127.0.0.1/32"}, // Allow local connections
		Debug:          true,
	}

	proxy, err := lmtpproxy.New(ctx, rdb, "localhost", proxyOpts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	t.Cleanup(func() {
		proxy.Stop()
	})

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Test cases for different ESMTP parameters
	testCases := []struct {
		name        string
		rcptCommand string
		expectOK    bool
		description string
	}{
		{
			name:        "RCPT with NOTIFY=NEVER (Postfix command_filter)",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER", testAccount.Email),
			expectOK:    true,
			description: "This is the exact command Postfix sends with command_filter",
		},
		{
			name:        "RCPT with NOTIFY=SUCCESS,FAILURE",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=SUCCESS,FAILURE", testAccount.Email),
			expectOK:    true,
			description: "Standard DSN notification request",
		},
		{
			name:        "RCPT with ORCPT parameter",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> ORCPT=rfc822;%s", testAccount.Email, testAccount.Email),
			expectOK:    true,
			description: "Original recipient for DSN",
		},
		{
			name:        "RCPT with multiple DSN parameters",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER ORCPT=rfc822;%s", testAccount.Email, testAccount.Email),
			expectOK:    true,
			description: "Multiple ESMTP parameters",
		},
		{
			name:        "RCPT with space after TO:",
			rcptCommand: fmt.Sprintf("RCPT TO: <%s> NOTIFY=NEVER", testAccount.Email),
			expectOK:    true,
			description: "Space after TO: should also work",
		},
		{
			name:        "Plain RCPT without parameters",
			rcptCommand: fmt.Sprintf("RCPT TO:<%s>", testAccount.Email),
			expectOK:    true,
			description: "Control test - plain RCPT should work",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Test: %s", tc.description)

			// Connect to proxy
			conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to proxy: %v", err)
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
				t.Fatalf("Unexpected greeting: %s", greeting)
			}
			t.Logf("✓ Greeting: %s", strings.TrimSpace(greeting))

			// Send LHLO
			lhlo := "LHLO localhost\r\n"
			if _, err := writer.WriteString(lhlo); err != nil {
				t.Fatalf("Failed to send LHLO: %v", err)
			}
			writer.Flush()

			// Read LHLO response (multiple lines)
			var lhloResponse []string
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("Failed to read LHLO response: %v", err)
				}
				lhloResponse = append(lhloResponse, strings.TrimSpace(line))
				t.Logf("  LHLO: %s", strings.TrimSpace(line))

				// Check if this is the last line (no hyphen after status code)
				if len(line) >= 4 && line[3] != '-' {
					break
				}
			}

			// Verify DSN is advertised
			dsnAdvertised := false
			for _, line := range lhloResponse {
				if strings.Contains(line, "DSN") {
					dsnAdvertised = true
					t.Logf("✓ DSN extension advertised")
					break
				}
			}
			if !dsnAdvertised {
				t.Logf("⚠ WARNING: DSN extension not advertised in LHLO response")
			}

			// Send MAIL FROM
			mailFrom := "MAIL FROM:<sender@example.com>\r\n"
			if _, err := writer.WriteString(mailFrom); err != nil {
				t.Fatalf("Failed to send MAIL FROM: %v", err)
			}
			writer.Flush()

			mailResp, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read MAIL FROM response: %v", err)
			}
			t.Logf("✓ MAIL FROM response: %s", strings.TrimSpace(mailResp))
			if !strings.HasPrefix(mailResp, "250") {
				t.Fatalf("MAIL FROM failed: %s", mailResp)
			}

			// Send RCPT TO with ESMTP parameters
			rcptCmd := tc.rcptCommand + "\r\n"
			t.Logf("→ Sending: %s", strings.TrimSpace(rcptCmd))
			if _, err := writer.WriteString(rcptCmd); err != nil {
				t.Fatalf("Failed to send RCPT TO: %v", err)
			}
			writer.Flush()

			rcptResp, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read RCPT TO response: %v", err)
			}
			t.Logf("← RCPT TO response: %s", strings.TrimSpace(rcptResp))

			// Check response
			if tc.expectOK {
				if strings.HasPrefix(rcptResp, "250") {
					t.Logf("✓ RCPT TO accepted with ESMTP parameters")
				} else {
					t.Errorf("❌ RCPT TO should succeed but got: %s", strings.TrimSpace(rcptResp))

					// Check for the specific error we're trying to fix
					if strings.Contains(rcptResp, "555") && strings.Contains(rcptResp, "Unsupported parameters") {
						t.Errorf("🐛 BUG REPRODUCED! Proxy/backend is rejecting ESMTP parameters")
					} else if strings.Contains(rcptResp, "5.5.4") {
						t.Errorf("🐛 BUG! ESMTP parameter error: %s", rcptResp)
					}
				}
			} else {
				if strings.HasPrefix(rcptResp, "250") {
					t.Errorf("RCPT TO should fail but got: %s", strings.TrimSpace(rcptResp))
				}
			}

			// Send QUIT
			quit := "QUIT\r\n"
			writer.WriteString(quit)
			writer.Flush()
		})
	}
}

// TestLMTPProxyFullDeliveryWithESMTP tests a complete message delivery
// with ESMTP parameters to ensure end-to-end functionality
func TestLMTPProxyFullDeliveryWithESMTP(t *testing.T) {
	ctx := context.Background()

	// Setup test database
	rdb := common.SetupTestDatabase(t)

	// Create test account
	testAccount := common.CreateTestAccount(t, rdb)
	t.Logf("Created test account: %s", testAccount.Email)

	// Initialize S3 storage (empty struct for testing)
	s3 := &storage.S3Storage{}

	// Start backend LMTP server
	backendAddr := "127.0.0.1:12427"
	backendServer, err := lmtp.New(ctx, "test-backend", "localhost", backendAddr, s3, rdb, nil, lmtp.LMTPServerOptions{
		Debug: true,
	})
	if err != nil {
		t.Fatalf("Failed to create backend LMTP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		backendServer.Start(errChan)
	}()
	t.Cleanup(func() {
		// Backend has no Shutdown method, just let it close when test ends
	})

	// Wait for backend to start
	time.Sleep(200 * time.Millisecond)

	// Start LMTP proxy
	proxyAddr := "127.0.0.1:12428"
	proxyOpts := lmtpproxy.ServerOptions{
		Name:           "test-proxy",
		Addr:           proxyAddr,
		RemoteAddrs:    []string{backendAddr},
		TrustedProxies: []string{"127.0.0.1/32"}, // Allow local connections
		Debug:          true,
	}

	proxy, err := lmtpproxy.New(ctx, rdb, "localhost", proxyOpts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	t.Cleanup(func() {
		proxy.Stop()
	})

	// Wait for proxy to start
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	t.Logf("Greeting: %s", strings.TrimSpace(greeting))

	// Send LHLO
	writer.WriteString("LHLO localhost\r\n")
	writer.Flush()

	// Read LHLO response
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		t.Logf("LHLO: %s", strings.TrimSpace(line))
		if len(line) >= 4 && line[3] != '-' {
			break
		}
	}

	// Send MAIL FROM
	writer.WriteString("MAIL FROM:<sender@example.com>\r\n")
	writer.Flush()

	mailResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	t.Logf("MAIL FROM: %s", strings.TrimSpace(mailResp))

	// Send RCPT TO with NOTIFY=NEVER (simulating Postfix command_filter)
	rcptCmd := fmt.Sprintf("RCPT TO:<%s> NOTIFY=NEVER\r\n", testAccount.Email)
	t.Logf("Sending: %s", strings.TrimSpace(rcptCmd))
	writer.WriteString(rcptCmd)
	writer.Flush()

	rcptResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	t.Logf("RCPT TO: %s", strings.TrimSpace(rcptResp))

	if !strings.HasPrefix(rcptResp, "250") {
		t.Fatalf("RCPT TO failed: %s", rcptResp)
	}

	// Send DATA
	writer.WriteString("DATA\r\n")
	writer.Flush()

	dataResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	t.Logf("DATA: %s", strings.TrimSpace(dataResp))

	if !strings.HasPrefix(dataResp, "354") {
		t.Fatalf("DATA command failed: %s", dataResp)
	}

	// Send message
	message := "From: sender@example.com\r\n" +
		"To: " + testAccount.Email + "\r\n" +
		"Subject: Test with ESMTP parameters\r\n" +
		"\r\n" +
		"This is a test message sent with NOTIFY=NEVER parameter.\r\n" +
		".\r\n"

	writer.WriteString(message)
	writer.Flush()

	// Read delivery response
	deliveryResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read delivery response: %v", err)
	}
	t.Logf("Delivery: %s", strings.TrimSpace(deliveryResp))

	if !strings.HasPrefix(deliveryResp, "250") {
		t.Fatalf("Message delivery failed: %s", deliveryResp)
	}

	// Send QUIT
	writer.WriteString("QUIT\r\n")
	writer.Flush()

	t.Log("✓ Full message delivery with NOTIFY=NEVER succeeded")
}
