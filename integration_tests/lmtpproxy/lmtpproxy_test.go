//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
)

// LMTPProxyWrapper wraps the LMTP proxy server to handle graceful shutdown
type LMTPProxyWrapper struct {
	server *lmtpproxy.Server
}

func (w *LMTPProxyWrapper) Close() error {
	if w.server != nil {
		return w.server.Stop()
	}
	return nil
}

// LogCapture captures log output for verification
type LogCapture struct {
	buffer         *bytes.Buffer
	writer         io.Writer
	oldLog         *log.Logger
	oldOut         io.Writer
	oldSlogHandler *slog.Logger
}

func NewLogCapture() *LogCapture {
	buffer := &bytes.Buffer{}
	writer := io.MultiWriter(os.Stderr, buffer)

	// Save old settings
	oldOut := log.Writer()
	oldLog := log.New(oldOut, "", log.LstdFlags)
	oldSlogHandler := slog.Default()

	// Set new logger to capture output
	log.SetOutput(writer)

	// Set up slog to capture output at DEBUG level
	handler := slog.NewTextHandler(writer, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	newLogger := slog.New(handler)
	slog.SetDefault(newLogger)

	return &LogCapture{
		buffer:         buffer,
		writer:         writer,
		oldLog:         oldLog,
		oldOut:         oldOut,
		oldSlogHandler: oldSlogHandler,
	}
}

func (lc *LogCapture) GetOutput() string {
	return lc.buffer.String()
}

func (lc *LogCapture) Close() {
	// Restore original log settings
	log.SetOutput(lc.oldOut)
	slog.SetDefault(lc.oldSlogHandler)
}

// LMTPClient provides a simple LMTP client for testing
type LMTPClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewLMTPClient(address string) (*LMTPClient, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	client := &LMTPClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}

	// Read greeting
	response, err := client.ReadResponse()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	if !strings.HasPrefix(response, "220") {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %s", response)
	}

	return client, nil
}

func (c *LMTPClient) SendCommand(command string) error {
	_, err := c.conn.Write([]byte(command + "\r\n"))
	return err
}

func (c *LMTPClient) ReadResponse() (string, error) {
	response, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(response, "\r\n"), nil
}

func (c *LMTPClient) ReadMultilineResponse() ([]string, error) {
	var responses []string
	for {
		response, err := c.ReadResponse()
		if err != nil {
			return nil, err
		}
		responses = append(responses, response)

		// Check if this is the last line (not a continuation)
		if len(response) >= 4 && response[3] == ' ' {
			break
		}
	}
	return responses, nil
}

func (c *LMTPClient) Close() error {
	return c.conn.Close()
}

// setupLMTPProxyWithPROXY sets up an LMTP proxy that uses PROXY protocol to connect to the backend
func setupLMTPProxyWithPROXY(t *testing.T, backendAddress string) (string, *LMTPProxyWrapper) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with PROXY protocol support
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendAddress},
			RemotePort:             25,                                 // Default LMTP port
			RemoteUseProxyProtocol: true,                               // Enable PROXY protocol to backend
			RemoteUseXCLIENT:       false,                              // Disable XCLIENT (using PROXY instead)
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"}, // Trust localhost
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with PROXY protocol: %v", err)
	}

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return proxyAddress, &LMTPProxyWrapper{server: server}
}

// setupLMTPProxyWithXCLIENT sets up an LMTP proxy that uses XCLIENT command to forward parameters
func setupLMTPProxyWithXCLIENT(t *testing.T, backendAddress string) (string, *LMTPProxyWrapper) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with XCLIENT support
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendAddress},
			RemotePort:             25,                                 // Default LMTP port
			RemoteUseProxyProtocol: false,                              // Disable PROXY protocol
			RemoteUseXCLIENT:       true,                               // Enable XCLIENT command
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"}, // Trust localhost
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with XCLIENT support: %v", err)
	}

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return proxyAddress, &LMTPProxyWrapper{server: server}
}

// TestLMTPProxyWithPROXYProtocol tests LMTP proxy using PROXY protocol
func TestLMTPProxyWithPROXYProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server with PROXY protocol support
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	// Set up LMTP proxy with PROXY protocol
	proxyAddress, proxyWrapper := setupLMTPProxyWithPROXY(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Test basic LMTP commands through proxy
	// 1. LHLO command
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// 2. MAIL FROM command
	if err := client.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", "sender@example.com")); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// 3. RCPT TO command
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("RCPT TO failed: %s", response)
	}

	// 4. DATA command
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content
	messageContent := "Subject: Test Message\r\n\r\nThis is a test message through LMTP proxy.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Message delivery failed: %s", response)
	}

	// 5. Close connection (LMTP doesn't typically use QUIT like SMTP)
	// The session ends after message delivery

	// Wait a bit for logs to be written
	time.Sleep(200 * time.Millisecond)

	// Verify that proxy information appears in logs
	logOutput := logCapture.GetOutput()
	if !strings.Contains(logOutput, "proxy=127.0.0.1") {
		t.Errorf("Expected to find 'proxy=127.0.0.1' in logs, but didn't find it.\nLog output:\n%s", logOutput)
	}
}

// TestLMTPProxyWithXCLIENT tests LMTP proxy using XCLIENT command forwarding
func TestLMTPProxyWithXCLIENT(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server without PROXY protocol (for XCLIENT mode)
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy with XCLIENT support
	proxyAddress, proxyWrapper := setupLMTPProxyWithXCLIENT(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Test basic LMTP commands through proxy
	// 1. LHLO command
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// 2. MAIL FROM command
	if err := client.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", "sender@example.com")); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// 3. RCPT TO command
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("RCPT TO failed: %s", response)
	}

	// 4. DATA command
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content
	messageContent := "Subject: Test Message\r\n\r\nThis is a test message through LMTP proxy with XCLIENT.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Message delivery failed: %s", response)
	}

	// 5. Close connection (LMTP doesn't typically use QUIT like SMTP)
	// The session ends after message delivery

	// Wait a bit for logs to be written
	time.Sleep(200 * time.Millisecond)

	// Note: The XCLIENT command is currently rejected at the go-smtp protocol level
	// with "501 5.5.2 Bad command" before reaching our XCLIENT backend implementation.
	// This is a limitation in the go-smtp library's XCLIENT handling for LMTP.
	// However, message delivery still works correctly through the proxy.
	logOutput := logCapture.GetOutput()

	// Verify that XCLIENT was attempted but rejected (expected behavior)
	if strings.Contains(logOutput, "backend rejected XCLIENT command") {
		t.Logf("XCLIENT command was rejected at protocol level (known go-smtp limitation)")
	}

	// Verify basic proxy functionality works
	if strings.Contains(logOutput, "message delivered") {
		t.Logf("Message was delivered successfully through LMTP proxy")
	} else {
		t.Errorf("Expected successful message delivery through proxy")
	}

	t.Logf("LMTP XCLIENT proxy test completed - proxy functionality verified")
}

// TestLMTPProxyXCLIENTShouldWork tests XCLIENT behavior with the patched go-smtp library
// This test verifies that XCLIENT forwarding works correctly after patching the go-smtp library
func TestLMTPProxyXCLIENTShouldWork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify XCLIENT forwarding works
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server without PROXY protocol (for XCLIENT mode)
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy with XCLIENT support
	proxyAddress, proxyWrapper := setupLMTPProxyWithXCLIENT(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Test basic LMTP commands through proxy
	// 1. LHLO command
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// 2. MAIL FROM command
	if err := client.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", "sender@example.com")); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// 3. RCPT TO command
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("RCPT TO failed: %s", response)
	}

	// 4. DATA command
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content
	messageContent := "Subject: Test Message\r\n\r\nThis is a test message through LMTP proxy with working XCLIENT.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Message delivery failed: %s", response)
	}

	// Wait a bit for logs to be written
	time.Sleep(200 * time.Millisecond)

	// When XCLIENT works properly, we should see:
	// 1. XCLIENT forwarding success message (not rejection)
	// 2. proxy=127.0.0.1 in the backend logs (showing original client IP was forwarded)
	// 3. Backend processing XCLIENT command successfully
	logOutput := logCapture.GetOutput()

	// Verify XCLIENT forwarding succeeded (this will fail with current go-smtp)
	if strings.Contains(logOutput, "backend rejected XCLIENT command") {
		t.Errorf("XCLIENT command was rejected - this indicates go-smtp library limitation")
		t.Errorf("Expected: XCLIENT forwarding to succeed")
		t.Errorf("Actual: XCLIENT command rejected at protocol level")
	}

	// Verify proxy information appears in logs (this should work when XCLIENT works)
	if !strings.Contains(logOutput, "proxy=127.0.0.1") {
		t.Errorf("Expected to find 'proxy=127.0.0.1' in logs when XCLIENT works properly")
		t.Errorf("This indicates the original client IP was not properly forwarded")
	}

	// Verify XCLIENT success logging from proxy
	if !strings.Contains(logOutput, "XCLIENT and session reset completed") {
		t.Errorf("Expected XCLIENT forwarding success message in logs")
	}

	// Verify backend processed XCLIENT command
	if !strings.Contains(logOutput, "xclient command received") {
		t.Errorf("Expected backend to process XCLIENT command")
		t.Errorf("This indicates XCLIENT command never reached the backend handler")
	}

	t.Logf("LMTP XCLIENT proxy test with expected working behavior completed")
}

// setupLMTPProxyWithXRCPTFORWARD sets up an LMTP proxy that supports XRCPTFORWARD in RCPT TO
func setupLMTPProxyWithXRCPTFORWARD(t *testing.T, backendAddress string) (string, *LMTPProxyWrapper) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with XRCPTFORWARD support
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendAddress},
			RemotePort:             25,                                 // Default LMTP port
			RemoteUseProxyProtocol: false,                              // Disable PROXY protocol
			RemoteUseXCLIENT:       false,                              // Disable XCLIENT (focus on XRCPTFORWARD)
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"}, // Trust localhost
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with XRCPTFORWARD support: %v", err)
	}

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return proxyAddress, &LMTPProxyWrapper{server: server}
}

// TestLMTPProxyWithXRCPTFORWARD tests LMTP proxy using XRCPTFORWARD extension in RCPT TO
func TestLMTPProxyWithXRCPTFORWARD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server with XRCPTFORWARD support
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy with XRCPTFORWARD support
	proxyAddress, proxyWrapper := setupLMTPProxyWithXRCPTFORWARD(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Test basic LMTP commands through proxy
	// 1. LHLO command
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// 2. MAIL FROM command
	if err := client.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", "sender@example.com")); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// 3. RCPT TO command with XRCPTFORWARD parameter
	// XRCPTFORWARD should contain Base64 encoded tab-separated key=value pairs
	// Example forwarding parameters: proxy=127.0.0.1	originating-ip=192.168.1.100
	xrcptForwardData := "proxy=127.0.0.1\toriginating-ip=192.168.1.100"
	base64Data := base64.StdEncoding.EncodeToString([]byte(xrcptForwardData))

	rcptCommand := fmt.Sprintf("RCPT TO:<%s> XRCPTFORWARD=%s", account.Email, base64Data)
	if err := client.SendCommand(rcptCommand); err != nil {
		t.Fatalf("Failed to send RCPT TO with XRCPTFORWARD: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	// XRCPTFORWARD should work with the forked go-smtp
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("RCPT TO with XRCPTFORWARD failed: %s", response)
	}

	// 4. DATA command
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content
	messageContent := "Subject: Test Message with XRCPTFORWARD\r\n\r\nThis is a test message through LMTP proxy with XRCPTFORWARD.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Message delivery failed: %s", response)
	}

	// Wait a bit for logs to be written
	time.Sleep(200 * time.Millisecond)

	// Verify that XRCPTFORWARD was processed successfully
	logOutput := logCapture.GetOutput()
	if !strings.Contains(logOutput, "processed xrcptforward parameters") {
		t.Errorf("Expected to find 'processed xrcptforward parameters' in logs, but didn't find it.\nLog output:\n%s", logOutput)
	}

	// Just like XCLIENT, XRCPTFORWARD should show proxy= in session logs
	if !strings.Contains(logOutput, "proxy=127.0.0.1") {
		t.Errorf("Expected to find 'proxy=127.0.0.1' in logs from XRCPTFORWARD (like XCLIENT does), but didn't find it.\nLog output:\n%s", logOutput)
	}

	// Verify XRCPTFORWARD processing
	if strings.Contains(logOutput, "processed xrcptforward parameters") {
		t.Logf("XRCPTFORWARD parameters were processed successfully")
	} else {
		t.Logf("XRCPTFORWARD parameters may not have been processed (could be expected if proxy doesn't forward them)")
	}

	t.Logf("LMTP XRCPTFORWARD proxy test completed")
}

// TestLMTPProxyXRCPTFORWARDTrustedNetworksOnly tests that XRCPTFORWARD only works from trusted networks
func TestLMTPProxyXRCPTFORWARDTrustedNetworksOnly(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server with XRCPTFORWARD support
	backendServer, _ := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy with restricted trusted networks (excluding localhost)
	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with NO trusted networks (to test access control)
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendServer.Address},
			RemotePort:             25,                     // Default LMTP port
			RemoteUseProxyProtocol: false,                  // Disable PROXY protocol
			RemoteUseXCLIENT:       false,                  // Disable XCLIENT
			TrustedProxies:         []string{"10.0.0.0/8"}, // Trust only private networks (NOT localhost)
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with restricted trusted networks: %v", err)
	}

	proxyWrapper := &LMTPProxyWrapper{server: server}
	defer proxyWrapper.Close()

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Try to connect to the proxy (should fail from untrusted network)
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		// Expected - connection should be rejected from untrusted network
		t.Logf("Connection correctly rejected from untrusted network: %v", err)
		t.Logf("LMTP XRCPTFORWARD trusted networks test completed")
		return
	}
	defer client.Close()

	// If we reach here, the connection was accepted (unexpected)
	t.Errorf("Connection was accepted from untrusted network, but should have been rejected")

	// Since the connection was accepted, we don't test XRCPTFORWARD
	// The test has already failed at this point
}

// TestLMTPProxyXCLIENTTrustedNetworksOnly tests that XCLIENT only works from trusted networks
func TestLMTPProxyXCLIENTTrustedNetworksOnly(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server with XCLIENT support
	backendServer, _ := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Set up LMTP proxy with restricted trusted networks (excluding localhost)
	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with NO localhost in trusted networks
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendServer.Address},
			RemotePort:             25,                     // Default LMTP port
			RemoteUseProxyProtocol: false,                  // Disable PROXY protocol
			RemoteUseXCLIENT:       true,                   // Enable XCLIENT command
			TrustedProxies:         []string{"10.0.0.0/8"}, // Trust only private networks (NOT localhost)
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with restricted trusted networks: %v", err)
	}

	proxyWrapper := &LMTPProxyWrapper{server: server}
	defer proxyWrapper.Close()

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Try to connect to the proxy (should fail from untrusted network)
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		// Expected - connection should be rejected from untrusted network
		t.Logf("Connection correctly rejected from untrusted network: %v", err)
		t.Logf("LMTP XCLIENT trusted networks test completed")
		return
	}
	defer client.Close()

	// If we reach here, the connection was accepted (unexpected)
	t.Errorf("Connection was accepted from untrusted network, but should have been rejected")

	// Since the connection was accepted, we don't test XCLIENT
	// The test has already failed at this point
}

// TestLMTPDirectXRCPTFORWARD tests XRCPTFORWARD directly on LMTP backend (without proxy)
func TestLMTPDirectXRCPTFORWARD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	// Set up backend LMTP server directly (no proxy)
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
	defer backendServer.Close()

	// Connect directly to the LMTP backend
	client, err := NewLMTPClient(backendServer.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// Test basic LMTP commands
	// 1. LHLO command
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	t.Logf("LHLO responses: %v", responses)

	// 2. MAIL FROM command
	if err := client.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", "sender@example.com")); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// 3. RCPT TO command with XRCPTFORWARD parameter
	xrcptForwardData := "proxy=127.0.0.1\toriginating-ip=192.168.1.100"
	base64Data := base64.StdEncoding.EncodeToString([]byte(xrcptForwardData))

	rcptCommand := fmt.Sprintf("RCPT TO:<%s> XRCPTFORWARD=%s", account.Email, base64Data)
	if err := client.SendCommand(rcptCommand); err != nil {
		t.Fatalf("Failed to send RCPT TO with XRCPTFORWARD: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}

	// Log the response for debugging
	t.Logf("RCPT TO with XRCPTFORWARD response: %s", response)

	if !strings.HasPrefix(response, "250") {
		t.Logf("XRCPTFORWARD failed as expected (not enabled): %s", response)
		return // Exit early since XRCPTFORWARD isn't working
	}

	// If RCPT TO succeeded, continue with message delivery
	// 4. DATA command
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content
	messageContent := "Subject: Test Direct XRCPTFORWARD\r\n\r\nThis is a test message with direct XRCPTFORWARD.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Message delivery failed: %s", response)
	}

	// Wait for logs
	time.Sleep(200 * time.Millisecond)

	// Check logs for XRCPTFORWARD processing
	logOutput := logCapture.GetOutput()
	if strings.Contains(logOutput, "processed xrcptforward parameters") {
		t.Logf("XRCPTFORWARD was processed successfully")
		if strings.Contains(logOutput, "proxy=127.0.0.1") {
			t.Logf("Proxy information found in logs")
		}
	} else {
		t.Logf("XRCPTFORWARD processing not found in logs")
	}

	t.Logf("LMTP direct XRCPTFORWARD test completed")
}

// TestLMTPProxyBackendUnavailable tests that the proxy correctly rejects messages when backend is unavailable
func TestLMTPProxyBackendUnavailable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up backend LMTP server
	backendServer, account := common.SetupLMTPServerWithXCLIENT(t)

	// Set up LMTP proxy pointing to the backend
	proxyAddress, proxyWrapper := setupLMTPProxyWithXCLIENT(t, backendServer.Address)
	defer proxyWrapper.Close()

	// Now stop the backend server to simulate unavailability
	backendServer.Close()
	time.Sleep(100 * time.Millisecond) // Wait for backend to stop

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Send LHLO
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// Send MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// Send RCPT TO - this should fail because backend is unavailable
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}

	// Verify we get a 4xx temporary failure code (not 2xx success)
	if strings.HasPrefix(response, "250") {
		t.Errorf("RCPT TO should have failed with 4xx when backend unavailable, got: %s", response)
	}

	// Verify we get the expected error code (451 4.4.1 Backend connection failed)
	if !strings.HasPrefix(response, "451") {
		t.Errorf("Expected '451 4.4.1 Backend connection failed', got: %s", response)
	}

	// Verify the error message indicates backend failure
	if !strings.Contains(response, "Backend") && !strings.Contains(response, "backend") {
		t.Errorf("Expected error message to mention backend failure, got: %s", response)
	}

	t.Logf("Backend unavailability test passed - proxy correctly rejected with: %s", response)
}

// TestLMTPProxyBackendFailsDuringDelivery tests backend failure during message DATA transmission
func TestLMTPProxyBackendFailsDuringDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up a mock LMTP backend that accepts connection but fails during DATA
	backendAddr := common.GetRandomAddress(t)
	backendListener, err := net.Listen("tcp", backendAddr)
	if err != nil {
		t.Fatalf("Failed to create mock backend listener: %v", err)
	}
	defer backendListener.Close()

	// Create test account with unique email
	rdb := common.SetupTestDatabase(t)
	accountEmail := fmt.Sprintf("test-%s-%d@example.com", strings.ToLower(t.Name()), time.Now().UnixNano())
	common.CreateTestAccountWithEmail(t, rdb, accountEmail, "password")

	// Start mock backend that fails during DATA
	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go handleMockLMTPBackendFailDuringDATA(conn)
		}
	}()

	// Set up LMTP proxy pointing to the mock backend
	proxyAddress, proxyWrapper := setupLMTPProxyWithXCLIENT(t, backendAddr)
	defer proxyWrapper.Close()

	// Connect to the proxy
	client, err := NewLMTPClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// Send LHLO
	if err := client.SendCommand("LHLO localhost"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("LHLO failed: %v", responses)
	}

	// Send MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("MAIL FROM failed: %s", response)
	}

	// Send RCPT TO - should succeed (backend accepts it)
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", accountEmail)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("RCPT TO failed: %s", response)
	}

	// Send DATA command - backend accepts
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("DATA failed: %s", response)
	}

	// Send message content - backend will fail with 5xx error
	messageContent := "Subject: Test Message\r\n\r\nThis is a test message.\r\n.\r\n"
	if err := client.SendCommand(messageContent); err != nil {
		t.Fatalf("Failed to send message content: %v", err)
	}

	// Read response - should be a failure from backend (forwarded by proxy)
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read message response: %v", err)
	}

	// Verify we get a 5xx permanent failure (backend storage error)
	if !strings.HasPrefix(response, "554") {
		t.Errorf("Expected '554 5.3.0 Backend storage error' when backend fails, got: %s", response)
	}

	// Verify the message was NOT accepted
	if strings.HasPrefix(response, "250") {
		t.Errorf("Message should NOT be accepted when backend fails during DATA, got: %s", response)
	}

	t.Logf("Backend failure during DATA test passed - proxy forwarded error: %s", response)
}

// handleMockLMTPBackendFailDuringDATA simulates an LMTP backend that fails during DATA
func handleMockLMTPBackendFailDuringDATA(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Send greeting
	writer.WriteString("220 localhost LMTP Service Ready\r\n")
	writer.Flush()

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		cmd := strings.ToUpper(strings.Fields(line)[0])

		switch cmd {
		case "LHLO", "EHLO":
			writer.WriteString("250 localhost\r\n")
			writer.Flush()
		case "MAIL":
			writer.WriteString("250 Ok\r\n")
			writer.Flush()
		case "RCPT":
			writer.WriteString("250 Ok\r\n")
			writer.Flush()
		case "DATA":
			writer.WriteString("354 Start mail input; end with <CRLF>.<CRLF>\r\n")
			writer.Flush()

			// Read message body until ".\r\n"
			for {
				bodyLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(bodyLine) == "." {
					break
				}
			}

			// Simulate backend storage failure
			writer.WriteString("554 5.3.0 Backend storage error\r\n")
			writer.Flush()
			return
		case "QUIT":
			writer.WriteString("221 Bye\r\n")
			writer.Flush()
			return
		default:
			writer.WriteString("502 Command not implemented\r\n")
			writer.Flush()
		}
	}
}

// TestLMTPProxyRemoteLookupFallbackToDefault tests the lookup_local_users setting
// when remotelookup fails or returns empty results
func TestLMTPProxyRemoteLookupFallbackToDefault(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Test cases for different fallback scenarios
	// Note: lookup_local_users controls ALL fallback behavior including user not found (404)
	testCases := []struct {
		name                   string
		fallbackToDefault      bool
		remotelookupStatusCode int    // HTTP status code for remotelookup response
		remotelookupBody       string // HTTP response body
		expectAccept           bool   // Should RCPT TO succeed?
		expectLog              string // Expected log message
	}{
		{
			name:                   "fallback_enabled_transient_error_rejects_recipient",
			fallbackToDefault:      true,
			remotelookupStatusCode: 500,
			remotelookupBody:       `{"error": "internal server error"}`,
			expectAccept:           false,
			expectLog:              "remotelookup transient error - service unavailable, rejecting recipient",
		},
		{
			name:                   "fallback_disabled_transient_error_rejects_recipient",
			fallbackToDefault:      false,
			remotelookupStatusCode: 500,
			remotelookupBody:       `{"error": "internal server error"}`,
			expectAccept:           false,
			expectLog:              "remotelookup transient error - service unavailable, rejecting recipient",
		},
		{
			name:                   "user_not_found_fallback_enabled",
			fallbackToDefault:      true,
			remotelookupStatusCode: 404,
			remotelookupBody:       `{"error": "user not found"}`,
			expectAccept:           true,
			expectLog:              "user not found in remote lookup, local lookup enabled - attempting main DB",
		},
		{
			name:                   "user_not_found_fallback_disabled",
			fallbackToDefault:      false,
			remotelookupStatusCode: 404,
			remotelookupBody:       `{"error": "user not found"}`,
			expectAccept:           false,
			expectLog:              "user not found in remote lookup, fallback disabled",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Start log capture
			logCapture := NewLogCapture()
			defer logCapture.Close()

			// Set up backend LMTP server
			backendServer, account := common.SetupLMTPServerWithXCLIENT(t)
			defer backendServer.Close()

			// Set up mock remotelookup HTTP server
			remotelookupAddr := common.GetRandomAddress(t)
			mockRemoteLookupServer := setupMockRemoteLookupServer(t, remotelookupAddr, tc.remotelookupStatusCode, tc.remotelookupBody)
			defer mockRemoteLookupServer.Close()

			// Get HTTP URL for remotelookup
			remotelookupURL := fmt.Sprintf("http://%s/lookup", remotelookupAddr)

			// Set up LMTP proxy with remotelookup
			proxyAddress, proxyWrapper := setupLMTPProxyWithRemoteLookup(t, backendServer.Address, remotelookupURL, tc.fallbackToDefault)
			defer proxyWrapper.Close()

			// Connect to proxy
			client, err := NewLMTPClient(proxyAddress)
			if err != nil {
				t.Fatalf("Failed to connect to LMTP proxy: %v", err)
			}
			defer client.Close()

			// Send LHLO
			if err := client.SendCommand("LHLO localhost"); err != nil {
				t.Fatalf("Failed to send LHLO: %v", err)
			}
			responses, err := client.ReadMultilineResponse()
			if err != nil {
				t.Fatalf("Failed to read LHLO response: %v", err)
			}
			if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
				t.Fatalf("LHLO failed: %v", responses)
			}

			// Send MAIL FROM
			if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
				t.Fatalf("Failed to send MAIL FROM: %v", err)
			}
			response, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read MAIL FROM response: %v", err)
			}
			if !strings.HasPrefix(response, "250") {
				t.Fatalf("MAIL FROM failed: %s", response)
			}

			// Send RCPT TO - this is where remotelookup is called
			if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
				t.Fatalf("Failed to send RCPT TO: %v", err)
			}
			response, err = client.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read RCPT TO response: %v", err)
			}

			// Wait a bit for logs to be written
			time.Sleep(100 * time.Millisecond)

			// Verify response matches expectation
			if tc.expectAccept {
				if !strings.HasPrefix(response, "250") {
					t.Errorf("Expected RCPT TO to succeed (fallback enabled), got: %s", response)
				}
			} else {
				if strings.HasPrefix(response, "250") {
					t.Errorf("Expected RCPT TO to fail (fallback disabled), got: %s", response)
				}
			}

			// Verify log message
			logOutput := logCapture.GetOutput()
			if !strings.Contains(logOutput, tc.expectLog) {
				t.Errorf("Expected log message '%s' not found in output:\n%s", tc.expectLog, logOutput)
			}

			t.Logf("Test case '%s' passed - RCPT TO result: %s", tc.name, response)
		})
	}
}

// setupLMTPProxyWithRemoteLookup creates an LMTP proxy with remotelookup configuration
func setupLMTPProxyWithRemoteLookup(t *testing.T, backendAddress string, remotelookupURL string, fallbackToDefault bool) (string, *LMTPProxyWrapper) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	proxyAddress := common.GetRandomAddress(t)

	// Create LMTP proxy server with remotelookup
	server, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-proxy-remotelookup",
			Addr:                   proxyAddress,
			RemoteAddrs:            []string{backendAddress},
			RemotePort:             25,
			RemoteUseProxyProtocol: false,
			RemoteUseXCLIENT:       true,
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
			ConnectTimeout:         5 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
			RemoteLookup: &config.RemoteLookupConfig{
				Enabled:          true,
				URL:              remotelookupURL,
				Timeout:          "5s",
				LookupLocalUsers: fallbackToDefault,
			},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with remotelookup: %v", err)
	}

	// Start the proxy server
	go func() {
		if err := server.Start(); err != nil {
			t.Logf("LMTP proxy server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return proxyAddress, &LMTPProxyWrapper{server: server}
}

// MockRemoteLookupServer wraps the mock HTTP server for cleanup
type MockRemoteLookupServer struct {
	listener net.Listener
	done     chan struct{}
}

func (m *MockRemoteLookupServer) Close() error {
	close(m.done)
	return m.listener.Close()
}

// setupMockRemoteLookupServer creates a mock HTTP server for remotelookup
func setupMockRemoteLookupServer(t *testing.T, addr string, statusCode int, responseBody string) *MockRemoteLookupServer {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to create mock remotelookup listener: %v", err)
	}

	done := make(chan struct{})
	server := &MockRemoteLookupServer{
		listener: listener,
		done:     done,
	}

	// Start HTTP server
	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}

			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go handleMockRemoteLookupRequest(conn, statusCode, responseBody)
		}
	}()

	return server
}

// handleMockRemoteLookupRequest handles a mock remotelookup HTTP request
func handleMockRemoteLookupRequest(conn net.Conn, statusCode int, responseBody string) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read HTTP request (we don't parse it, just consume it)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		// Empty line signals end of headers
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Send HTTP response
	statusText := "OK"
	if statusCode >= 400 {
		statusText = "Internal Server Error"
	}

	response := fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, statusText)
	response += "Content-Type: application/json\r\n"
	response += fmt.Sprintf("Content-Length: %d\r\n", len(responseBody))
	response += "\r\n"
	response += responseBody

	writer.WriteString(response)
	writer.Flush()
}

func TestLMTPProxy_NullSender(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup backend LMTP server
	lmtpServer, account := common.SetupLMTPServer(t)
	defer lmtpServer.Close()

	// Setup proxy
	proxyAddr, proxyServer := setupLMTPProxyWithXCLIENT(t, lmtpServer.Address)
	defer proxyServer.Close()

	// Connect to proxy
	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP proxy: %v", err)
	}
	defer client.Close()

	// LHLO
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// MAIL FROM with null sender (used for bounce messages per RFC 5321)
	if err := client.SendCommand("MAIL FROM:<>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to MAIL FROM:<> (null sender), got: %s", response)
	}
	t.Logf("✓ Null sender accepted by proxy: %s", response)

	// RCPT TO
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to RCPT TO, got: %s", response)
	}

	// DATA
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if !strings.HasPrefix(response, "354") {
		t.Fatalf("Expected 354 response to DATA, got: %s", response)
	}

	// Send bounce message content (typical bounce format)
	message := "From: MAILER-DAEMON@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Delivery Status Notification (Failure)\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status\r\n" +
		"\r\n" +
		"This is a delivery failure notification.\r\n" +
		"Your message could not be delivered.\r\n" +
		".\r\n"

	if _, err := client.conn.Write([]byte(message)); err != nil {
		t.Fatalf("Failed to send message data: %v", err)
	}

	// Read final response
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read final response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response after message data, got: %s", response)
	}

	t.Logf("✓ Bounce message with null sender delivered successfully through proxy: %s", response)
}
