//go:build integration

package lmtp_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// LogCapture captures log output for verification
type LogCapture struct {
	buffer *bytes.Buffer
	writer io.Writer
	oldLog *log.Logger
	oldOut io.Writer
}

func NewLogCapture() *LogCapture {
	buffer := &bytes.Buffer{}
	writer := io.MultiWriter(os.Stderr, buffer)

	// Save old settings
	oldOut := log.Writer()
	oldLog := log.New(oldOut, "", log.LstdFlags)

	// Set new logger to capture output
	log.SetOutput(writer)

	return &LogCapture{
		buffer: buffer,
		writer: writer,
		oldLog: oldLog,
		oldOut: oldOut,
	}
}

func (lc *LogCapture) GetOutput() string {
	return lc.buffer.String()
}

func (lc *LogCapture) Close() {
	log.SetOutput(lc.oldOut)
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
	return strings.TrimSpace(response), nil
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

// ReadDataResponses reads the expected number of individual responses after DATA
// In LMTP, each recipient gets its own response line
func (c *LMTPClient) ReadDataResponses(expectedCount int) ([]string, error) {
	var responses []string
	for i := 0; i < expectedCount; i++ {
		response, err := c.ReadResponse()
		if err != nil {
			return responses, err
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func (c *LMTPClient) Close() error {
	c.SendCommand("QUIT")
	c.ReadResponse() // Read quit response
	return c.conn.Close()
}

func TestLMTP_BasicConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServer(t)
	defer server.Close()

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	t.Logf("Successfully connected to LMTP server at %s", server.Address)
}

func TestLMTP_LHLO(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServer(t)
	defer server.Close()

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// Send LHLO command
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}

	responses, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// Check that we got a 250 response
	if len(responses) == 0 || !strings.HasPrefix(responses[0], "250") {
		t.Fatalf("Expected 250 response to LHLO, got: %v", responses)
	}

	t.Logf("LHLO successful, server responded with %d lines", len(responses))
	for i, response := range responses {
		t.Logf("LHLO response %d: %s", i+1, response)
	}
}

func TestLMTP_SimpleDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start capture to verify no proxy logs
	logCapture := NewLogCapture()
	defer logCapture.Close()

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// LHLO
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to MAIL FROM, got: %s", response)
	}

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

	// Send message content
	message := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Message\r\n" +
		"\r\n" +
		"This is a test message.\r\n" +
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

	// Wait a bit for logs to be written
	time.Sleep(200 * time.Millisecond)

	// Verify that NO proxy information appears in logs (direct backend connection)
	logOutput := logCapture.GetOutput()
	if strings.Contains(logOutput, "proxy=") {
		t.Errorf("Expected no 'proxy=' in logs for direct backend connection, but found it.\nLog output:\n%s", logOutput)
	}

	t.Log("Message delivered successfully")
}

func TestLMTP_InvalidRecipient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServer(t)
	defer server.Close()

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// LHLO
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to MAIL FROM, got: %s", response)
	}

	// RCPT TO with invalid recipient
	if err := client.SendCommand("RCPT TO:<nonexistent@example.com>"); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if strings.HasPrefix(response, "250") {
		t.Fatalf("Expected error response to invalid RCPT TO, got: %s", response)
	}

	t.Logf("RCPT TO correctly rejected invalid recipient: %s", response)
}

func TestLMTP_MultipleRecipients(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	// Create a second test account
	account2 := common.CreateTestAccount(t, server.ResilientDB)

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// LHLO
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to MAIL FROM, got: %s", response)
	}

	// First RCPT TO
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send first RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read first RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to first RCPT TO, got: %s", response)
	}

	// Second RCPT TO
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account2.Email)); err != nil {
		t.Fatalf("Failed to send second RCPT TO: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read second RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to second RCPT TO, got: %s", response)
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

	// Send message content
	message := "From: sender@example.com\r\n" +
		"To: " + account.Email + ", " + account2.Email + "\r\n" +
		"Subject: Test Message to Multiple Recipients\r\n" +
		"\r\n" +
		"This is a test message to multiple recipients.\r\n" +
		".\r\n"

	if _, err := client.conn.Write([]byte(message)); err != nil {
		t.Fatalf("Failed to send message data: %v", err)
	}

	// Read final response - should get one response per recipient
	// In LMTP, after DATA, we get one response line per recipient
	responses, err := client.ReadDataResponses(2) // Expecting 2 recipients
	if err != nil {
		t.Fatalf("Failed to read final responses: %v", err)
	}

	if len(responses) < 2 {
		t.Fatalf("Expected at least 2 responses for 2 recipients, got %d", len(responses))
	}

	for i, response := range responses {
		if !strings.HasPrefix(response, "250") {
			t.Errorf("Response %d: Expected 250, got: %s", i+1, response)
		}
	}

	t.Logf("Message delivered successfully to %d recipients", len(responses))
}

func TestLMTP_Reset(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()

	client, err := NewLMTPClient(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	// LHLO
	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// MAIL FROM
	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}

	// RCPT TO
	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}

	// RSET (reset)
	if err := client.SendCommand("RSET"); err != nil {
		t.Fatalf("Failed to send RSET: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RSET response: %v", err)
	}
	if !strings.HasPrefix(response, "250") {
		t.Fatalf("Expected 250 response to RSET, got: %s", response)
	}

	// Try to send DATA after reset (should fail)
	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}
	if strings.HasPrefix(response, "354") {
		t.Fatal("DATA command should fail after RSET without new MAIL/RCPT commands")
	}

	t.Logf("RSET command worked correctly: %s", response)
}
