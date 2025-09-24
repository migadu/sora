//go:build integration

package pop3_test

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// LogCapture helps capture log output for verification
type LogCapture struct {
	original *os.File
	buffer   *bytes.Buffer
}

// NewLogCapture creates a new log capture that redirects standard log output to a buffer
func NewLogCapture() *LogCapture {
	lc := &LogCapture{
		original: os.Stderr,
		buffer:   &bytes.Buffer{},
	}

	// Redirect log output to our buffer
	log.SetOutput(lc.buffer)
	return lc
}

// Stop restores the original log output and returns captured logs
func (lc *LogCapture) Stop() string {
	log.SetOutput(lc.original)
	return lc.buffer.String()
}

// ContainsProxyLog checks if the captured logs contain proxy= entries
func (lc *LogCapture) ContainsProxyLog() bool {
	logs := lc.buffer.String()
	return strings.Contains(logs, "proxy=")
}

// POP3Client provides a simple POP3 client for testing
type POP3Client struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewPOP3Client(address string) (*POP3Client, error) {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}

	client := &POP3Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}

	// Read greeting
	response, err := client.ReadResponse()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("unexpected greeting: %s", response)
	}

	return client, nil
}

func (c *POP3Client) SendCommand(command string) error {
	_, err := c.conn.Write([]byte(command + "\r\n"))
	return err
}

func (c *POP3Client) ReadResponse() (string, error) {
	response, err := c.reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(response), nil
}

func (c *POP3Client) ReadMultilineResponse() ([]string, error) {
	var responses []string
	for {
		response, err := c.ReadResponse()
		if err != nil {
			return nil, err
		}
		if response == "." {
			break
		}
		responses = append(responses, response)
	}
	return responses, nil
}

func (c *POP3Client) Close() error {
	c.SendCommand("QUIT")
	c.ReadResponse() // Read quit response
	return c.conn.Close()
}

func TestPOP3_BasicConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	t.Logf("Successfully connected to POP3 server at %s", server.Address)
}

func TestPOP3_UserPass(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify no proxy= entries (direct backend connection)
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if strings.Contains(logs, "proxy=") {
			t.Errorf("Expected NO 'proxy=' entries in logs for direct backend connection, but found some. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified no 'proxy=' entries in logs for direct backend connection")
		}
	}()

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Send USER command
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to USER, got: %s", response)
	}

	// Send PASS command
	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	response, err = client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to PASS, got: %s", response)
	}

	t.Log("USER/PASS authentication successful")
}

func TestPOP3_InvalidLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Start log capture to verify no proxy= entries (direct backend connection)
	logCapture := NewLogCapture()
	defer func() {
		logs := logCapture.Stop()
		if strings.Contains(logs, "proxy=") {
			t.Errorf("Expected NO 'proxy=' entries in logs for direct backend connection, but found some. Logs:\n%s", logs)
		} else {
			t.Log("✓ Verified no 'proxy=' entries in logs for direct backend connection")
		}
	}()

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Test invalid user
	if err := client.SendCommand("USER nonexistent@example.com"); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	// Some servers may accept USER and fail on PASS, others may fail on USER
	if strings.HasPrefix(response, "+OK") {
		// Server accepted USER, try PASS
		if err := client.SendCommand("PASS password"); err != nil {
			t.Fatalf("Failed to send PASS: %v", err)
		}
		response, err = client.ReadResponse()
		if err != nil {
			t.Fatalf("Failed to read PASS response: %v", err)
		}
		if strings.HasPrefix(response, "+OK") {
			t.Fatal("Expected authentication to fail for invalid user")
		}
	}

	t.Logf("Invalid user correctly rejected: %s", response)

	// Test valid user with invalid password
	client2, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to reconnect to POP3 server: %v", err)
	}
	defer client2.Close()

	if err := client2.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if _, err := client2.ReadResponse(); err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	if err := client2.SendCommand("PASS wrongpassword"); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	response, err = client2.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}
	if strings.HasPrefix(response, "+OK") {
		t.Fatal("Expected authentication to fail for wrong password")
	}

	t.Logf("Wrong password correctly rejected: %s", response)
}

func TestPOP3_STAT(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Authenticate
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	// Send STAT command
	if err := client.SendCommand("STAT"); err != nil {
		t.Fatalf("Failed to send STAT: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read STAT response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to STAT, got: %s", response)
	}

	// Parse STAT response (should be "+OK <count> <size>")
	parts := strings.Fields(response)
	if len(parts) < 3 {
		t.Fatalf("Invalid STAT response format: %s", response)
	}

	t.Logf("STAT successful: %s", response)
}

func TestPOP3_LIST(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Authenticate
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	// Send LIST command
	if err := client.SendCommand("LIST"); err != nil {
		t.Fatalf("Failed to send LIST: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read LIST response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to LIST, got: %s", response)
	}

	// Read multiline response
	messages, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read LIST messages: %v", err)
	}

	t.Logf("LIST successful, found %d messages", len(messages))
}

func TestPOP3_CAPA(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Send CAPA command
	if err := client.SendCommand("CAPA"); err != nil {
		t.Fatalf("Failed to send CAPA: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read CAPA response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to CAPA, got: %s", response)
	}

	// Read capabilities
	capabilities, err := client.ReadMultilineResponse()
	if err != nil {
		t.Fatalf("Failed to read CAPA capabilities: %v", err)
	}

	t.Logf("CAPA successful, server capabilities:")
	for _, cap := range capabilities {
		t.Logf("  %s", cap)
	}

	// Check for required capabilities
	hasUser := false
	for _, cap := range capabilities {
		if strings.ToUpper(cap) == "USER" {
			hasUser = true
			break
		}
	}
	if !hasUser {
		t.Log("Note: USER capability not explicitly listed (may be implicit)")
	}
}

func TestPOP3_NOOP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}
	defer client.Close()

	// Authenticate
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	// Send NOOP command
	if err := client.SendCommand("NOOP"); err != nil {
		t.Fatalf("Failed to send NOOP: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read NOOP response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to NOOP, got: %s", response)
	}

	t.Logf("NOOP successful: %s", response)
}

func TestPOP3_MultipleConnections(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	// Test multiple concurrent connections
	numConnections := 3
	done := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(connID int) {
			client, err := NewPOP3Client(server.Address)
			if err != nil {
				done <- fmt.Errorf("connection %d: failed to connect: %v", connID, err)
				return
			}
			defer client.Close()

			// Authenticate
			if err := client.SendCommand("USER " + account.Email); err != nil {
				done <- fmt.Errorf("connection %d: failed to send USER: %v", connID, err)
				return
			}
			if _, err := client.ReadResponse(); err != nil {
				done <- fmt.Errorf("connection %d: failed to read USER response: %v", connID, err)
				return
			}

			if err := client.SendCommand("PASS " + account.Password); err != nil {
				done <- fmt.Errorf("connection %d: failed to send PASS: %v", connID, err)
				return
			}
			if _, err := client.ReadResponse(); err != nil {
				done <- fmt.Errorf("connection %d: failed to read PASS response: %v", connID, err)
				return
			}

			// Test STAT command
			if err := client.SendCommand("STAT"); err != nil {
				done <- fmt.Errorf("connection %d: failed to send STAT: %v", connID, err)
				return
			}
			if _, err := client.ReadResponse(); err != nil {
				done <- fmt.Errorf("connection %d: failed to read STAT response: %v", connID, err)
				return
			}

			done <- nil
		}(i)
	}

	// Wait for all connections to complete
	for i := 0; i < numConnections; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
	t.Logf("Successfully handled %d concurrent POP3 connections", numConnections)
}

func TestPOP3_QUIT(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	client, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 server: %v", err)
	}

	// Authenticate
	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}

	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	// Send QUIT command
	if err := client.SendCommand("QUIT"); err != nil {
		t.Fatalf("Failed to send QUIT: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read QUIT response: %v", err)
	}
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("Expected +OK response to QUIT, got: %s", response)
	}

	t.Logf("QUIT successful: %s", response)

	// Connection should be closed after QUIT
	client.conn.Close()
}
