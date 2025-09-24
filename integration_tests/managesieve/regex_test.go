//go:build integration

package managesieve

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

func TestManageSieveRegexExtension(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create test database and account with regex extension enabled
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create ManageSieve server with regex extension enabled
	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        true, // Enable PLAIN auth for testing
			SupportedExtensions: []string{"fileinto", "vacation", "regex"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	defer func() {
		server.Close()
		select {
		case <-errChan:
		default:
		}
	}()

	// Connect and authenticate
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Authenticate (this handles reading the greeting too)
	authenticateManageSieve(t, reader, writer, account)

	// Test 1: Script with regex extension should succeed
	t.Log("=== Testing script with regex extension ===")
	regexScript := `require ["fileinto", "regex"]; if header :regex "subject" ".*test.*" { fileinto "Test"; } else { fileinto "INBOX"; }`

	// Use literal string format: PUTSCRIPT "name" {length+}
	literalCommand := fmt.Sprintf("PUTSCRIPT \"regex_test\" {%d+}", len(regexScript))
	writer.WriteString(literalCommand + "\r\n")
	writer.Flush()

	// Wait for continuation response (+)
	continuationResponse := readResponse(t, reader)
	if !strings.Contains(continuationResponse, "+") {
		t.Errorf("Expected continuation response, got: %s", continuationResponse)
	}

	// Send the script content
	writer.WriteString(regexScript + "\r\n")
	writer.Flush()

	// Read the final response
	response := readResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("Script with regex extension should succeed: %s", response)
	} else {
		t.Logf("Regex extension script accepted: %s", strings.TrimSpace(response))
	}

	// Test 2: Script without regex extension but using regex syntax should fail
	t.Log("=== Testing regex syntax without regex extension ===")

	// Create a server without regex extension
	address2 := common.GetRandomAddress(t)
	server2, err := managesieve.New(
		context.Background(),
		"test2",
		"localhost",
		address2,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        true,                             // Enable PLAIN auth for testing
			SupportedExtensions: []string{"fileinto", "vacation"}, // No regex
		},
	)
	if err != nil {
		t.Fatalf("Failed to create second ManageSieve server: %v", err)
	}

	errChan2 := make(chan error, 1)
	go func() {
		server2.Start(errChan2)
	}()

	time.Sleep(100 * time.Millisecond)

	defer func() {
		server2.Close()
		select {
		case <-errChan2:
		default:
		}
	}()

	// Connect to second server
	conn2, err := net.Dial("tcp", address2)
	if err != nil {
		t.Fatalf("Failed to connect to second ManageSieve server: %v", err)
	}
	defer conn2.Close()

	reader2 := bufio.NewReader(conn2)
	writer2 := bufio.NewWriter(conn2)

	// Authenticate
	authenticateManageSieve(t, reader2, writer2, account)

	// Try to upload script with regex extension
	literalCommand2 := fmt.Sprintf("PUTSCRIPT \"regex_fail_test\" {%d+}", len(regexScript))
	writer2.WriteString(literalCommand2 + "\r\n")
	writer2.Flush()

	// Wait for continuation response (+)
	continuationResponse2 := readResponse(t, reader2)
	if !strings.Contains(continuationResponse2, "+") {
		t.Errorf("Expected continuation response, got: %s", continuationResponse2)
	}

	// Send the script content
	writer2.WriteString(regexScript + "\r\n")
	writer2.Flush()

	// Read the final response
	response2 := readResponse(t, reader2)
	if strings.Contains(response2, "OK") {
		t.Errorf("Script with regex extension should fail when regex is not supported: %s", response2)
	} else {
		t.Logf("Regex extension script correctly rejected: %s", strings.TrimSpace(response2))
	}
}
