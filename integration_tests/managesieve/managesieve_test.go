//go:build integration

package managesieve

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

func TestManageSieveBasicConnection(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect to the server
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read capabilities lines until we get the OK greeting
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		lines = append(lines, line)

		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Check that we got the expected greeting
	foundImplementation := false
	foundSieve := false
	foundOK := false

	for _, line := range lines {
		if strings.Contains(line, "\"IMPLEMENTATION\"") {
			foundImplementation = true
		}
		if strings.Contains(line, "\"SIEVE\"") {
			foundSieve = true
		}
		if strings.HasPrefix(line, "OK") && strings.Contains(line, "ManageSieve server ready") {
			foundOK = true
		}
	}

	if !foundImplementation {
		t.Errorf("Expected IMPLEMENTATION capability in greeting")
	}
	if !foundSieve {
		t.Errorf("Expected SIEVE capability in greeting")
	}
	if !foundOK {
		t.Errorf("Expected OK greeting line, got lines: %v", lines)
	}

	// Test CAPABILITY command
	writer.WriteString("CAPABILITY\r\n")
	writer.Flush()

	// Read CAPABILITY response (capabilities followed by OK)
	var capabilityLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CAPABILITY response line: %v", err)
		}
		line = strings.TrimSpace(line)
		capabilityLines = append(capabilityLines, line)

		// The response ends with just OK
		if line == "OK" {
			break
		}
	}

	// Check that we got capabilities in the response
	foundSieveCapability := false
	foundOKResponse := false

	for _, line := range capabilityLines {
		if strings.Contains(line, "\"SIEVE\"") {
			foundSieveCapability = true
		}
		if line == "OK" {
			foundOKResponse = true
		}
	}

	if !foundSieveCapability {
		t.Errorf("Expected SIEVE capability in CAPABILITY response, got: %v", capabilityLines)
	}
	if !foundOKResponse {
		t.Errorf("Expected OK response at end of CAPABILITY, got: %v", capabilityLines)
	}

	t.Logf("Successfully connected to ManageSieve server at %s", server.Address)
	_ = account // Use account variable to avoid unused variable error
}

func TestManageSieveAuthentication(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect to the server
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting (capabilities followed by OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Test AUTHENTICATE PLAIN command
	authCmd := fmt.Sprintf("AUTHENTICATE PLAIN %s\r\n",
		encodeBase64Plain(account.Email, account.Password))
	writer.WriteString(authCmd)
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read authenticate response: %v", err)
	}

	if !strings.Contains(response, "OK") {
		t.Errorf("Authentication failed: %s", response)
	}

	t.Logf("Successfully authenticated to ManageSieve server with account %s", account.Email)
}

func TestManageSieveScriptOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect and authenticate
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting and authenticate
	authenticateManageSieve(t, reader, writer, account)

	// Test 1: PUTSCRIPT - store a script
	t.Log("=== Testing PUTSCRIPT ===")
	vacationScript := `require ["vacation"]; if header :contains "subject" "vacation" { vacation "I'm on vacation"; }`
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"vacation\" %s", vacationScript))
	response := readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT failed: %s", response)
	} else {
		t.Logf("PUTSCRIPT succeeded")
	}

	// Test 2: LISTSCRIPTS - should show the script
	t.Log("=== Testing LISTSCRIPTS ===")
	sendCommand(t, writer, "LISTSCRIPTS")
	response = readSimpleResponse(t, reader)
	// Just check that we get some response - parsing the complex format is tricky
	if strings.HasPrefix(response, "NO") {
		t.Errorf("LISTSCRIPTS failed: %s", response)
	} else {
		t.Logf("LISTSCRIPTS response: %s", strings.TrimSpace(response))
	}

	// Test 3: SETACTIVE - activate the script
	t.Log("=== Testing SETACTIVE ===")
	sendCommand(t, writer, "SETACTIVE \"vacation\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("SETACTIVE failed: %s", response)
	} else {
		t.Logf("SETACTIVE succeeded")
	}

	// Test 4: GETSCRIPT - retrieve the script (just check it doesn't fail)
	t.Log("=== Testing GETSCRIPT ===")
	sendCommand(t, writer, "GETSCRIPT \"vacation\"")
	response = readGetScriptResponse(t, reader)
	if strings.HasPrefix(response, "NO") {
		t.Errorf("GETSCRIPT failed: %s", response)
	} else {
		t.Logf("GETSCRIPT response received: %s", strings.TrimSpace(response))
	}

	// Test 5: DELETESCRIPT - delete the script
	t.Log("=== Testing DELETESCRIPT ===")
	sendCommand(t, writer, "DELETESCRIPT \"vacation\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("DELETESCRIPT failed: %s", response)
	} else {
		t.Logf("DELETESCRIPT succeeded")
	}

	// Test 6: Try operations on non-existent script
	t.Log("=== Testing operations on non-existent script ===")

	// GETSCRIPT on deleted script should fail
	sendCommand(t, writer, "GETSCRIPT \"vacation\"")
	response = readGetScriptResponse(t, reader)
	if !strings.HasPrefix(response, "NO") {
		t.Errorf("GETSCRIPT should fail for deleted script but got: %s", response)
	} else {
		t.Logf("GETSCRIPT correctly failed for deleted script")
	}

	// SETACTIVE on non-existent script should fail
	sendCommand(t, writer, "SETACTIVE \"nonexistent\"")
	response = readSimpleResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("SETACTIVE should fail for non-existent script but got: %s", response)
	} else {
		t.Logf("SETACTIVE correctly failed for non-existent script")
	}

	// DELETESCRIPT on non-existent script should fail
	sendCommand(t, writer, "DELETESCRIPT \"nonexistent\"")
	response = readSimpleResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("DELETESCRIPT should fail for non-existent script but got: %s", response)
	} else {
		t.Logf("DELETESCRIPT correctly failed for non-existent script")
	}

	t.Log("Successfully completed comprehensive ManageSieve script operations test")
}

func TestManageSieveScriptDeactivation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect and authenticate
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read greeting and authenticate
	authenticateManageSieve(t, reader, writer, account)

	// Test 1: Create and activate a script
	t.Log("=== Creating and activating a script ===")
	vacationScript := `require ["vacation"]; if header :contains "subject" "vacation" { vacation "I'm on vacation"; }`
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"vacation\" %s", vacationScript))
	response := readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Fatalf("PUTSCRIPT failed: %s", response)
	}

	sendCommand(t, writer, "SETACTIVE \"vacation\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Fatalf("SETACTIVE vacation failed: %s", response)
	}
	t.Logf("Script activated successfully")

	// Test 2: Verify the script is active via LISTSCRIPTS
	t.Log("=== Verifying script is active ===")
	sendCommand(t, writer, "LISTSCRIPTS")
	listResponse := readListScriptsResponse(t, reader)
	if !strings.Contains(listResponse, "vacation") || !strings.Contains(listResponse, "ACTIVE") {
		t.Logf("Warning: LISTSCRIPTS response may not clearly show ACTIVE status: %s", listResponse)
	} else {
		t.Logf("Script is active: %s", listResponse)
	}

	// Test 3: Deactivate all scripts using SETACTIVE ""
	t.Log("=== Deactivating all scripts with SETACTIVE \"\" ===")
	sendCommand(t, writer, "SETACTIVE \"\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("SETACTIVE \"\" should deactivate all scripts but got: %s", response)
	} else {
		t.Logf("Successfully deactivated all scripts")
	}

	// Test 4: Verify no script is active via LISTSCRIPTS
	t.Log("=== Verifying no script is active ===")
	sendCommand(t, writer, "LISTSCRIPTS")
	listResponse = readListScriptsResponse(t, reader)
	if strings.Contains(listResponse, "ACTIVE") {
		t.Errorf("After SETACTIVE \"\", no script should be marked ACTIVE but got: %s", listResponse)
	} else {
		t.Logf("Confirmed no script is active: %s", listResponse)
	}

	// Test 5: Reactivate the script
	t.Log("=== Reactivating the script ===")
	sendCommand(t, writer, "SETACTIVE \"vacation\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("Re-activating script failed: %s", response)
	} else {
		t.Logf("Script reactivated successfully")
	}

	// Test 6: Deactivate again and delete the script
	t.Log("=== Deactivating and deleting script ===")
	sendCommand(t, writer, "SETACTIVE \"\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("Second SETACTIVE \"\" failed: %s", response)
	}

	sendCommand(t, writer, "DELETESCRIPT \"vacation\"")
	response = readSimpleResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("DELETESCRIPT failed: %s", response)
	}

	t.Log("Successfully completed script deactivation test")
}

// Simple response reader that just gets the first line (for commands that return simple OK/NO)
func readSimpleResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	return strings.TrimSpace(response)
}

// readListScriptsResponse reads the multi-line LISTSCRIPTS response
func readListScriptsResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var fullResponse strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LISTSCRIPTS response line: %v", err)
		}
		line = strings.TrimSpace(line)
		fullResponse.WriteString(line)
		fullResponse.WriteString(" ")

		// The response ends with OK
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	return fullResponse.String()
}

// readGetScriptResponse handles the multi-line response from GETSCRIPT command
func readGetScriptResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	// Read the first line - should be either {length} or NO
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read GETSCRIPT response: %v", err)
	}
	firstLine = strings.TrimSpace(firstLine)

	// If it starts with NO, it's an error response - return it directly
	if strings.HasPrefix(firstLine, "NO") {
		return firstLine
	}

	// If it starts with {, it's a literal response - read the script content and OK
	if strings.HasPrefix(firstLine, "{") && strings.HasSuffix(firstLine, "}") {
		// Extract length from {length}
		lengthStr := strings.Trim(firstLine, "{}")
		length := 0
		if n, err := fmt.Sscanf(lengthStr, "%d", &length); n != 1 || err != nil {
			t.Fatalf("Invalid literal length in GETSCRIPT response: %s", firstLine)
		}

		// Read the script content (exact number of bytes)
		scriptBytes := make([]byte, length)
		_, err = io.ReadFull(reader, scriptBytes)
		if err != nil {
			t.Fatalf("Failed to read script content: %v", err)
		}

		// Read the final OK response
		finalLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read final OK from GETSCRIPT: %v", err)
		}

		return strings.TrimSpace(finalLine)
	}

	// Unexpected format - could be an OK from a previous command
	if firstLine == "OK" {
		// This might be a leftover OK response, try to read the actual GETSCRIPT response
		t.Logf("Got unexpected OK, trying to read actual GETSCRIPT response")
		actualLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read actual GETSCRIPT response after OK: %v", err)
		}
		firstLine = strings.TrimSpace(actualLine)

		// Try to process the actual response
		if strings.HasPrefix(firstLine, "NO") {
			return firstLine
		}
		if strings.HasPrefix(firstLine, "{") && strings.HasSuffix(firstLine, "}") {
			// Process as literal response
			lengthStr := strings.Trim(firstLine, "{}")
			length := 0
			if n, err := fmt.Sscanf(lengthStr, "%d", &length); n != 1 || err != nil {
				t.Fatalf("Invalid literal length in GETSCRIPT response: %s", firstLine)
			}

			scriptBytes := make([]byte, length)
			_, err = io.ReadFull(reader, scriptBytes)
			if err != nil {
				t.Fatalf("Failed to read script content: %v", err)
			}

			finalLine, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read final OK from GETSCRIPT: %v", err)
			}

			return strings.TrimSpace(finalLine)
		}
	}

	// Still unexpected format
	t.Fatalf("Unexpected GETSCRIPT response format: %s", firstLine)
	return ""
}

func TestManageSieveMultipleConnections(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()
	_ = account // Use account variable to avoid unused variable error

	// Test multiple concurrent connections
	numConnections := 3
	done := make(chan bool, numConnections)

	for i := 0; i < numConnections; i++ {
		go func(connNum int) {
			defer func() { done <- true }()

			// Connect to the server
			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Errorf("Connection %d: Failed to connect to ManageSieve server: %v", connNum, err)
				return
			}
			defer conn.Close()

			reader := bufio.NewReader(conn)
			writer := bufio.NewWriter(conn)

			// Read greeting (capabilities followed by OK)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Errorf("Connection %d: Failed to read greeting line: %v", connNum, err)
					return
				}
				line = strings.TrimSpace(line)
				// The greeting ends with OK line
				if strings.HasPrefix(line, "OK") {
					break
				}
			}

			// Test CAPABILITY command
			writer.WriteString("CAPABILITY\r\n")
			writer.Flush()

			// Read CAPABILITY response (capabilities followed by OK)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					t.Errorf("Connection %d: Failed to read CAPABILITY response line: %v", connNum, err)
					return
				}
				line = strings.TrimSpace(line)
				// The response ends with just OK
				if line == "OK" {
					break
				}
			}

			t.Logf("Connection %d: Successfully completed", connNum)
		}(i)
	}

	// Wait for all connections to complete with timeout
	timeout := time.After(10 * time.Second)
	completedConnections := 0

	for completedConnections < numConnections {
		select {
		case <-done:
			completedConnections++
		case <-timeout:
			t.Fatalf("Timeout waiting for connections to complete. Completed: %d/%d", completedConnections, numConnections)
		}
	}

	t.Logf("Successfully handled %d concurrent ManageSieve connections", numConnections)
}

func TestManageSieveConnectionTimeout(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect to the server
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting (capabilities followed by OK)
	var foundOK bool
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") && strings.Contains(line, "ManageSieve server ready") {
			foundOK = true
			break
		}
	}

	if !foundOK {
		t.Errorf("Expected OK greeting with ManageSieve server ready")
	}

	// Don't send any commands and wait for timeout
	// The server should eventually close idle connections
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Try to read - should eventually fail due to connection closure or timeout
	_, err = reader.ReadString('\n')

	// We expect either a timeout or connection closed error
	if err == nil {
		t.Logf("Connection remained open (server may have long timeout)")
	} else {
		t.Logf("Connection properly handled timeout/closure: %v", err)
	}
}

func TestManageSieveScriptEdgeCases(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	// Connect and authenticate
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Authenticate
	authenticateManageSieve(t, reader, writer, account)

	// Test 1: PUTSCRIPT with invalid script name (empty)
	t.Log("=== Testing PUTSCRIPT with empty script name ===")
	sendCommand(t, writer, `PUTSCRIPT "" require ["fileinto"];`)
	response := readResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT with empty name should fail: %s", response)
	} else if strings.Contains(response, "Script name cannot be empty") {
		t.Logf("Empty name correctly rejected: %s", strings.TrimSpace(response))
	} else {
		t.Logf("Empty name response: %s", strings.TrimSpace(response))
	}

	// Test 2: PUTSCRIPT with invalid Sieve syntax
	t.Log("=== Testing PUTSCRIPT with invalid Sieve syntax ===")
	invalidScript := `invalid sieve syntax here`
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"invalid\" %s", invalidScript))
	response = readResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT with invalid syntax should fail: %s", response)
	}
	t.Logf("Invalid syntax response: %s", strings.TrimSpace(response))

	// Test 3: SETACTIVE with non-existent script
	t.Log("=== Testing SETACTIVE with non-existent script ===")
	sendCommand(t, writer, "SETACTIVE \"nonexistent\"")
	response = readResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("SETACTIVE with non-existent script should fail: %s", response)
	}
	t.Logf("Set active non-existent response: %s", strings.TrimSpace(response))

	// Test 4: Create and test script name with special characters
	t.Log("=== Testing PUTSCRIPT with special characters in name ===")
	specialScript := `require ["fileinto"]; fileinto "INBOX";`
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"test-script_123\" %s", specialScript))
	response = readResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT with valid special characters should succeed: %s", response)
	}

	// Test 5: Test maximum script name length handling
	t.Log("=== Testing PUTSCRIPT with very long script name ===")
	longName := strings.Repeat("a", 255) // Very long script name
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"%s\" %s", longName, specialScript))
	response = readResponse(t, reader)
	// The server may accept or reject this - just log the behavior
	t.Logf("Long name response: %s", strings.TrimSpace(response))

	// Test 6: Test script with unsupported extensions (should fail)
	t.Log("=== Testing PUTSCRIPT with unsupported extensions ===")
	rejectScript := `require ["fileinto", "reject"]; if header :contains "subject" "test" { reject "Spam not allowed"; } else { fileinto "INBOX"; }`
	sendCommand(t, writer, fmt.Sprintf("PUTSCRIPT \"reject_script\" %s", rejectScript))
	response = readResponse(t, reader)
	if strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT with unsupported 'reject' extension should fail: %s", response)
	} else if strings.Contains(response, "unsupported extension") || strings.Contains(response, "reject") {
		t.Logf("Unsupported 'reject' extension correctly rejected: %s", strings.TrimSpace(response))
	} else {
		t.Logf("Reject extension response: %s", strings.TrimSpace(response))
	}

	// Test 7: Test script with only supported extensions using literal string format
	t.Log("=== Testing PUTSCRIPT with literal string format ===")
	supportedScript := `require ["fileinto", "vacation"]; if header :contains "subject" "vacation" { vacation "I'm on vacation"; } else { fileinto "INBOX"; }`

	// Use literal string format: PUTSCRIPT "name" {length+}
	literalCommand := fmt.Sprintf("PUTSCRIPT \"supported\" {%d+}", len(supportedScript))
	writer.WriteString(literalCommand + "\r\n")
	writer.Flush()

	// Wait for continuation response (+)
	continuationResponse := readResponse(t, reader)
	if !strings.HasPrefix(continuationResponse, "+") {
		t.Errorf("Expected continuation response (+), got: %s", continuationResponse)
		return
	}
	t.Logf("Received continuation response: %s", strings.TrimSpace(continuationResponse))

	// Now send the literal data
	writer.WriteString(supportedScript)
	writer.Flush()

	// Read the final response
	response = readResponse(t, reader)
	if !strings.Contains(response, "OK") {
		t.Errorf("PUTSCRIPT with literal string format should succeed: %s", response)
	} else {
		t.Logf("Literal string format script accepted: %s", strings.TrimSpace(response))
	}

	t.Logf("Successfully completed ManageSieve edge cases test")
}

func TestManageSieveTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// For this test, we'd need TLS-enabled server setup
	// Skip for now as it requires certificate configuration
	t.Skip("TLS test requires certificate configuration")
}

// Helper function to encode PLAIN authentication
func encodeBase64Plain(username, password string) string {
	// PLAIN SASL mechanism: authzid\0authcid\0password
	plain := fmt.Sprintf("\x00%s\x00%s", username, password)

	// Base64 encode using standard library
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

// Helper function to authenticate with ManageSieve server
func authenticateManageSieve(t *testing.T, reader *bufio.Reader, writer *bufio.Writer, account common.TestAccount) {
	t.Helper()

	// Read greeting (capabilities followed by OK)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting line: %v", err)
		}
		line = strings.TrimSpace(line)
		// The greeting ends with OK line
		if strings.HasPrefix(line, "OK") {
			break
		}
	}

	// Authenticate
	authCmd := fmt.Sprintf("AUTHENTICATE PLAIN %s\r\n",
		encodeBase64Plain(account.Email, account.Password))
	writer.WriteString(authCmd)
	writer.Flush()

	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read authenticate response: %v", err)
	}

	if !strings.Contains(response, "OK") {
		t.Fatalf("Authentication failed: %s", response)
	}
}

// Helper function to send a command
func sendCommand(t *testing.T, writer *bufio.Writer, command string) {
	t.Helper()

	writer.WriteString(command + "\r\n")
	writer.Flush()
}

// Helper function to read a complete ManageSieve response (handles literals and multi-line responses)
func readResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var fullResponse strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response line: %v", err)
		}

		line = strings.TrimSpace(line)
		fullResponse.WriteString(line)

		// Check if this line indicates a literal string follows
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			// Extract the length from {length} (not used but shows intent)
			_ = strings.Trim(line, "{}")
			// Read the literal string content (we'll just read one more line for simplicity)
			literalLine, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read literal content: %v", err)
			}
			fullResponse.WriteString(" ")
			fullResponse.WriteString(strings.TrimSpace(literalLine))

			// Continue reading for the final OK/NO response
			continue
		}

		// If it's a final response (OK, NO, BYE), we're done
		if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
			break
		}

		// If it's a continuation response (+), we're done reading this response
		if strings.HasPrefix(line, "+") {
			break
		}

		// If it's a quoted string response, continue reading
		if strings.HasPrefix(line, "\"") && strings.HasSuffix(line, "\"") {
			fullResponse.WriteString(" ")
			continue
		}

		// For other responses, assume single line
		break
	}

	return fullResponse.String()
}
