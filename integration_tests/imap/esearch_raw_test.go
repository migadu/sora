//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_ESearchReturnAllRaw(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect via raw TCP
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	line, _ := reader.ReadString('\n')
	t.Logf("S: %s", strings.TrimSpace(line))

	// Login
	fmt.Fprintf(conn, "A001 LOGIN %s %s\r\n", account.Email, account.Password)
	line, err = reader.ReadString('\n') // A001 OK
	if err != nil || !strings.HasPrefix(line, "A001 OK") {
		t.Fatalf("Login failed: %s", line)
	}

	// Select INBOX
	fmt.Fprintf(conn, "A002 SELECT INBOX\r\n")
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Select failed: %v", err)
		}
		if strings.HasPrefix(line, "A002 ") {
			if !strings.HasPrefix(line, "A002 OK") {
				t.Fatalf("Select failed: %s", line)
			}
			break
		}
	}

	// Append 3 messages
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(conn, "A%03d APPEND INBOX {13+}\r\nSubject: test\r\n", 100+i)
		// Consume until OK
		tag := fmt.Sprintf("A%03d", 100+i)
		for {
			line, err = reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Append %d failed reading: %v", i, err)
			}
			t.Logf("S: %s", strings.TrimSpace(line))
			if strings.HasPrefix(line, tag+" ") {
				if !strings.HasPrefix(line, tag+" OK") {
					t.Fatalf("Append %d failed: %s", i, line)
				}
				break
			}
		}
	}

	// Send ESEARCH RETURN (ALL)
	fmt.Fprintf(conn, "A004 SEARCH RETURN (ALL) ALL\r\n")

	// Expect response: * ESEARCH ... ALL 1:3 (or 1,2,3)
	// And A004 OK
	foundESearch := false
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read SEARCH response: %v", err)
		}
		t.Logf("S: %s", strings.TrimSpace(line))

		if strings.HasPrefix(line, "* ESEARCH") {
			if strings.Contains(line, "ALL 1:3") || strings.Contains(line, "ALL 1,2,3") {
				foundESearch = true
			} else {
				t.Errorf("ESEARCH response missing expected ALL result (1:3 or 1,2,3). Got: %s", line)
			}
		}

		if strings.HasPrefix(line, "A004 ") {
			if !strings.HasPrefix(line, "A004 OK") {
				t.Fatalf("SEARCH command failed: %s", line)
			}
			break
		}
	}

	if !foundESearch {
		t.Fatal("Did not receive * ESEARCH response with ALL data")
	}

	t.Log("ESEARCH RETURN (ALL) raw test passed")
}
