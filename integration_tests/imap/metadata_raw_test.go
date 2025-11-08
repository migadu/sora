//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_MetadataRawCommand tests raw GETMETADATA command like SnappyMail sends
func TestIMAP_MetadataRawCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Make raw TCP connection
	conn, err := net.Dial("tcp", server.Address)
	require.NoError(t, err)
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	require.NoError(t, err)
	t.Logf("Greeting: %s", greeting)

	// Login
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	_, err = conn.Write([]byte(loginCmd))
	require.NoError(t, err)

	// Read login response
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Login response: %s", line)
		if strings.HasPrefix(line, "A001 ") {
			break
		}
	}

	// Test 1: Send GETMETADATA with wildcard mailbox like SnappyMail does
	t.Run("SnappyMailStyleCommand", func(t *testing.T) {
		// This is exactly what SnappyMail sends
		cmd := "A002 GETMETADATA (DEPTH infinity) \"*\" (/shared /private)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read all response lines
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A002 ") {
				// Check if this is a parse error
				if strings.Contains(line, "CLIENTBUG") {
					t.Errorf("Got CLIENTBUG error: %s", line)
				}
				if strings.Contains(line, "expected CRLF") {
					t.Errorf("Got CRLF parse error: %s", line)
				}
				break
			}
		}
	})

	// Test 2: Send GETMETADATA with correct server metadata syntax
	t.Run("CorrectServerMetadata", func(t *testing.T) {
		cmd := "A003 GETMETADATA \"\" (/shared /private)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read response
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A003 ") {
				require.Contains(t, line, "OK", "Command should succeed")
				break
			}
		}
	})

	// Test 3: Send GETMETADATA with options
	t.Run("WithDepthOption", func(t *testing.T) {
		cmd := "A004 GETMETADATA (DEPTH infinity) \"\" (/shared /private)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read response
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A004 ") {
				// This should work - DEPTH infinity with empty string for server metadata
				t.Logf("Final response: %s", line)
				break
			}
		}
	})
}
