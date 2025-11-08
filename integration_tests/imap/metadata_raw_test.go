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

// TestIMAP_MetadataRawProtocol tests raw GETMETADATA command protocol handling
// This test verifies that the go-imap parser correctly handles GETMETADATA syntax
// and that our wildcard rejection works at the application level.
func TestIMAP_MetadataRawProtocol(t *testing.T) {
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
	require.Contains(t, greeting, "OK")

	// Login
	loginCmd := fmt.Sprintf("A001 LOGIN %s %s\r\n", account.Email, account.Password)
	_, err = conn.Write([]byte(loginCmd))
	require.NoError(t, err)

	// Read login response
	for {
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Login response: %s", strings.TrimRight(line, "\r\n"))
		if strings.HasPrefix(line, "A001 ") {
			require.Contains(t, line, "OK")
			break
		}
	}

	t.Run("WildcardSingleEntry", func(t *testing.T) {
		// Test wildcard mailbox with single entry in list
		// NOTE: go-imap currently requires parentheses for RFC 5464 compliance
		// TODO: Update when single entry without parens is supported
		cmd := "A002 GETMETADATA \"*\" (/private/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read response
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

		// Should reject wildcard with CLIENTBUG (not a parse error)
		require.Contains(t, line, "A002 NO", "Expected NO response for wildcard")
		require.Contains(t, line, "CLIENTBUG", "Expected CLIENTBUG code")
		require.Contains(t, strings.ToLower(line), "wildcard", "Error should mention wildcards")
	})

	t.Run("WildcardMultipleEntries", func(t *testing.T) {
		// Test wildcard mailbox with multiple entries in parentheses
		cmd := "A003 GETMETADATA \"*\" (/private/comment /shared/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

		// Should reject wildcard
		require.Contains(t, line, "A003 NO")
		require.Contains(t, line, "CLIENTBUG")
		require.Contains(t, strings.ToLower(line), "wildcard")
	})

	t.Run("ValidServerMetadataSingleEntry", func(t *testing.T) {
		// Test with correct empty string for server metadata, single entry
		// NOTE: go-imap currently requires parentheses
		// TODO: Update when single entry without parens is supported
		cmd := "A004 GETMETADATA \"\" (/private/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		// Read all response lines until we get the tagged response
		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A004 ") {
				require.Contains(t, line, "OK", "Valid command should succeed")
				break
			}
		}
	})

	t.Run("ValidServerMetadataMultipleEntries", func(t *testing.T) {
		// Test with parenthesized entry list
		cmd := "A005 GETMETADATA \"\" (/private/comment /shared/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A005 ") {
				require.Contains(t, line, "OK", "Valid command should succeed")
				break
			}
		}
	})

	t.Run("PercentWildcard", func(t *testing.T) {
		// Test with % wildcard
		// NOTE: go-imap currently requires parentheses
		cmd := "A006 GETMETADATA \"%\" (/shared/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

		// Should also reject % wildcard
		require.Contains(t, line, "A006 NO")
		require.Contains(t, line, "CLIENTBUG")
	})

	t.Run("WildcardInMiddle", func(t *testing.T) {
		// Test wildcard in middle of mailbox name
		// NOTE: go-imap currently requires parentheses
		cmd := "A007 GETMETADATA \"INBOX*\" (/private/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

		// Should reject wildcards anywhere in name
		require.Contains(t, line, "A007 NO")
		require.Contains(t, line, "CLIENTBUG")
		require.Contains(t, strings.ToLower(line), "wildcard")
	})

	t.Run("WithDepthOption", func(t *testing.T) {
		// Test GETMETADATA with DEPTH option
		cmd := "A008 GETMETADATA (DEPTH infinity) \"\" (/private/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		for {
			line, err := reader.ReadString('\n')
			require.NoError(t, err)
			t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

			if strings.HasPrefix(line, "A008 ") {
				require.Contains(t, line, "OK", "Valid command with options should succeed")
				break
			}
		}
	})

	t.Run("WildcardWithDepthOption", func(t *testing.T) {
		// Test wildcard with DEPTH option (what SnappyMail originally sent)
		cmd := "A009 GETMETADATA (DEPTH infinity) \"*\" (/private/comment)\r\n"
		t.Logf("Sending: %q", cmd)

		_, err := conn.Write([]byte(cmd))
		require.NoError(t, err)

		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		t.Logf("Response: %s", strings.TrimRight(line, "\r\n"))

		// Should reject wildcard even with valid options
		require.Contains(t, line, "A009 NO")
		require.Contains(t, line, "CLIENTBUG")
		require.Contains(t, strings.ToLower(line), "wildcard")
	})
}
