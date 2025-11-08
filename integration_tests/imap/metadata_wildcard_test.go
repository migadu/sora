//go:build integration

package imap_test

import (
	"strings"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIMAP_MetadataWildcardMailbox tests GETMETADATA with wildcard mailbox name
// This reproduces the SnappyMail bug where it sends: GETMETADATA (DEPTH infinity) "*" (/shared /private)
//
// BACKGROUND:
// SnappyMail webmail client incorrectly sends GETMETADATA with "*" as the mailbox parameter,
// which is not supported by RFC 5464. RFC 5464 only supports:
// - Empty string "" for server-level metadata
// - Specific mailbox name for mailbox-level metadata
//
// The wildcard "*" should be rejected with a clear error message, not a parse error.
func TestIMAP_MetadataWildcardMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	defer c.Logout()

	err = c.Login(account.Email, account.Password).Wait()
	require.NoError(t, err)

	t.Run("WildcardMailboxName", func(t *testing.T) {
		// This is what SnappyMail sends - which should fail gracefully
		// GETMETADATA (DEPTH infinity) "*" (/shared /private)

		// Test with wildcard "*" mailbox name
		_, err := c.GetMetadata("*", []string{"/shared", "/private"}, nil).Wait()

		// This should fail with a proper error about wildcards not being supported
		require.Error(t, err)
		t.Logf("Error received: %v", err)

		// Verify it's a CLIENTBUG error
		var imapErr *imap.Error
		if assert.ErrorAs(t, err, &imapErr) {
			assert.Equal(t, imap.ResponseCodeClientBug, imapErr.Code)
			assert.Contains(t, strings.ToLower(imapErr.Text), "wildcard")
		}

		// The error should NOT be a protocol parsing error like "expected CRLF, got T"
		assert.NotContains(t, strings.ToLower(err.Error()), "expected crlf")
		assert.NotContains(t, strings.ToLower(err.Error()), "syntax error")
	})

	t.Run("PercentWildcard", func(t *testing.T) {
		// Test with "%" wildcard as well
		_, err := c.GetMetadata("%", []string{"/shared"}, nil).Wait()

		require.Error(t, err)
		t.Logf("Error received: %v", err)

		// Should also reject percent wildcard
		var imapErr *imap.Error
		if assert.ErrorAs(t, err, &imapErr) {
			assert.Equal(t, imap.ResponseCodeClientBug, imapErr.Code)
		}
	})

	t.Run("EmptyMailboxForServerMetadata", func(t *testing.T) {
		// The correct way to get server metadata is with empty string
		result, err := c.GetMetadata("", []string{"/shared", "/private"}, nil).Wait()

		// This should succeed (even if no metadata exists)
		require.NoError(t, err)
		t.Logf("Server metadata: %+v", result)
		assert.Empty(t, result.Mailbox, "Server metadata should have empty mailbox")
	})

	t.Run("SpecificMailbox", func(t *testing.T) {
		// Create a test mailbox
		mailboxName := "TestMetadataWildcard"
		err := c.Create(mailboxName, nil).Wait()
		require.NoError(t, err)

		// Getting metadata for a specific mailbox should work
		result, err := c.GetMetadata(mailboxName, []string{"/shared", "/private"}, nil).Wait()
		require.NoError(t, err)
		t.Logf("Mailbox metadata: %+v", result)
		assert.Equal(t, mailboxName, result.Mailbox)
	})

	t.Run("WithDepthOption", func(t *testing.T) {
		// Test GETMETADATA with DEPTH option (like SnappyMail sends)
		options := &imap.GetMetadataOptions{
			Depth: imap.GetMetadataDepthInfinity,
		}

		// Should work with empty mailbox (server metadata)
		result, err := c.GetMetadata("", []string{"/shared", "/private"}, options).Wait()
		require.NoError(t, err)
		t.Logf("Server metadata with DEPTH infinity: %+v", result)

		// Should fail with wildcard
		_, err = c.GetMetadata("*", []string{"/shared", "/private"}, options).Wait()
		require.Error(t, err)
		t.Logf("Wildcard with DEPTH rejected: %v", err)
	})
}
