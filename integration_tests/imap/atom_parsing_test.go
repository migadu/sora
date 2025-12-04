//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AtomSpecialChars tests that special characters in mailbox names are handled correctly
// RFC 3501 defines atom-specials that require quoting or literals:
// atom-specials = "(" / ")" / "{" / SP / CTL / list-wildcards / quoted-specials / resp-specials
// quoted-specials = DQUOTE / "\"
// resp-specials = "]"
// list-wildcards = "%" / "*"
//
// Valid atom characters include: !#$&'+,-.0123456789:;<=>?@^_`|[}
func TestIMAP_AtomSpecialChars(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test cases with special characters that should be valid in atoms
	testCases := []struct {
		name        string
		mailboxName string
		shouldExist bool
	}{
		{
			name:        "Tilde prefix",
			mailboxName: "~foo",
			shouldExist: false, // Should get NO response, not crash
		},
		{
			name: "Atom-special characters",
			// All valid atom characters (excluding atom-specials which need quoting)
			mailboxName: "!#$&'+,-.0123456789:;<=>?@^_`|[}",
			shouldExist: false, // Should get NO response, not crash
		},
		{
			name:        "Simple test",
			mailboxName: "TestMailbox",
			shouldExist: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing SELECT with mailbox name: %q", tc.mailboxName)

			// Try to SELECT the mailbox - should get NO response, not BAD or disconnect
			_, err := c.Select(tc.mailboxName, nil).Wait()

			if err == nil && !tc.shouldExist {
				t.Errorf("Expected error for non-existent mailbox %q, got nil", tc.mailboxName)
				return
			}

			if err != nil {
				// Check the error type
				t.Logf("Got error (expected): %v", err)

				// The error should be a "NO" response (mailbox doesn't exist)
				// NOT a "BAD" response (syntax error) or disconnection
				if imapErr, ok := err.(*imap.Error); ok {
					if imapErr.Type == imap.StatusResponseTypeBad {
						t.Errorf("Got BAD response (syntax error) for mailbox %q: %v", tc.mailboxName, imapErr)
					} else if imapErr.Type == imap.StatusResponseTypeNo {
						t.Logf("Correctly got NO response for non-existent mailbox")
					}
				}
			}

			// Test that connection is still alive after the SELECT
			// Try a NOOP command
			if err := c.Noop().Wait(); err != nil {
				t.Errorf("Connection died after SELECT %q: %v", tc.mailboxName, err)
			} else {
				t.Logf("Connection still alive after SELECT (good)")
			}
		})
	}
}

// TestIMAP_AtomListCommand tests LIST command with special characters
func TestIMAP_AtomListCommand(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test LIST command with special characters
	// This was causing "Unexpected disconnection" in imaptest
	testCases := []struct {
		name    string
		pattern string
	}{
		{
			name:    "Simple wildcard",
			pattern: "*",
		},
		{
			name:    "Tilde with wildcard",
			pattern: "~foo%*",
		},
		{
			name: "Atom-special chars with wildcard",
			// This should work - wildcards at the end, atom chars before
			pattern: "!#$&'+,-.0123456789:;<=>?@^_`|[}%*",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing LIST with pattern: %q", tc.pattern)

			// Try LIST command
			listCmd := c.List("", tc.pattern, nil)

			// Collect responses
			var mailboxes []string
			for {
				mbox := listCmd.Next()
				if mbox == nil {
					break
				}
				mailboxes = append(mailboxes, mbox.Mailbox)
			}

			err := listCmd.Close()
			if err != nil {
				t.Logf("LIST returned error: %v", err)
				// Check if it's a BAD response
				if imapErr, ok := err.(*imap.Error); ok {
					if imapErr.Type == imap.StatusResponseTypeBad {
						t.Errorf("Got BAD response (syntax error) for LIST pattern %q: %v", tc.pattern, imapErr)
					}
				}
			} else {
				t.Logf("LIST succeeded, found %d mailboxes", len(mailboxes))
			}

			// Test that connection is still alive
			if err := c.Noop().Wait(); err != nil {
				t.Errorf("Connection died after LIST %q: %v", tc.pattern, err)
			} else {
				t.Logf("Connection still alive after LIST (good)")
			}
		})
	}
}

// TestIMAP_AtomQuotingRequired tests cases where quoting IS required
func TestIMAP_AtomQuotingRequired(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Create a mailbox with spaces (requires quoting)
	mailboxWithSpaces := "Test Mailbox With Spaces"

	t.Logf("Creating mailbox: %q", mailboxWithSpaces)
	createCmd := c.Create(mailboxWithSpaces, nil)
	if err := createCmd.Wait(); err != nil {
		t.Fatalf("Failed to create mailbox: %v", err)
	}

	// List it to verify it was created
	listCmd := c.List("", mailboxWithSpaces, nil)
	found := false
	for {
		mbox := listCmd.Next()
		if mbox == nil {
			break
		}
		if mbox.Mailbox == mailboxWithSpaces {
			found = true
			t.Logf("Found mailbox: %q", mbox.Mailbox)
		}
	}
	if err := listCmd.Close(); err != nil {
		t.Fatalf("LIST failed: %v", err)
	}

	if !found {
		t.Errorf("Mailbox %q was not found after creation", mailboxWithSpaces)
	}

	// Select it
	_, err = c.Select(mailboxWithSpaces, nil).Wait()
	if err != nil {
		t.Errorf("Failed to SELECT mailbox with spaces: %v", err)
	} else {
		t.Logf("Successfully selected mailbox with spaces")
	}

	// Cleanup - close mailbox before deleting
	// Note: UNSELECT or SELECT INBOX to close current mailbox
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Logf("SELECT INBOX failed: %v", err)
	}

	deleteCmd := c.Delete(mailboxWithSpaces)
	if err := deleteCmd.Wait(); err != nil {
		t.Logf("Failed to delete mailbox (cleanup): %v", err)
	}
}
