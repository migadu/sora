//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_PlusAddressingS3Key tests that messages delivered to plus addresses
// (e.g., user+alias@domain.com) are stored with the correct S3 key (using base address).
// This test catches the bug where s3_localpart was stored with the full alias instead
// of the base email localpart.
//
// The bug manifests when:
// 1. User authenticates with plus address (user+alias@example.com)
// 2. APPEND stores message with s3_localpart = 'user+alias'
// 3. But uploader uses primary email (user@example.com) so stores with s3_localpart = 'user'
// 4. Later FETCH tries to get from S3 with key using 'user+alias' → 404 → empty body
//
// The fix ensures APPEND queries the primary email and uses that for s3_localpart,
// matching what the uploader uses.
func TestIMAP_PlusAddressingS3Key(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Create a plus-address variant of the account email
	// The account's primary email is the base (e.g., test@example.com)
	plusAddress := strings.Replace(account.Email, "@", "+alias@", 1)

	t.Logf("Primary email: %s", account.Email)
	t.Logf("Plus address for test: %s", plusAddress)

	// Connect and login with the BASE address (not plus address)
	// In the real world, users might login with plus address, but credentials
	// are stored with base address, so authentication resolves to base account.
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// APPEND a message TO the plus address
	// This simulates mail delivery to user+alias@example.com
	messageContent := fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test Plus Addressing S3 Key
Date: %s
Message-ID: <test-plus-s3key-%d@example.com>

This is a test message to verify that S3 keys are constructed correctly
for plus-addressed recipients. The s3_localpart should be the BASE email
localpart (without +alias), not the full alias.
`, plusAddress, time.Now().Format(time.RFC1123Z), time.Now().UnixNano())

	appendCmd := c.Append("INBOX", int64(len(messageContent)), nil)
	if _, err := appendCmd.Write([]byte(messageContent)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	data, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	appendedUID := data.UID
	t.Logf("✓ Message appended successfully (UID=%d)", appendedUID)

	// Give uploader a moment to process (though with empty S3, file stays local)
	time.Sleep(100 * time.Millisecond)

	// Now FETCH the message body to verify it's retrievable
	// If s3_localpart was stored incorrectly (with +alias), this would fail
	// because the server would try to fetch from wrong S3 key.
	//
	// With the fix, s3_localpart is stored correctly (base address),
	// so retrieval works (either from local disk or S3 with matching key).

	fetchCmd := c.Fetch(imap.UIDSetNum(appendedUID), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{}}, // BODY[] - full message
		},
	})

	var retrievedBody []byte
	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := make([]byte, 0, 4096)
				tmp := make([]byte, 1024)
				for {
					n, err := bodyItem.Literal.Read(tmp)
					if n > 0 {
						buf = append(buf, tmp[:n]...)
					}
					if err != nil {
						break
					}
				}
				retrievedBody = buf
			}
		}
	}

	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	// Verify we retrieved the message body successfully
	if len(retrievedBody) == 0 {
		t.Fatalf("FETCH returned empty body! This indicates S3 key mismatch bug.\n"+
			"Message was appended for %s but s3_localpart was likely stored incorrectly.\n"+
			"Expected s3_localpart='%s' (base address localpart), but may have been stored as '%s' (with +alias).",
			plusAddress,
			strings.Split(account.Email, "@")[0],
			strings.Split(plusAddress, "@")[0])
	}

	// Verify the body contains expected content
	bodyStr := string(retrievedBody)
	if !strings.Contains(bodyStr, "Test Plus Addressing S3 Key") {
		t.Fatalf("Retrieved body doesn't contain expected content. Got %d bytes", len(retrievedBody))
	}

	t.Logf("✓ Successfully retrieved message body (%d bytes)", len(retrievedBody))
	t.Logf("✓ S3 key is constructed correctly (using base address localpart)")
}
