//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_SubscriptionOperations(t *testing.T) {
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

	testMailbox := "SubscribeTest"

	// Create a mailbox
	if err := c.Create(testMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE failed: %v", err)
	}

	// 1. Verify not subscribed initially
	// Check via LSUB
	lsubCmd := c.List("", "*", &imap.ListOptions{SelectSubscribed: true})
	mboxes, err := lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB failed: %v", err)
	}
	for _, mbox := range mboxes {
		if mbox.Mailbox == testMailbox {
			t.Errorf("Mailbox %s should not be subscribed initially", testMailbox)
		}
	}

	// 2. Subscribe
	if err := c.Subscribe(testMailbox).Wait(); err != nil {
		t.Fatalf("SUBSCRIBE failed: %v", err)
	}

	// Verify subscribed via LSUB
	lsubCmd = c.List("", "*", &imap.ListOptions{SelectSubscribed: true})
	mboxes, err = lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB failed after subscribe: %v", err)
	}
	found := false
	for _, mbox := range mboxes {
		if mbox.Mailbox == testMailbox {
			found = true
			// Check for \Subscribed flag if returned in LSUB (it should be)
			hasSub := false
			for _, attr := range mbox.Attrs {
				if attr == imap.MailboxAttrSubscribed {
					hasSub = true
					break
				}
			}
			if !hasSub {
				// While RFC doesn't strictly require \Subscribed in LSUB response, it's good practice.
				// But presence in LSUB list IS the verification.
				t.Logf("Mailbox found in LSUB but \\Subscribed attribute missing (acceptable)")
			}
			break
		}
	}
	if !found {
		t.Errorf("Mailbox %s not found in LSUB after subscription", testMailbox)
	}

	// Verify \Subscribed flag in LIST response as well
	listCmd := c.List("", testMailbox, nil)
	mboxes, err = listCmd.Collect()
	if err != nil {
		t.Fatalf("LIST failed: %v", err)
	}
	if len(mboxes) > 0 {
		hasSub := false
		for _, attr := range mboxes[0].Attrs {
			if attr == imap.MailboxAttrSubscribed {
				hasSub = true
				break
			}
		}
		if !hasSub {
			t.Errorf("\\Subscribed attribute missing in LIST response for subscribed mailbox")
		}
	}

	// 3. Unsubscribe
	if err := c.Unsubscribe(testMailbox).Wait(); err != nil {
		t.Fatalf("UNSUBSCRIBE failed: %v", err)
	}

	// Verify not subscribed via LSUB
	lsubCmd = c.List("", "*", &imap.ListOptions{SelectSubscribed: true})
	mboxes, err = lsubCmd.Collect()
	if err != nil {
		t.Fatalf("LSUB failed after unsubscribe: %v", err)
	}
	for _, mbox := range mboxes {
		if mbox.Mailbox == testMailbox {
			t.Errorf("Mailbox %s should not be in LSUB after unsubscribe", testMailbox)
		}
	}

	// 4. Subscribe to non-existent mailbox (RFC 3501 says this is allowed)
	phantomMailbox := "PhantomBox"
	if err := c.Subscribe(phantomMailbox).Wait(); err != nil {
		t.Logf("Computed subscription failure (optional): %v", err)
	} else {
		// If succeeded, check it appears in LSUB with \NonExistent or similar?
		// RFC 3501: "The Subscribe command adds the specified mailbox name to the server's set of 'active' or 'subscribed' mailboxes... The server may allow the subscription of a name that does not exist in the repository."
		lsubCmd = c.List("", phantomMailbox, &imap.ListOptions{SelectSubscribed: true})
		mboxes, err = lsubCmd.Collect()
		if len(mboxes) > 0 {
			t.Logf("Subscription to non-existent mailbox confirmed")
			found := false
			for _, attr := range mboxes[0].Attrs {
				if attr == imap.MailboxAttrNonExistent {
					found = true
					break
				}
			}
			if !found {
				t.Logf("\\NonExistent attribute not strictly required but useful")
			}
		} else {
			t.Logf("Subscribed to phantom mailbox but it doesn't appear in LSUB - server might filter non-existent mailboxes from LSUB or checks existence silently")
		}
	}
}
