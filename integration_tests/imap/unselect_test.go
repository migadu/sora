//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_UnselectCommand tests the UNSELECT command functionality and connection stability
func TestIMAP_UnselectCommand(t *testing.T) {
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

	// Test 1: Basic UNSELECT after SELECT
	t.Run("BasicUnselect", func(t *testing.T) {
		// Select INBOX
		selectData, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		t.Logf("Selected INBOX: %d messages", selectData.NumMessages)

		// UNSELECT the mailbox
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT failed: %v", err)
		}
		t.Log("UNSELECT succeeded")

		// Verify we can still execute commands
		caps, err := c.Capability().Wait()
		if err != nil {
			t.Fatalf("CAPABILITY after UNSELECT failed: %v", err)
		}
		t.Logf("CAPABILITY after UNSELECT succeeded: %d capabilities", len(caps))
	})

	// Test 2: Multiple SELECT/UNSELECT cycles
	t.Run("MultipleUnselectCycles", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			// Select INBOX
			_, err := c.Select("INBOX", nil).Wait()
			if err != nil {
				t.Fatalf("Select INBOX cycle %d failed: %v", i+1, err)
			}

			// UNSELECT the mailbox
			err = c.Unselect().Wait()
			if err != nil {
				t.Fatalf("UNSELECT cycle %d failed: %v", i+1, err)
			}
			t.Logf("SELECT/UNSELECT cycle %d completed", i+1)
		}

		// Verify connection is still stable
		caps, err := c.Capability().Wait()
		if err != nil {
			t.Fatalf("CAPABILITY after multiple cycles failed: %v", err)
		}
		t.Logf("Connection stable after %d cycles: %d capabilities", 3, len(caps))
	})

	// Test 3: UNSELECT with messages in mailbox
	t.Run("UnselectWithMessages", func(t *testing.T) {
		// Select INBOX
		_, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// Add a test message
		testMessage := "From: test@example.com\r\nSubject: UNSELECT Test\r\nDate: " +
			time.Now().Format(time.RFC1123) + "\r\n\r\nTest message for UNSELECT.\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
			Time:  time.Now(),
		})
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		t.Log("Test message appended")

		// Re-select to see the message
		selectData, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Re-select INBOX failed: %v", err)
		}
		if selectData.NumMessages == 0 {
			t.Error("Expected at least 1 message after APPEND")
		}
		t.Logf("INBOX has %d messages", selectData.NumMessages)

		// UNSELECT the mailbox with messages
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT with messages failed: %v", err)
		}
		t.Log("UNSELECT with messages succeeded")

		// Verify connection is still working
		listCmd := c.List("", "*", nil)
		mailboxes, err := listCmd.Collect()
		if err != nil {
			t.Fatalf("LIST after UNSELECT failed: %v", err)
		}
		t.Logf("LIST after UNSELECT succeeded: %d mailboxes", len(mailboxes))
	})

	// Test 4: UNSELECT followed by SELECT different mailbox
	t.Run("UnselectThenSelectDifferent", func(t *testing.T) {
		// Select INBOX
		_, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// UNSELECT
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT failed: %v", err)
		}

		// Try to select INBOX again
		selectData, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Re-select INBOX after UNSELECT failed: %v", err)
		}
		t.Logf("Re-select INBOX after UNSELECT succeeded: %d messages", selectData.NumMessages)
	})

	// Test 5: UNSELECT in invalid state (should fail gracefully)
	t.Run("UnselectInInvalidState", func(t *testing.T) {
		// Make sure we're not in selected state by doing UNSELECT
		err = c.Unselect().Wait()
		if err != nil {
			// This is expected - we should already be unselected
			t.Logf("UNSELECT when not selected failed as expected: %v", err)
		}

		// Try UNSELECT again (should fail)
		err = c.Unselect().Wait()
		if err == nil {
			t.Error("UNSELECT when not selected should fail")
		} else {
			t.Logf("Second UNSELECT correctly failed: %v", err)
		}

		// Verify connection is still working after failed UNSELECT
		caps, err := c.Capability().Wait()
		if err != nil {
			t.Fatalf("CAPABILITY after failed UNSELECT failed: %v", err)
		}
		t.Logf("Connection stable after failed UNSELECT: %d capabilities", len(caps))
	})

	// Test 6: Connection stability after UNSELECT
	t.Run("ConnectionStabilityAfterUnselect", func(t *testing.T) {
		// Select and unselect multiple times rapidly
		for i := 0; i < 5; i++ {
			_, err := c.Select("INBOX", nil).Wait()
			if err != nil {
				t.Fatalf("Rapid select %d failed: %v", i+1, err)
			}

			err = c.Unselect().Wait()
			if err != nil {
				t.Fatalf("Rapid unselect %d failed: %v", i+1, err)
			}
		}

		// Test various commands to ensure connection stability
		commands := []struct {
			name string
			test func() error
		}{
			{"CAPABILITY", func() error {
				_, err := c.Capability().Wait()
				return err
			}},
			{"LIST", func() error {
				listCmd := c.List("", "*", nil)
				_, err := listCmd.Collect()
				return err
			}},
			{"SELECT", func() error {
				_, err := c.Select("INBOX", nil).Wait()
				return err
			}},
			{"UNSELECT", func() error {
				return c.Unselect().Wait()
			}},
		}

		for _, cmd := range commands {
			if err := cmd.test(); err != nil {
				t.Errorf("%s command failed after rapid UNSELECT cycles: %v", cmd.name, err)
			} else {
				t.Logf("%s command succeeded after rapid cycles", cmd.name)
			}
		}
	})

	t.Log("UNSELECT command integration test completed successfully")
}

// TestIMAP_UnselectBrokenPipeInvestigation tests scenarios that might trigger broken pipe after UNSELECT
func TestIMAP_UnselectBrokenPipeInvestigation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Test 1: UNSELECT followed by immediate client disconnect
	t.Run("UnselectThenDisconnect", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		// Select INBOX
		_, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// UNSELECT
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT failed: %v", err)
		}
		t.Log("UNSELECT succeeded")

		// Immediately close connection without LOGOUT
		err = c.Close()
		if err != nil {
			t.Logf("Connection close error (may be expected): %v", err)
		} else {
			t.Log("Connection closed cleanly")
		}
	})

	// Test 2: UNSELECT with rapid operations
	t.Run("UnselectWithRapidOperations", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		// Select INBOX
		_, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// Add a message to have some data
		testMessage := "From: test@example.com\r\nSubject: Broken Pipe Test\r\nDate: " +
			time.Now().Format(time.RFC1123) + "\r\n\r\nTest message.\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen},
			Time:  time.Now(),
		})
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}

		// UNSELECT and immediately try other operations
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT failed: %v", err)
		}

		// Try multiple rapid commands after UNSELECT
		for i := 0; i < 5; i++ {
			_, err := c.Capability().Wait()
			if err != nil {
				t.Errorf("CAPABILITY %d after UNSELECT failed: %v", i+1, err)
			}
		}
		t.Log("Rapid operations after UNSELECT completed")
	})

	// Test 3: UNSELECT with concurrent operations (simulating production load)
	t.Run("UnselectWithConcurrentOps", func(t *testing.T) {
		const numClients = 3
		errors := make(chan error, numClients)

		for clientID := 0; clientID < numClients; clientID++ {
			go func(id int) {
				defer func() {
					if r := recover(); r != nil {
						errors <- fmt.Errorf("client %d panicked: %v", id, r)
					}
				}()

				c, err := imapclient.DialInsecure(server.Address, nil)
				if err != nil {
					errors <- fmt.Errorf("client %d dial failed: %v", id, err)
					return
				}

				if err := c.Login(account.Email, account.Password).Wait(); err != nil {
					errors <- fmt.Errorf("client %d login failed: %v", id, err)
					return
				}

				// Rapid SELECT/UNSELECT cycles
				for cycle := 0; cycle < 3; cycle++ {
					_, err = c.Select("INBOX", nil).Wait()
					if err != nil {
						errors <- fmt.Errorf("client %d select cycle %d failed: %v", id, cycle, err)
						return
					}

					err = c.Unselect().Wait()
					if err != nil {
						errors <- fmt.Errorf("client %d unselect cycle %d failed: %v", id, cycle, err)
						return
					}
				}

				c.Logout()
				errors <- nil
			}(clientID)
		}

		// Wait for all clients
		for i := 0; i < numClients; i++ {
			err := <-errors
			if err != nil {
				t.Errorf("Concurrent client error: %v", err)
			}
		}
		t.Log("Concurrent UNSELECT operations completed")
	})

	// Test 4: UNSELECT after various operations that might leave background tasks
	t.Run("UnselectAfterCommands", func(t *testing.T) {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()

		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Login failed: %v", err)
		}

		// Select INBOX
		_, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}

		// Perform various operations before UNSELECT that might leave state
		operations := []struct {
			name string
			op   func() error
		}{
			{"FETCH", func() error {
				if _, err := c.Fetch(imap.SeqSet{imap.SeqRange{Start: 1, Stop: 0}}, &imap.FetchOptions{
					Flags: true,
				}).Collect(); err != nil {
					return err
				}
				return nil
			}},
			{"SEARCH", func() error {
				_, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
				return err
			}},
			{"CAPABILITY", func() error {
				_, err := c.Capability().Wait()
				return err
			}},
		}

		for _, op := range operations {
			if err := op.op(); err != nil {
				t.Logf("%s failed (may be expected): %v", op.name, err)
			} else {
				t.Logf("%s succeeded", op.name)
			}
		}

		// Wait a moment to let any background tasks settle
		time.Sleep(50 * time.Millisecond)

		// UNSELECT after the operations
		err = c.Unselect().Wait()
		if err != nil {
			t.Fatalf("UNSELECT after operations failed: %v", err)
		}
		t.Log("UNSELECT after various operations succeeded")

		// Verify connection stability
		_, err = c.Capability().Wait()
		if err != nil {
			t.Errorf("CAPABILITY after UNSELECT failed: %v", err)
		}
	})

	t.Log("UNSELECT broken pipe investigation completed")
}
