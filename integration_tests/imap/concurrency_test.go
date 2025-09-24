//go:build integration

package imap_test

import (
	"sync"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ConcurrentAccess tests multiple clients accessing the same mailbox
func TestIMAP_ConcurrentAccess(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Number of concurrent clients
	numClients := 3
	clientDone := make(chan bool, numClients)
	var wg sync.WaitGroup

	// Pre-populate mailbox with some messages
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	if _, err := setupClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Setup client select failed: %v", err)
	}

	// Add initial messages
	for i := 1; i <= 5; i++ {
		testMessage := "From: concurrent@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Concurrent Test Message " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for concurrent access testing.\r\n"

		appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("Setup APPEND write failed: %v", err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Setup APPEND close failed: %v", err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Setup APPEND failed: %v", err)
		}
	}

	setupClient.Logout()

	// Start concurrent clients
	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { clientDone <- true }()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				return
			}

			// Each client performs different operations
			switch id % 3 {
			case 0:
				// Client performs FETCH operations
				for i := 0; i < 3; i++ {
					fetchResults, err := c.Fetch(imap.SeqSetNum(uint32(i+1)), &imap.FetchOptions{
						Envelope: true,
						Flags:    true,
					}).Collect()
					if err != nil {
						t.Errorf("Client %d: FETCH failed: %v", id, err)
						return
					}
					if len(fetchResults) == 0 {
						t.Errorf("Client %d: FETCH returned no results", id)
						return
					}
					time.Sleep(10 * time.Millisecond) // Small delay
				}

			case 1:
				// Client performs flag operations
				for i := 1; i <= 2; i++ {
					storeCmd := c.Store(imap.SeqSetNum(uint32(i)), &imap.StoreFlags{
						Op:    imap.StoreFlagsAdd,
						Flags: []imap.Flag{imap.FlagSeen},
					}, nil)
					_, err := storeCmd.Collect()
					if err != nil {
						t.Errorf("Client %d: STORE failed: %v", id, err)
						return
					}
					time.Sleep(10 * time.Millisecond)
				}

			case 2:
				// Client performs search operations
				for i := 0; i < 3; i++ {
					searchResults, err := c.Search(&imap.SearchCriteria{}, nil).Wait()
					if err != nil {
						t.Errorf("Client %d: SEARCH failed: %v", id, err)
						return
					}
					if len(searchResults.AllSeqNums()) == 0 {
						t.Errorf("Client %d: SEARCH returned no results", id)
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
			}

			t.Logf("Client %d completed successfully", id)
		}(clientID)
	}

	// Wait for all clients to complete with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("All concurrent clients completed successfully")
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent access test timed out")
	}

	// Verify we received completion signals from all clients
	for i := 0; i < numClients; i++ {
		select {
		case <-clientDone:
			// Good, client completed
		case <-time.After(1 * time.Second):
			t.Errorf("Did not receive completion signal from all clients")
		}
	}
}

// TestIMAP_RaceConditions tests race conditions in mailbox operations
func TestIMAP_RaceConditions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	numClients := 5
	messagesPerClient := 10
	var wg sync.WaitGroup
	errors := make(chan error, numClients*messagesPerClient)

	// Test concurrent APPEND operations
	t.Run("ConcurrentAppend", func(t *testing.T) {
		for clientID := 0; clientID < numClients; clientID++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				c, err := imapclient.DialInsecure(server.Address, nil)
				if err != nil {
					errors <- err
					return
				}
				defer c.Logout()

				if err := c.Login(account.Email, account.Password).Wait(); err != nil {
					errors <- err
					return
				}

				// Rapidly append messages
				for msgID := 0; msgID < messagesPerClient; msgID++ {
					testMessage := "From: race@example.com\r\n" +
						"To: " + account.Email + "\r\n" +
						"Subject: Race Test Client " + string(rune('0'+id)) + " Message " + string(rune('0'+msgID)) + "\r\n" +
						"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
						"\r\n" +
						"Race condition test message.\r\n"

					appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
					_, err = appendCmd.Write([]byte(testMessage))
					if err != nil {
						errors <- err
						return
					}
					err = appendCmd.Close()
					if err != nil {
						errors <- err
						return
					}
					_, err = appendCmd.Wait()
					if err != nil {
						errors <- err
						return
					}
				}
			}(clientID)
		}

		wg.Wait()
		close(errors)

		// Check for errors
		for err := range errors {
			if err != nil {
				t.Errorf("Concurrent append error: %v", err)
			}
		}

		// Verify total message count
		verifyClient, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("Failed to dial verify client: %v", err)
		}
		defer verifyClient.Logout()

		if err := verifyClient.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("Verify client login failed: %v", err)
		}

		mbox, err := verifyClient.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Verify client select failed: %v", err)
		}

		expectedMessages := uint32(numClients * messagesPerClient)
		if mbox.NumMessages != expectedMessages {
			t.Errorf("Expected %d messages after concurrent append, got %d", expectedMessages, mbox.NumMessages)
		} else {
			t.Logf("Successfully appended %d messages concurrently", expectedMessages)
		}
	})
}

// TestIMAP_ConcurrentFlagOperations tests concurrent flag modifications
func TestIMAP_ConcurrentFlagOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add a test message
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	if _, err := setupClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Setup client select failed: %v", err)
	}

	testMessage := "From: flagrace@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Flag Race Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message will have its flags modified concurrently.\r\n"

	appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Setup APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Setup APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Setup APPEND failed: %v", err)
	}

	setupClient.Logout()

	// Test concurrent flag operations on the same message
	numClients := 3
	var wg sync.WaitGroup
	flagOperations := []struct {
		op    imap.StoreFlagsOp
		flags []imap.Flag
		name  string
	}{
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, "add_seen"},
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagFlagged}, "add_flagged"},
		{imap.StoreFlagsAdd, []imap.Flag{imap.FlagAnswered}, "add_answered"},
	}

	successCount := make(chan int, numClients)

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				successCount <- 0
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				successCount <- 0
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				successCount <- 0
				return
			}

			// Perform flag operation
			op := flagOperations[id%len(flagOperations)]
			storeCmd := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
				Op:    op.op,
				Flags: op.flags,
			}, nil)
			_, err = storeCmd.Collect()
			if err != nil {
				t.Errorf("Client %d (%s): STORE failed: %v", id, op.name, err)
				successCount <- 0
				return
			}

			t.Logf("Client %d (%s) completed flag operation successfully", id, op.name)
			successCount <- 1
		}(clientID)
	}

	wg.Wait()

	// Count successful operations
	totalSuccess := 0
	for i := 0; i < numClients; i++ {
		totalSuccess += <-successCount
	}

	if totalSuccess != numClients {
		t.Errorf("Expected %d successful flag operations, got %d", numClients, totalSuccess)
	}

	// Verify final flag state
	verifyClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial verify client: %v", err)
	}
	defer verifyClient.Logout()

	if err := verifyClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Verify client login failed: %v", err)
	}

	if _, err := verifyClient.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Verify client select failed: %v", err)
	}

	fetchResults, err := verifyClient.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("Verify FETCH failed: %v", err)
	}

	if len(fetchResults) > 0 {
		finalFlags := fetchResults[0].Flags
		t.Logf("Final message flags after concurrent operations: %v", finalFlags)

		// Check that at least some flags were set (depending on race conditions, we might get different combinations)
		flagCount := 0
		if containsFlag(finalFlags, imap.FlagSeen) {
			flagCount++
		}
		if containsFlag(finalFlags, imap.FlagFlagged) {
			flagCount++
		}
		if containsFlag(finalFlags, imap.FlagAnswered) {
			flagCount++
		}

		if flagCount == 0 {
			t.Error("No flags were set despite successful operations")
		}
	}

	t.Log("Concurrent flag operations test completed")
}

// TestIMAP_ConcurrentMailboxOperations tests concurrent mailbox creation/deletion
func TestIMAP_ConcurrentMailboxOperations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	numClients := 3
	var wg sync.WaitGroup
	results := make(chan string, numClients*2) // CREATE + DELETE per client

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				results <- "error"
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				results <- "error"
				return
			}

			mailboxName := "ConcurrentTest" + string(rune('A'+id))

			// CREATE mailbox
			if err := c.Create(mailboxName, nil).Wait(); err != nil {
				results <- "create_error"
				return
			}
			results <- "create_success"

			// Small delay to let other operations interleave
			time.Sleep(50 * time.Millisecond)

			// DELETE mailbox
			if err := c.Delete(mailboxName).Wait(); err != nil {
				results <- "delete_error"
				return
			}
			results <- "delete_success"
		}(clientID)
	}

	wg.Wait()

	// Analyze results
	createSuccess := 0
	deleteSuccess := 0
	errors := 0

	for i := 0; i < numClients*2; i++ {
		result := <-results
		switch result {
		case "create_success":
			createSuccess++
		case "delete_success":
			deleteSuccess++
		default:
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("Got %d errors during concurrent mailbox operations", errors)
	}

	if createSuccess != numClients {
		t.Errorf("Expected %d successful CREATE operations, got %d", numClients, createSuccess)
	}

	if deleteSuccess != numClients {
		t.Errorf("Expected %d successful DELETE operations, got %d", numClients, deleteSuccess)
	}

	t.Logf("Concurrent mailbox operations: %d creates, %d deletes, %d errors", createSuccess, deleteSuccess, errors)
}
