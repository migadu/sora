package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/config"
	"github.com/stretchr/testify/require"
)

func setupTestDatabaseWithMaxConns(t testing.TB, maxConns int) *Database {
	ctx := context.Background()

	configPath, err := findTestConfig()
	require.NoError(t, err, "config-test.toml not found")

	var cfg TestConfig
	_, err = toml.DecodeFile(configPath, &cfg)
	require.NoError(t, err, "Failed to load test config")

	dbConfig := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:          cfg.Database.Write.Hosts,
			Port:           cfg.Database.Write.Port,
			User:           cfg.Database.Write.User,
			Password:       cfg.Database.Write.Password,
			Name:           cfg.Database.Write.Name,
			TLSMode:        cfg.Database.Write.TLS,
			MaxConnections: maxConns,
		},
	}

	database, err := NewDatabaseFromConfig(ctx, dbConfig, true, true)
	require.NoError(t, err)

	return database
}

// TestConnectionStarvation_GetMailboxByName proves that concurrent Inserts
// starve the connection pool, causing read queries to time out.
func TestConnectionStarvation_GetMailboxByName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	// 1. Setup DB with exactly 5 max connections
	db := setupTestDatabaseWithMaxConns(t, 5)
	defer db.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("starvation_%d@example.com", time.Now().UnixNano())

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create test mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx2.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// 2. Launch 10 concurrent insert workers
	var wg sync.WaitGroup
	startCh := make(chan struct{})
	numWorkers := 20

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			<-startCh // Wait for signal to start simultaneously

			// Each worker inserts 100 messages in a row
			for j := 0; j < 100; j++ {
				workerCtx := context.Background()
				tx, err := db.GetWritePool().Begin(workerCtx)
				if err != nil {
					continue
				}

				bs := &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
				var ibs imap.BodyStructure = bs
				opts := &InsertMessageOptions{
					AccountID:     accountID,
					MailboxID:     mailbox.ID,
					MailboxName:   "INBOX",
					S3Domain:      "example.com",
					S3Localpart:   fmt.Sprintf("w%d_msg%d", workerID, j),
					ContentHash:   fmt.Sprintf("hash_%d_%d", workerID, j),
					MessageID:     fmt.Sprintf("<msg%d_%d@example.com>", workerID, j),
					InternalDate:  time.Now(),
					Size:          100,
					Subject:       "Test",
					PlaintextBody: "Body",
					SentDate:      time.Now(),
					BodyStructure: &ibs,
				}

				upload := PendingUpload{
					AccountID:   accountID,
					ContentHash: opts.ContentHash,
					InstanceID:  "test",
					Size:        100,
				}

				_, _, _ = db.InsertMessage(workerCtx, tx, opts, upload)
				_ = tx.Commit(workerCtx)
			}
		}(i)
	}

	// Signal workers to start
	close(startCh)

	// Give workers a tiny bit of time to grab the connections
	time.Sleep(10 * time.Millisecond)

	// 3. Try to perform a read query with a short timeout (e.g., 50ms)
	readCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = db.GetMailboxByName(readCtx, accountID, "INBOX")

	// We expect NO error since starvation is resolved by the Dedicated Read Pool and Go-level locking.
	require.NoError(t, err, "GetMailboxByName should not time out (starvation is fixed)")

	// Wait for workers to finish
	wg.Wait()
}
