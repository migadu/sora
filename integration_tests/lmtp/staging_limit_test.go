//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func TestLMTP_StagingLimitEnforcement(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Set up dependencies manually to inject a small maxStagingSize
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "lmtp-s3-limit-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	errCh := make(chan error, 1)

	// Set maxStagingSize to 10 bytes (will definitely trigger)
	var maxStagingSize int64 = 10

	// Create upload worker with the small limit
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,
		10,
		2,
		3,
		time.Second,
		maxStagingSize,
		"localhost",
		rdb,
		&common.NoopUploaderS3{},
		&common.NoopUploaderCache{},
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	if err := uploadWorker.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start LMTP upload worker: %v", err)
	}
	defer uploadWorker.Stop()

	// Simulate that the DB currently has some pending uploads so the cache
	// isn't just 0. Actually, the easiest way to test is to just send a message
	// that's larger than 10 bytes! The limit check is `currentSize + additionalSize > maxStagingSize`.
	// Since 10 bytes is tiny, any message will trigger the limit.

	s3Storage := &storage.S3Storage{}
	server, err := lmtp.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3Storage,
		rdb,
		uploadWorker,
		lmtp.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}

	serverErrChan := make(chan error, 1)
	go func() {
		server.Start(serverErrChan)
	}()
	time.Sleep(100 * time.Millisecond)

	defer func() {
		if err := server.Close(); err != nil {
			t.Logf("Error closing LMTP server: %v", err)
		}
	}()

	client, err := NewLMTPClient(address)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer client.Close()

	if err := client.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := client.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	if err := client.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}

	if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}

	if err := client.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}

	// Send message content (much larger than 10 bytes)
	message := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Staging Limit\r\n" +
		"\r\n" +
		"This message is definitely larger than 10 bytes.\r\n" +
		".\r\n"

	if _, err := client.conn.Write([]byte(message)); err != nil {
		t.Fatalf("Failed to send message data: %v", err)
	}

	// The message should be rejected with 452 Insufficient system storage
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read final response: %v", err)
	}

	if !strings.HasPrefix(response, "452") || !strings.Contains(response, "Insufficient system storage") {
		t.Fatalf("Expected 452 Insufficient system storage, got: %s", response)
	}

	t.Logf("✓ Message successfully rejected due to staging limit: %s", response)
}
