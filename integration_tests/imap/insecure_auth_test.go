//go:build integration

package imap_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestInsecureAuthAutoEnabled_IMAP tests that when TLS is not configured,
// InsecureAuth is automatically enabled regardless of the setting.
// This is correct behavior: you can't require TLS if TLS isn't configured.
func TestInsecureAuthAutoEnabled_IMAP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(), tempDir, 10, 1, 3, time.Second,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with InsecureAuth=false and TLS=false (default)
	// The constructor should auto-enable insecureAuth: false || !false = true
	server, err := imapserver.New(
		context.Background(), "test-insecure-auto", "localhost", address,
		&storage.S3Storage{}, rdb, uploadWorker, nil,
		imapserver.IMAPServerOptions{
			InsecureAuth: false, // Explicitly set to false, but TLS is not configured
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	go func() {
		if err := server.Serve(address); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	c, err := imapclient.DialInsecure(address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	// LOGIN should succeed because TLS is not configured, so insecureAuth is auto-enabled
	err = c.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Expected LOGIN to succeed (insecureAuth auto-enabled when TLS not configured), but got: %v", err)
	}

	t.Log("✓ LOGIN succeeded: insecureAuth correctly auto-enabled when TLS is not configured")
}

// TestInsecureAuthExplicitlyEnabled_IMAP tests that InsecureAuth=true works.
func TestInsecureAuthExplicitlyEnabled_IMAP(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(), tempDir, 10, 1, 3, time.Second,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imapserver.New(
		context.Background(), "test-insecure-enabled", "localhost", address,
		&storage.S3Storage{}, rdb, uploadWorker, nil,
		imapserver.IMAPServerOptions{
			InsecureAuth: true,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	go func() {
		if err := server.Serve(address); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	c, err := imapclient.DialInsecure(address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	err = c.Login(account.Email, account.Password).Wait()
	if err != nil {
		t.Fatalf("Expected LOGIN to succeed with InsecureAuth=true, but got: %v", err)
	}

	t.Log("✓ LOGIN succeeded with InsecureAuth=true")
}
