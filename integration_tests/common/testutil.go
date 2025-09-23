//go:build integration

package common

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

type TestServer struct {
	Address     string
	Server      interface{}
	cleanup     func()
	ResilientDB *resilient.ResilientDatabase
}

type TestAccount struct {
	Email    string
	Password string
}

func (ts *TestServer) Close() {
	if ts.cleanup != nil {
		ts.cleanup()
	}
}

func SetupTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	cfg := &config.DatabaseConfig{
		LogQueries: false, // Set to true for debugging
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatalf("Failed to set up test database: %v", err)
	}

	t.Cleanup(func() {
		rdb.Close()
	})

	return rdb
}

func CreateTestAccount(t *testing.T, rdb *resilient.ResilientDatabase) TestAccount {
	t.Helper()

	email := fmt.Sprintf("test-%s-%d@example.com", strings.ToLower(t.Name()), time.Now().UnixNano())
	password := "s3cur3p4ss!"

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	if err := rdb.CreateAccountWithRetry(context.Background(), req); err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	return TestAccount{Email: email, Password: password}
}

func GetRandomAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen on a random port: %v", err)
	}
	defer listener.Close()

	return listener.Addr().String()
}

func SetupIMAPServer(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imap.New(
		context.Background(),
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imap.IMAPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
		// Clean up temporary directory
		os.RemoveAll(tempDir)
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

func SetupLMTPServer(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create minimal S3 storage for LMTP
	s3Storage := &storage.S3Storage{}

	// Create minimal uploader for LMTP
	tempDir := t.TempDir()
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,
		10,            // batch size
		2,             // concurrency
		3,             // max attempts
		5*time.Second, // retry interval
		"test-host",
		rdb,
		s3Storage,
		nil, // cache
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := lmtp.New(
		context.Background(),
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

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		if err := server.Close(); err != nil {
			t.Logf("Error closing LMTP server: %v", err)
		}
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("LMTP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

func SetupPOP3Server(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := pop3.New(
		context.Background(),
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("POP3 server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

func SkipIfDatabaseUnavailable(t *testing.T) {
	t.Helper()

	if os.Getenv("SKIP_INTEGRATION_TESTS") == "1" {
		t.Skip("Integration tests disabled via SKIP_INTEGRATION_TESTS=1")
	}

	// Try to connect to the database to see if it's available
	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rdb, err := resilient.NewResilientDatabase(ctx, cfg, true, true)
	if err != nil {
		t.Skipf("Database unavailable, skipping integration test: %v", err)
	}
	rdb.Close()
}

func init() {
	// Reduce log noise during tests
	log.SetOutput(os.Stderr)
}
