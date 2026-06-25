//go:build integration

package common

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/pkg/spamtraining"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// ScriptedS3 is a minimal S3 GetObject emulator for fetch-path tests. It returns a real
// NoSuchKey 404 — which the AWS SDK deserializes into the same typed *types.NoSuchKey that
// production sees — for the first FailFirst GETs, then serves the configured body. This
// drives the not-yet-uploaded retry path with genuine S3 responses (real error
// classification, the bounded retry, and the pending-gate), which the empty-stub S3 cannot.
// Construct it with NewScriptedS3.
type ScriptedS3 struct {
	mu        sync.Mutex
	body      []byte
	failFirst int
	gets      int
}

// SetBody sets the body served once the scripted NoSuchKey responses are exhausted.
func (f *ScriptedS3) SetBody(b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body = append([]byte(nil), b...)
}

// GetCount returns how many GET requests have been received so far.
func (f *ScriptedS3) GetCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets
}

func (f *ScriptedS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	f.mu.Lock()
	f.gets++
	n, body, failFirst := f.gets, f.body, f.failFirst
	f.mu.Unlock()

	if n <= failFirst {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-amz-request-id", "test-req")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// NewScriptedS3 starts a fake S3 endpoint (cleaned up via t.Cleanup) that returns NoSuchKey
// for the first failFirst GETs, then the body. It returns the controller plus a real
// *storage.S3Storage pointed at it (path-style addressing makes the httptest server a valid
// S3 endpoint).
func NewScriptedS3(t *testing.T, failFirst int) (*ScriptedS3, *storage.S3Storage) {
	t.Helper()
	fake := &ScriptedS3{failFirst: failFirst}
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	s3, err := storage.New(srv.URL, "test", "test", "test-bucket", false, false, 5*time.Second)
	if err != nil {
		t.Fatalf("storage.New(fake S3): %v", err)
	}
	return fake, s3
}

// NoopUploaderS3 is a no-op S3 implementation used in integration tests.
// PutWithRetry always succeeds (returns nil), allowing the upload worker to
// immediately mark messages as uploaded=true in the database.  This is
// required because all FETCH query paths now filter to m.uploaded = true for
// multi-node correctness — without a working upload path, freshly-APPENDed
// messages would never appear in FETCH responses.
type NoopUploaderS3 struct{}

func (n *NoopUploaderS3) PutWithRetry(_ context.Context, _ string, r io.Reader, _ int64) error {
	// Drain the reader so the caller does not block on a full pipe.
	_, _ = io.Copy(io.Discard, r)
	return nil
}

func (n *NoopUploaderS3) ExistsWithRetry(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// NoopUploaderCache is a no-op cache used in integration tests.
// MoveIn deliberately does nothing, which leaves the local file on disk.
// This is required so that after the no-op S3 upload the IMAP server can
// still serve the message body via the local-disk fallback in getMessageBody.
type NoopUploaderCache struct{}

func (c *NoopUploaderCache) MoveIn(_, _ string) error { return nil }

type TestServer struct {
	Address      string
	Server       any
	cleanup      func()
	ResilientDB  *resilient.ResilientDatabase
	uploadWorker *uploader.UploadWorker // exposed for WaitForUploads
	UploadPath   string                 // local staging dir; set by setups that need to manipulate staged files
}

// WaitForUploads blocks until all pending uploads for this test server have
// been processed and messages are marked uploaded=true in the database.
// Call this between an APPEND and a subsequent FETCH in tests to ensure the
// FETCH query (which filters on m.uploaded = true) can see the new message.
func (ts *TestServer) WaitForUploads(t interface {
	Helper()
	Fatalf(string, ...any)
}) {
	t.Helper()
	if ts.uploadWorker == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := ts.uploadWorker.DrainSync(ctx); err != nil {
		t.Fatalf("WaitForUploads: DrainSync failed: %v", err)
	}
}

type TestAccount struct {
	Email    string
	Password string
}

// IMAPServerOpts contains optional configuration for IMAP server setup
type IMAPServerOpts struct {
	SpamTrainingEnabled           bool
	SpamTrainingEndpoint          string
	SpamTrainingToken             string
	SpamTrainingCircuitThreshold  int
	SpamTrainingCircuitTimeout    string
	SpamTrainingCircuitMaxRequest int
}

func (ts *TestServer) Close() {
	if ts.cleanup != nil {
		ts.cleanup()
	}
}

// SetCleanup sets the cleanup function for the test server
func (ts *TestServer) SetCleanup(cleanup func()) {
	ts.cleanup = cleanup
}

// FlushFTSQueue synchronously forces the FTS worker logic to process any pending
// messages_fts rows so that subsequent SEARCH commands find newly appended messages.
func (ts *TestServer) FlushFTSQueue() error {
	_, err := ts.ResilientDB.ProcessFTSBatchWithRetry(context.Background(), 5000)
	return err
}

func SetupTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	// Use database name from environment variable, or default to sora_test_db
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}

	cfg := &config.DatabaseConfig{
		Debug: false, // Set to true for debugging
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     dbName,
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

	// Subtest names embed '/' (and '#NN' for duplicate names), neither of which is a
	// valid email local-part character since the local-part validation was tightened
	// (M3 audit fix). Sanitize them so helpers invoked inside t.Run subtests still
	// produce a creatable test address.
	safeName := strings.NewReplacer("/", "-", "#", "-").Replace(strings.ToLower(t.Name()))
	email := fmt.Sprintf("test-%s-%d@example.com", safeName, time.Now().UnixNano())
	password := "s3cur3p4ss!"

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	accountID, err := rdb.CreateAccountWithRetry(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Create default mailboxes (INBOX, Sent, Drafts, etc.)
	tx, err := rdb.BeginTxWithRetry(context.Background(), pgx.TxOptions{})
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	if err := rdb.GetDatabase().CreateDefaultMailboxes(context.Background(), tx, accountID); err != nil {
		t.Fatalf("Failed to create default mailboxes: %v", err)
	}

	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	return TestAccount{Email: email, Password: password}
}

// CreateTestAccountWithEmail creates a test account with a specific email
func CreateTestAccountWithEmail(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) TestAccount {
	t.Helper()

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	accountID, err := rdb.CreateAccountWithRetry(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	// Create default mailboxes (INBOX, Sent, Drafts, etc.)
	tx, err := rdb.BeginTxWithRetry(context.Background(), pgx.TxOptions{})
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	if err := rdb.GetDatabase().CreateDefaultMailboxes(context.Background(), tx, accountID); err != nil {
		t.Fatalf("Failed to create default mailboxes: %v", err)
	}

	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	return TestAccount{Email: email, Password: password}
}

// GetTimestamp returns current Unix nano timestamp for unique identifiers
func GetTimestamp() int64 {
	return time.Now().UnixNano()
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

	// Use NewWithS3Interface + NoopUploaderS3 so the upload worker can complete
	// uploads immediately (no real S3 needed).  This is required because all FETCH
	// query paths filter on m.uploaded = true; without a working upload path,
	// freshly-APPENDed messages would be invisible to FETCH.
	//
	// IMPORTANT: instanceID must match the IMAP server's hostname ("localhost")
	// because pending_uploads.instance_id is set to the server's hostname, and
	// AcquireAndLeasePendingUploads queries WHERE instance_id = $1.
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,     // path
		10,          // batchSize
		1,           // concurrency
		3,           // maxAttempts
		time.Second, // retryInterval
		0,           // maxStagingSize
		"localhost", // instanceID — must match imap.New hostname arg
		rdb,         // database
		&NoopUploaderS3{},
		&NoopUploaderCache{}, // keeps local file on disk so getMessageBody can fall back to disk when S3 unavailable
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Enable synchronous-upload mode: NotifyUploadQueued will process the
	// pending-upload queue in the caller's goroutine before returning.
	// This guarantees that messages are marked uploaded=true in the database
	// before the APPEND response is delivered to the client, allowing tests to
	// FETCH immediately after APPEND without a race condition.
	uploadWorker.EnableSyncUpload()

	// Start the upload worker so it processes queued uploads.
	if err := uploadWorker.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start upload worker: %v", err)
	}

	// Create test config with shared mailboxes enabled
	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth: true, // Allow PLAIN auth (no TLS in tests)
			Config:       testConfig,
		},
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
		uploadWorker.Stop()
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
		Address:      address,
		Server:       server,
		cleanup:      cleanup,
		ResilientDB:  rdb,
		uploadWorker: uploadWorker,
		UploadPath:   tempDir,
	}, account
}

// SetupIMAPServerWithRealS3 creates an IMAP server backed by an in-memory FakeS3
// (real PutObject/GetObject/HeadObject/CopyObject). Both the upload worker and the
// IMAP server share the same storage, and the worker runs in synchronous mode with
// NO local cache — so an APPENDed message is uploaded to S3 and its local staging
// file is removed, forcing subsequent FETCHes (and cross-account server-side COPY)
// to exercise the genuine S3 round-trip. Shared mailboxes are enabled.
func SetupIMAPServerWithRealS3(t *testing.T) (*TestServer, TestAccount, *FakeS3) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-reals3-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	fake, s3storage := NewFakeS3Storage(t)

	errCh := make(chan error, 1)
	// instanceID must match the IMAP server hostname ("localhost") because
	// pending_uploads.instance_id is set to the hostname and the worker queries
	// WHERE instance_id = $1.
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,     // path
		10,          // batchSize
		1,           // concurrency
		3,           // maxAttempts
		time.Second, // retryInterval
		0,           // maxStagingSize
		"localhost", // instanceID
		rdb,
		s3storage,
		nil, // no cache: local file removed after upload, so FETCH must hit S3
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	uploadWorker.EnableSyncUpload()
	if err := uploadWorker.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start upload worker: %v", err)
	}

	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3storage,
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth: true,
			Config:       testConfig,
		},
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

	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		uploadWorker.Stop()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
		os.RemoveAll(tempDir)
	}

	return &TestServer{
		Address:      address,
		Server:       server,
		cleanup:      cleanup,
		ResilientDB:  rdb,
		uploadWorker: uploadWorker,
		UploadPath:   tempDir,
	}, account, fake
}

// NewSyncUploaderWithS3 builds a synchronous, no-cache upload worker backed by the
// same in-memory FakeS3, leased under the given instanceID. It is started and torn
// down via t.Cleanup. Use a distinct instanceID per server so workers don't race on
// each other's pending_uploads.
func NewSyncUploaderWithS3(t *testing.T, rdb *resilient.ResilientDatabase, fake *FakeS3, instanceID string) *uploader.UploadWorker {
	t.Helper()
	s3storage, err := storage.New(
		fake.Endpoint(), "test-access-key", "test-secret-key", "test-bucket",
		false, false, 10*time.Second,
	)
	if err != nil {
		t.Fatalf("Failed to create S3 storage: %v", err)
	}
	tempDir, err := os.MkdirTemp("", "sora-test-sync-up-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	errCh := make(chan error, 1)
	up, err := uploader.New(
		context.Background(),
		tempDir, 10, 1, 3, time.Second, 0,
		instanceID, rdb, s3storage, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	up.EnableSyncUpload()
	if err := up.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start upload worker: %v", err)
	}
	t.Cleanup(func() {
		up.Stop()
		os.RemoveAll(tempDir)
	})
	return up
}

// StartLMTPServerWithS3 starts an LMTP backend that shares rdb and is backed by the
// same in-memory FakeS3, with a synchronous real-S3 uploader and no local cache — so
// an LMTP-delivered (or SIEVE fileinto'd) message is uploaded to S3 and its staging
// file removed, exactly like the IMAP real-S3 setup. It uses a DISTINCT hostname
// ("lmtp-host") so its uploader's pending_uploads (instance_id) never race with the
// IMAP server's "localhost" uploader. Returns the LMTP listen address; the server,
// uploader, and temp dir are torn down via t.Cleanup.
func StartLMTPServerWithS3(t *testing.T, rdb *resilient.ResilientDatabase, fake *FakeS3) string {
	t.Helper()

	s3storage, err := storage.New(
		fake.Endpoint(),
		"test-access-key",
		"test-secret-key",
		"test-bucket",
		false, false, 10*time.Second,
	)
	if err != nil {
		t.Fatalf("Failed to create S3 storage for LMTP: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "sora-test-lmtp-reals3-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	const lmtpHost = "lmtp-host"
	errCh := make(chan error, 1)
	up, err := uploader.New(
		context.Background(),
		tempDir, 10, 1, 3, time.Second, 0,
		lmtpHost, // instanceID must match the LMTP server hostname below
		rdb, s3storage, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP upload worker: %v", err)
	}
	up.EnableSyncUpload()
	if err := up.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start LMTP upload worker: %v", err)
	}

	addr := GetRandomAddress(t)
	srv, err := lmtp.New(context.Background(), "test-lmtp", lmtpHost, addr, s3storage, rdb, up, lmtp.LMTPServerOptions{})
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	go srv.Start(make(chan error, 1))
	time.Sleep(200 * time.Millisecond)

	t.Cleanup(func() {
		srv.Close()
		up.Stop()
		os.RemoveAll(tempDir)
	})
	return addr
}

// SetupIMAPServerForUploadRace creates an IMAP server whose upload worker is
// constructed but NOT started and NOT in synchronous mode. APPENDed messages are
// therefore staged on local disk and recorded in pending_uploads, but never marked
// uploaded=true (no worker processes the queue). This lets tests reproduce the
// "not-yet-uploaded" body-fetch race: delete the staged file under TestServer.UploadPath
// to simulate a fetch hitting a node that does not hold the staging file while S3 does
// not yet have the object. The IMAP server's S3 is an empty stub, so body reads miss S3.
func SetupIMAPServerForUploadRace(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()
	return SetupIMAPServerForUploadRaceWithS3(t, &storage.S3Storage{})
}

// SetupIMAPServerForUploadRaceWithS3 is SetupIMAPServerForUploadRace with a caller-provided
// S3 backend, letting a test script GET responses (e.g. NoSuchKey then a body via a fake S3
// endpoint) to exercise the not-yet-uploaded retry/timing path end to end.
func SetupIMAPServerForUploadRaceWithS3(t *testing.T, s3Storage *storage.S3Storage) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-race-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	errCh := make(chan error, 1)

	// instanceID must match the IMAP server hostname ("localhost") so that the
	// pending_uploads rows are attributable, matching the other setups.
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,     // path
		10,          // batchSize
		1,           // concurrency
		3,           // maxAttempts
		time.Second, // retryInterval
		0,           // maxStagingSize
		"localhost", // instanceID — must match imap.New hostname arg
		rdb,         // database
		&NoopUploaderS3{},
		&NoopUploaderCache{},
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	// Deliberately NOT calling EnableSyncUpload()/Start(): uploads stay pending so
	// APPENDed messages remain uploaded=false with their bodies only on local disk.

	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3Storage,
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth: true,
			Config:       testConfig,
		},
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

	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		uploadWorker.Stop() // no-op if never started
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
		os.RemoveAll(tempDir)
	}

	return &TestServer{
		Address:      address,
		Server:       server,
		cleanup:      cleanup,
		ResilientDB:  rdb,
		uploadWorker: uploadWorker,
		UploadPath:   tempDir,
	}, account
}

// SetupIMAPServerWithOptions creates an IMAP server with custom options (e.g., spam training)
func SetupIMAPServerWithOptions(t *testing.T, opts *IMAPServerOpts) (*TestServer, TestAccount) {
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
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create test config with shared mailboxes enabled
	testConfig := &config.Config{
		SharedMailboxes: config.SharedMailboxesConfig{
			Enabled:               true,
			NamespacePrefix:       "Shared/",
			AllowUserCreate:       true,
			DefaultRights:         "lrswipkxtea",
			AllowAnyoneIdentifier: true,
		},
	}

	// Configure spam training if enabled
	var spamTrainingClient *spamtraining.Client
	if opts != nil && opts.SpamTrainingEnabled {
		cfg := &config.SpamTrainingConfig{
			Enabled:           true,
			Endpoint:          opts.SpamTrainingEndpoint,
			AuthToken:         opts.SpamTrainingToken,
			Timeout:           "10s",
			MaxMessageSize:    "10MB",
			MaxAttachmentSize: "5MB",
			Async:             true,
			CircuitBreaker: config.SpamTrainingCircuitBreakerConfig{
				Threshold:   opts.SpamTrainingCircuitThreshold,
				Timeout:     opts.SpamTrainingCircuitTimeout,
				MaxRequests: opts.SpamTrainingCircuitMaxRequest,
			},
		}

		// Set defaults if not specified
		if cfg.CircuitBreaker.Threshold == 0 {
			cfg.CircuitBreaker.Threshold = 5
		}
		if cfg.CircuitBreaker.Timeout == "" {
			cfg.CircuitBreaker.Timeout = "30s"
		}
		if cfg.CircuitBreaker.MaxRequests == 0 {
			cfg.CircuitBreaker.MaxRequests = 3
		}

		spamTrainingClient, err = spamtraining.NewClient(cfg)
		if err != nil {
			t.Fatalf("Failed to create spam training client: %v", err)
		}
	}

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth: true, // Allow PLAIN auth (no TLS in tests)
			Config:       testConfig,
			SpamTraining: spamTrainingClient,
		},
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

	// Use NoopUploaderS3 + EnableSyncUpload so LMTP-delivered messages are
	// immediately marked uploaded=true in the database (same approach as SetupIMAPServer).
	// Without this, FETCH queries with AND m.uploaded = true would never find them.
	tempDir := t.TempDir()
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.NewWithS3Interface(
		tempDir,
		10,          // batch size
		2,           // concurrency
		3,           // max attempts
		time.Second, // retry interval
		0,           // maxStagingSize
		"localhost", // instanceID must match lmtp.New hostname arg
		rdb,
		&NoopUploaderS3{},
		&NoopUploaderCache{},
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	// Start the upload worker but do NOT enable sync mode.  Background processing
	// with NoopS3 completes quickly and doesn't interfere with LMTP delivery flow.
	// Tests that need to FETCH after LMTP delivery can call server.WaitForUploads(t)
	// to ensure uploads are processed before querying.
	if err := uploadWorker.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start LMTP upload worker: %v", err)
	}

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
		Address:      address,
		Server:       server,
		cleanup:      cleanup,
		ResilientDB:  rdb,
		uploadWorker: uploadWorker,
	}, account
}

func SetupPOP3Server(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{InsecureAuth: true},
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

// SetupIMAPServerWithPROXY sets up an IMAP server with PROXY protocol support for proxy testing
func SetupIMAPServerWithPROXY(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-proxy-*")
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
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with PROXY protocol support and master user credentials
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth:         true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:        true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout: "5s",                               // Timeout for PROXY headers
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername:   []byte(masterUsername),             // Master username for proxy authentication
			MasterSASLPassword:   []byte(masterPassword),             // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server with PROXY support: %v", err)
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

// SetupIMAPServerWithPROXYAndDatabase sets up an IMAP server with PROXY protocol using an existing database
func SetupIMAPServerWithPROXYAndDatabase(t *testing.T, rdb *resilient.ResilientDatabase) *TestServer {
	t.Helper()

	address := GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-proxy-*")
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
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with PROXY protocol support and master user credentials
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth:         true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:        true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout: "5s",                               // Timeout for PROXY headers
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername:   []byte(masterUsername),             // Master username for proxy authentication
			MasterSASLPassword:   []byte(masterPassword),             // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server with PROXY support: %v", err)
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
	}
}

// SetupIMAPServerWithMaster sets up an IMAP server with master credentials (no PROXY protocol)
func SetupIMAPServerWithMaster(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-master-*")
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
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create IMAP server with master credentials but no PROXY protocol
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := imap.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker, // properly initialized UploadWorker
		nil,          // cache.Cache
		imap.IMAPServerOptions{
			InsecureAuth:       true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:      false,                              // Disable PROXY protocol (ID command mode)
			TrustedNetworks:    []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername: []byte(masterUsername),             // Master username for proxy authentication
			MasterSASLPassword: []byte(masterPassword),             // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server with master credentials: %v", err)
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

// SetupPOP3ServerWithPROXY sets up a POP3 server with PROXY protocol support for proxy testing
func SetupPOP3ServerWithPROXY(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create POP3 server with PROXY protocol support and master credentials
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			InsecureAuth:         true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:        true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout: "5s",                               // Timeout for PROXY headers
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername:   masterUsername,                     // Master username for proxy authentication
			MasterSASLPassword:   masterPassword,                     // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with PROXY support: %v", err)
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

// SetupPOP3ServerForXCLIENT sets up a POP3 server for XCLIENT proxy testing
// This server does NOT use PROXY protocol (expects plain connections with XCLIENT command)
func SetupPOP3ServerForXCLIENT(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create POP3 server with master credentials and XCLIENT support (no PROXY protocol)
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			InsecureAuth:         true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:        false,                              // Disable PROXY protocol (using XCLIENT instead)
			ProxyProtocolTimeout: "5s",                               // Not used when ProxyProtocol is false
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost for XCLIENT commands
			MasterSASLUsername:   masterUsername,                     // Master username for proxy authentication
			MasterSASLPassword:   masterPassword,                     // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server for XCLIENT: %v", err)
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

// SetupPOP3ServerWithMaster sets up a POP3 server with master credentials (no PROXY protocol)
func SetupPOP3ServerWithMaster(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create POP3 server with master credentials but no PROXY protocol
	masterUsername := "proxyuser"
	masterPassword := "proxypass"

	server, err := pop3.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			InsecureAuth:       true,                               // Allow PLAIN auth (no TLS in tests)
			ProxyProtocol:      false,                              // Disable PROXY protocol (XCLIENT mode)
			TrustedNetworks:    []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername: masterUsername,                     // Master username for proxy authentication
			MasterSASLPassword: masterPassword,                     // Master password for proxy authentication
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with master credentials: %v", err)
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

// SetupPOP3ServerWithTimeout sets up a POP3 server with a custom command timeout for testing
func SetupPOP3ServerWithTimeout(t *testing.T, commandTimeout time.Duration) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := pop3.New(
		context.Background(),
		"test-timeout",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			InsecureAuth:   true, // Allow PLAIN auth (no TLS in tests)
			CommandTimeout: commandTimeout,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with timeout: %v", err)
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

// SetupPOP3ServerWithInsecureAuth sets up a POP3 server with configurable insecure_auth for testing
func SetupPOP3ServerWithInsecureAuth(t *testing.T, insecureAuth bool) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := pop3.New(
		context.Background(),
		"test-insecure-auth",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil,
		nil,
		pop3.POP3ServerOptions{
			InsecureAuth: insecureAuth,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with insecure_auth=%v: %v", insecureAuth, err)
	}

	errChan := make(chan error, 1)
	go func() {
		server.Start(errChan)
	}()

	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("POP3 server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

// SetupLMTPServerWithPROXY sets up an LMTP server with PROXY protocol support for proxy testing
func SetupLMTPServerWithPROXY(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create a temporary directory for S3 storage
	tempDir, err := os.MkdirTemp("", "lmtp-s3-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	s3Storage := &storage.S3Storage{} // Use empty S3 storage for testing

	// Create upload worker with proper parameters
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,         // path
		10,              // batchSize
		2,               // concurrency
		3,               // maxAttempts
		5*time.Second,   // retryInterval
		0,               // maxStagingSize
		"test-instance", // instanceID
		rdb,             // database
		s3Storage,       // s3
		nil,             // cache (nil for testing)
		errCh,           // error channel
	)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := lmtp.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3Storage,
		rdb,
		uploadWorker,
		lmtp.LMTPServerOptions{
			ProxyProtocol:        true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout: "5s",                               // Timeout for PROXY headers
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
		},
	)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create LMTP server with PROXY support: %v", err)
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

// SetupLMTPServerWithXCLIENT sets up an LMTP server without PROXY protocol (for XCLIENT mode)
func SetupLMTPServerWithXCLIENT(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create a temporary directory for S3 storage
	tempDir, err := os.MkdirTemp("", "lmtp-s3-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	s3Storage := &storage.S3Storage{} // Use empty S3 storage for testing

	// Create upload worker with proper parameters
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,         // path
		10,              // batchSize
		2,               // concurrency
		3,               // maxAttempts
		5*time.Second,   // retryInterval
		0,               // maxStagingSize
		"test-instance", // instanceID
		rdb,             // database
		s3Storage,       // s3
		nil,             // cache (nil for testing)
		errCh,           // error channel
	)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := lmtp.New(
		context.Background(),
		"test",
		"localhost",
		address,
		s3Storage,
		rdb,
		uploadWorker,
		lmtp.LMTPServerOptions{
			ProxyProtocol:   false,                              // Disable PROXY protocol (XCLIENT mode)
			TrustedNetworks: []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections for XCLIENT
		},
	)
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create LMTP server for XCLIENT mode: %v", err)
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

func SetupManageSieveServer(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth: true, // Enable PLAIN auth for testing
			// Test with a subset of supported extensions
			SupportedExtensions: []string{"fileinto", "vacation", "envelope", "variables"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
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
				t.Logf("ManageSieve server error during shutdown: %v", err)
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

func init() {
	// Reduce log noise during tests
	log.SetOutput(os.Stderr)
}

// SetupManageSieveServerWithTimeout sets up a ManageSieve server with a custom command timeout for testing
func SetupManageSieveServerWithTimeout(t *testing.T, commandTimeout time.Duration) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := managesieve.New(
		context.Background(),
		"test-timeout",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:        true, // Enable PLAIN auth for testing
			SupportedExtensions: []string{"fileinto", "vacation", "envelope", "variables"},
			CommandTimeout:      commandTimeout,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server with timeout: %v", err)
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
				t.Logf("ManageSieve server error during shutdown: %v", err)
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

// SetupIMAPServerWithTimeout creates an IMAP server with custom command timeout for testing
func SetupIMAPServerWithTimeout(t *testing.T, commandTimeout time.Duration) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create minimal S3 storage mock
	s3Storage := &storage.S3Storage{}

	server, err := imap.New(
		context.Background(),
		"test-timeout",
		"localhost",
		address,
		s3Storage,
		rdb,
		nil, // upload worker
		nil, // cache
		imap.IMAPServerOptions{
			InsecureAuth:   true, // Allow PLAIN auth (no TLS in tests)
			CommandTimeout: commandTimeout,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		err := server.Serve(address)
		if err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cleanup function - database cleanup is already handled by SetupTestDatabase
	cleanup := func() {
		server.Close()
	}

	t.Cleanup(cleanup)

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

// SetupIMAPServerWithSlowloris creates an IMAP server with custom timeouts and slowloris protection for testing
func SetupIMAPServerWithSlowloris(t *testing.T, commandTimeout time.Duration, minBytesPerMinute int64) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create minimal S3 storage mock
	s3Storage := &storage.S3Storage{}

	server, err := imap.New(
		context.Background(),
		"test-slowloris",
		"localhost",
		address,
		s3Storage,
		rdb,
		nil, // upload worker
		nil, // cache
		imap.IMAPServerOptions{
			InsecureAuth:      true, // Allow PLAIN auth (no TLS in tests)
			CommandTimeout:    commandTimeout,
			MinBytesPerMinute: minBytesPerMinute,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	go func() {
		err := server.Serve(address)
		if err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cleanup function - database cleanup is already handled by SetupTestDatabase
	cleanup := func() {
		server.Close()
	}

	t.Cleanup(cleanup)

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

// SetupManageSieveServerWithMaster sets up a ManageSieve server with master credentials
func SetupManageSieveServerWithMaster(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:       true,
			MasterUsername:     "master_admin",
			MasterPassword:     "master_secret_789",
			MasterSASLUsername: "master_sasl",
			MasterSASLPassword: "master_sasl_secret",
			// Test with a subset of supported extensions
			SupportedExtensions: []string{"fileinto", "vacation", "envelope", "variables"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server with master auth: %v", err)
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
				t.Logf("ManageSieve server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

// SetupManageSieveServerWithPROXY sets up a ManageSieve server with PROXY protocol support for proxy testing
func SetupManageSieveServerWithPROXY(t *testing.T) (*TestServer, TestAccount) {
	t.Helper()

	rdb := SetupTestDatabase(t)
	account := CreateTestAccount(t, rdb)
	address := GetRandomAddress(t)

	// Create ManageSieve server with PROXY protocol support and master SASL credentials
	masterSASLUsername := "master_sasl"
	masterSASLPassword := "master_sasl_secret"

	server, err := managesieve.New(
		context.Background(),
		"test",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			InsecureAuth:                true,
			ProxyProtocol:               true,                               // Enable PROXY protocol support
			ProxyProtocolTimeout:        "5s",                               // Timeout for PROXY headers
			ProxyProtocolTrustedProxies: []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			TrustedNetworks:             []string{"127.0.0.0/8", "::1/128"}, // Trust localhost connections
			MasterSASLUsername:          masterSASLUsername,                 // Master username for proxy authentication
			MasterSASLPassword:          masterSASLPassword,                 // Master password for proxy authentication
			SupportedExtensions:         []string{"fileinto", "vacation", "envelope", "variables"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server with PROXY support: %v", err)
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
				t.Logf("ManageSieve server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
		}
	}

	return &TestServer{
		Address:     address,
		Server:      server,
		cleanup:     cleanup,
		ResilientDB: rdb,
	}, account
}

// DialPOP3 connects to a POP3 server and reads the greeting
func DialPOP3(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Read greeting (+OK ...)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	greeting := string(buf[:n])
	if !strings.HasPrefix(greeting, "+OK") {
		conn.Close()
		return nil, fmt.Errorf("invalid greeting: %s", greeting)
	}

	return conn, nil
}

// POP3Login authenticates with USER/PASS commands
func POP3Login(conn net.Conn, email, password string) error {
	// Send USER command
	if _, err := fmt.Fprintf(conn, "USER %s\r\n", email); err != nil {
		return fmt.Errorf("failed to send USER: %w", err)
	}

	// Read USER response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read USER response: %w", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		return fmt.Errorf("USER failed: %s", string(buf[:n]))
	}

	// Send PASS command
	if _, err := fmt.Fprintf(conn, "PASS %s\r\n", password); err != nil {
		return fmt.Errorf("failed to send PASS: %w", err)
	}

	// Read PASS response
	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read PASS response: %w", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "+OK") {
		return fmt.Errorf("PASS failed: %s", string(buf[:n]))
	}

	return nil
}

// POP3Quit sends QUIT command and closes connection
func POP3Quit(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "QUIT\r\n"); err != nil {
		return fmt.Errorf("failed to send QUIT: %w", err)
	}

	// Read QUIT response
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf) // Ignore errors on quit

	return conn.Close()
}

// DialManageSieve connects to a ManageSieve server and reads the greeting
func DialManageSieve(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Read greeting (OK ...)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	greeting := string(buf[:n])
	if !strings.Contains(greeting, "OK") {
		conn.Close()
		return nil, fmt.Errorf("invalid greeting: %s", greeting)
	}

	return conn, nil
}

// ManageSieveLogin authenticates with AUTHENTICATE PLAIN (one-line form)
func ManageSieveLogin(conn net.Conn, email, password string) error {
	// Encode credentials: base64(\0email\0password)
	credentials := fmt.Sprintf("\x00%s\x00%s", email, password)
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))

	// Send AUTHENTICATE PLAIN command with credentials in one line
	if _, err := fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded); err != nil {
		return fmt.Errorf("failed to send AUTHENTICATE: %w", err)
	}

	// Read authentication response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}
	if !strings.HasPrefix(string(buf[:n]), "OK") {
		return fmt.Errorf("authentication failed: %s", string(buf[:n]))
	}

	return nil
}

// ManageSieveLogout sends LOGOUT command and closes connection
func ManageSieveLogout(conn net.Conn) error {
	if _, err := fmt.Fprintf(conn, "LOGOUT\r\n"); err != nil {
		return fmt.Errorf("failed to send LOGOUT: %w", err)
	}

	// Read LOGOUT response
	buf := make([]byte, 1024)
	_, _ = conn.Read(buf) // Ignore errors on logout

	return conn.Close()
}

// DialLMTP connects to an LMTP server and reads the greeting
func DialLMTP(address string) (net.Conn, error) {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Read greeting (220 ...)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read greeting: %w", err)
	}

	greeting := string(buf[:n])
	if !strings.HasPrefix(greeting, "220") {
		conn.Close()
		return nil, fmt.Errorf("invalid greeting: %s", greeting)
	}

	return conn, nil
}
