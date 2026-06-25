//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupHTTPAPIServerWithUploader is like setupHTTPAPIServer but wires a local-disk
// uploader (+ storage + hostname) so /admin/mail/deliver actually stores the message —
// which the default harness does not — letting us assert on the stored bytes. It returns
// the server and the uploader temp dir.
func setupHTTPAPIServerWithUploader(t *testing.T) (*HTTPAPITestServer, string) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)

	cacheDir := t.TempDir()
	sourceDB := &testSourceDB{rdb: rdb}
	testCache, err := cache.New(cacheDir, 100*1024*1024, 10*1024*1024, 5*time.Minute, 1*time.Hour, sourceDB)
	if err != nil {
		t.Fatalf("Failed to create test cache: %v", err)
	}

	tempDir := t.TempDir()
	uploaderInstance, err := uploader.NewWithS3Interface(
		tempDir, 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	addr := common.GetRandomAddress(t)
	options := adminapi.ServerOptions{
		Addr:         addr,
		APIKey:       testAPIKey,
		AllowedHosts: []string{},
		Cache:        testCache,
		Uploader:     uploaderInstance,
		Storage:      &storage.S3Storage{},
		Hostname:     "admin.test",
		TLS:          false,
	}

	server, err := adminapi.New(rdb, options)
	if err != nil {
		t.Fatalf("Failed to create HTTP API server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go adminapi.Start(ctx, rdb, options, errChan)
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-errChan:
		cancel()
		t.Fatalf("Failed to start HTTP API server: %v", err)
	default:
	}

	return &HTTPAPITestServer{
		URL:     fmt.Sprintf("http://%s", addr),
		server:  server,
		rdb:     rdb,
		cache:   testCache,
		cleanup: func() { cancel(); testCache.Close() },
	}, tempDir
}

// readStoredAdminMessage reads the single stored message body from the uploader temp dir
// (files are named by their 64-hex content hash under tempDir/<accountID>/).
func readStoredAdminMessage(t *testing.T, tempDir string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && len(filepath.Base(path)) == 64 {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no stored message found under %s", tempDir)
	}
	b, err := os.ReadFile(found)
	if err != nil {
		t.Fatalf("read stored message: %v", err)
	}
	return string(b)
}

func createDeliveryAccount(t *testing.T, server *HTTPAPITestServer, email string) {
	t.Helper()
	resp, body := server.makeRequest(t, "POST", "/admin/accounts", map[string]string{
		"email": email, "password": "testpassword123",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account %s: %d %s", email, resp.StatusCode, string(body))
	}
}

// TestAdminAPI_DeliverMail_StampsDeliveredToAndReceived verifies that a normal mail
// injection via /admin/mail/deliver stamps Delivered-To (first header) and a Received:
// trace (with HTTP) below it, preserving the original content.
func TestAdminAPI_DeliverMail_StampsDeliveredToAndReceived(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, tempDir := setupHTTPAPIServerWithUploader(t)
	defer server.Close()

	email := fmt.Sprintf("apihdr-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: API Header Test\r\n\r\nBody via API.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	time.Sleep(500 * time.Millisecond)
	stored := readStoredAdminMessage(t, tempDir)

	if !strings.HasPrefix(stored, "Delivered-To: "+email+"\r\n") {
		t.Errorf("Delivered-To must be the first header; got head:\n%s", adminHead(stored))
	}
	dtIdx := strings.Index(stored, "Delivered-To: ")
	rcvIdx := strings.Index(stored, "Received: ")
	if rcvIdx < 0 {
		t.Fatalf("no Received: header in stored message:\n%s", adminHead(stored))
	}
	if rcvIdx < dtIdx {
		t.Errorf("Received: must come after Delivered-To:\n%s", adminHead(stored))
	}
	for _, want := range []string{"by admin.test with HTTP", "for <" + email + ">"} {
		if !strings.Contains(stored, want) {
			t.Errorf("Received: header missing %q:\n%s", want, adminHead(stored))
		}
	}
	for _, want := range []string{"Subject: API Header Test", "Body via API."} {
		if !strings.Contains(stored, want) {
			t.Errorf("original content missing %q", want)
		}
	}
}

// TestAdminAPI_DeliverMail_MigrationBypassesStamping verifies that a migration-style
// injection (target mailbox set) is stored byte-for-byte: no Delivered-To and no
// Received are added, preserving archival fidelity and content dedup.
func TestAdminAPI_DeliverMail_MigrationBypassesStamping(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, tempDir := setupHTTPAPIServerWithUploader(t)
	defer server.Close()

	email := fmt.Sprintf("apimig-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: Migrated Message\r\n\r\nArchived body.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
		"mailbox":    "INBOX", // target mailbox => migration path, bypasses Sieve + stamping
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver(migration): %d %s", resp.StatusCode, string(body))
	}

	time.Sleep(500 * time.Millisecond)
	stored := readStoredAdminMessage(t, tempDir)

	if strings.Contains(stored, "Delivered-To:") {
		t.Errorf("migration delivery must NOT add Delivered-To:\n%s", adminHead(stored))
	}
	if strings.Contains(stored, "Received:") {
		t.Errorf("migration delivery must NOT add Received:\n%s", adminHead(stored))
	}
	if !strings.HasPrefix(stored, "From: sender@example.com\r\n") {
		t.Errorf("migration delivery must preserve original bytes verbatim; got head:\n%s", adminHead(stored))
	}
}

func adminHead(s string) string {
	if len(s) > 600 {
		return s[:600]
	}
	return s
}
