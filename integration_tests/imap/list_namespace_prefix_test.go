//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	soraimap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// setupIMAPServerWithSharedPrefix builds an IMAP server whose shared-mailbox
// namespace prefix is customised (not the "Shared/" default), so tests can verify
// the LIST \Noselect root uses the configured prefix rather than a hard-coded name.
func setupIMAPServerWithSharedPrefix(t *testing.T, prefix string) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(), tempDir, 10, 1, 3, time.Second, 0,
		"test-instance", rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("upload worker: %v", err)
	}

	srv, err := soraimap.New(
		context.Background(), "test", "localhost", address,
		&storage.S3Storage{}, rdb, uploadWorker, nil,
		soraimap.IMAPServerOptions{
			InsecureAuth: true,
			Config: &config.Config{
				SharedMailboxes: config.SharedMailboxesConfig{
					Enabled:               true,
					NamespacePrefix:       prefix,
					AllowUserCreate:       true,
					DefaultRights:         "lrswipkxtea",
					AllowAnyoneIdentifier: true,
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("imap.New: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("serve: %w", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() {
		srv.Close()
		os.RemoveAll(tempDir)
	})

	return &common.TestServer{Address: address, Server: srv, ResilientDB: rdb}, account
}

// TestIMAP_SharedNamespaceRootUsesConfiguredPrefix verifies that the \Noselect
// marker on the shared-namespace root follows the configured namespace_prefix,
// not a hard-coded "Shared". With prefix "TeamShare/", the "TeamShare" root that
// parents shared mailboxes must be reported \Noselect. Before the fix the check
// compared against the literal "Shared", so a custom prefix root was NOT marked.
func TestIMAP_SharedNamespaceRootUsesConfiguredPrefix(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const prefix = "TeamShare/"
	const root = "TeamShare"
	server, account := setupIMAPServerWithSharedPrefix(t, prefix)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}

	// Create a shared mailbox under the custom prefix; its parent (the namespace
	// root) is auto-created and must be reported \Noselect by LIST.
	if err := c.Create(prefix+"Project", nil).Wait(); err != nil {
		t.Fatalf("CREATE %sProject: %v", prefix, err)
	}

	mboxes, err := c.List("", "*", nil).Collect()
	if err != nil {
		t.Fatalf("LIST: %v", err)
	}

	var rootData *imap.ListData
	for _, m := range mboxes {
		if m.Mailbox == root {
			rootData = m
			break
		}
	}
	if rootData == nil {
		t.Fatalf("namespace root %q not present in LIST; got %v", root, mboxes)
	}
	if !hasAttr(rootData.Attrs, imap.MailboxAttrNoSelect) {
		t.Errorf("namespace root %q must be \\Noselect (configured prefix %q); attrs=%v", root, prefix, rootData.Attrs)
	}
}
