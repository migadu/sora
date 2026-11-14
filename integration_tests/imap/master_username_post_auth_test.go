//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAP_MasterUsername_LoginPreparesFreshAccount proves that a master-username
// login ("user@domain.com@MASTERUSER") completes exactly like a regular login, on
// both commands that reach the master form (LOGIN in login.go, AUTHENTICATE PLAIN
// in sasl.go).
//
// Account creation makes no mailboxes: they are created by the first login or
// delivery. A login that skips that step leaves an account that never logged in
// nor received mail without an INBOX for the whole session. The same login must
// also trigger the cache warmup a regular login triggers.
//
// The regular LOGIN subtest is the control: it shows that the checks pass for a
// login that prepares the account and that the warmup is observable. The fixture
// itself checks that every account starts without mailboxes.
func TestIMAP_MasterUsername_LoginPreparesFreshAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"
	serverName := fmt.Sprintf("test-master-username-post-auth-%d", time.Now().UnixNano())
	address := startIMAPWithMasterUsernameAndWarmup(t, rdb, serverName, masterUser, masterPass)

	logins := []struct {
		name  string
		login func(c *imapclient.Client, email, password string) error
	}{
		{"regular_LOGIN", func(c *imapclient.Client, email, password string) error {
			return c.Login(email, password).Wait()
		}},
		{"master_LOGIN", func(c *imapclient.Client, email, _ string) error {
			return c.Login(email+"@"+masterUser, masterPass).Wait()
		}},
		{"master_AUTHENTICATE_PLAIN", func(c *imapclient.Client, email, _ string) error {
			return c.Authenticate(sasl.NewPlainClient("", email+"@"+masterUser, masterPass))
		}},
	}

	for _, l := range logins {
		t.Run(l.name, func(t *testing.T) {
			email, password := createAccountWithoutMailboxes(t, rdb)

			c, err := imapclient.DialInsecure(address, nil)
			if err != nil {
				t.Fatalf("Failed to dial IMAP server: %v", err)
			}
			defer c.Logout()

			warmupsBefore := warmupsEnqueued(serverName)
			if err := l.login(c, email, password); err != nil {
				t.Fatalf("login failed: %v", err)
			}
			warmups := warmupsEnqueued(serverName) - warmupsBefore

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("SELECT INBOX after the login: %v", err)
			}

			listed, err := c.List("", "*", nil).Collect()
			if err != nil {
				t.Fatalf("LIST failed: %v", err)
			}
			have := make(map[string]bool, len(listed))
			for _, m := range listed {
				have[m.Mailbox] = true
			}
			for _, name := range consts.DefaultMailboxes {
				if !have[name] {
					t.Errorf("default mailbox %q missing after the login (LIST returned %d mailboxes)", name, len(listed))
				}
			}

			if warmups != 1 {
				t.Errorf("the login enqueued %v cache warmups, want 1", warmups)
			}
		})
	}
}

// createAccountWithoutMailboxes creates an account the way account creation
// does, with no mailboxes, unlike common.CreateTestAccount. It fails the test if
// the account already has a mailbox, since every check after the login would
// then pass without the login having created anything.
func createAccountWithoutMailboxes(t *testing.T, rdb *resilient.ResilientDatabase) (email, password string) {
	t.Helper()

	email = fmt.Sprintf("fresh-%d@example.com", time.Now().UnixNano())
	password = "s3cur3p4ss!"
	accountID, err := rdb.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	mailboxes, err := rdb.GetMailboxesWithRetry(context.Background(), accountID, false)
	if err != nil {
		t.Fatalf("Failed to list the new account's mailboxes: %v", err)
	}
	if len(mailboxes) != 0 {
		t.Fatalf("the new account already has %d mailboxes before any login, want 0", len(mailboxes))
	}
	return email, password
}

// warmupsEnqueued reads how many cache warmups the named server has enqueued.
// The counter is incremented inside the login command, before its reply.
func warmupsEnqueued(serverName string) float64 {
	return testutil.ToFloat64(metrics.WarmupOperationsTotal.WithLabelValues(serverName, "enqueued"))
}

// startIMAPWithMasterUsernameAndWarmup starts an IMAP backend configured with the
// master-username form and an asynchronous cache warmup of INBOX.
func startIMAPWithMasterUsernameAndWarmup(t *testing.T, rdb *resilient.ResilientDatabase, serverName, masterUser, masterPass string) string {
	t.Helper()

	c, err := cache.New(t.TempDir(), 100*1024*1024, 10*1024*1024, 5*time.Minute, time.Hour, rdb)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	address := common.GetRandomAddress(t)
	srv, err := serverImap.New(
		context.Background(),
		serverName,
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // upload worker
		c,
		serverImap.IMAPServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			MasterUsername:     []byte(masterUser),
			MasterPassword:     []byte(masterPass),
			EnableWarmup:       true,
			WarmupMessageCount: 10,
			WarmupMailboxes:    []string{"INBOX"},
			WarmupAsync:        true,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() {
		srv.Close()
		c.Close()
	})

	return address
}
