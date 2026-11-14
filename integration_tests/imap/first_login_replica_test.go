//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// replicaLagOnFirstLogin is what a replica has not replayed when an account logs in
// for the first time: everything the login writes when it creates the default
// mailboxes.
var replicaLagOnFirstLogin = []string{"mailboxes", "subscriptions", "mailbox_stats"}

// TestIMAP_FirstLoginReadsTheDefaultMailboxesFromTheWriter is issues #600 and #602.
// Account creation makes no mailboxes; the account's first login creates them, on
// the writer. The same session must then find them, whatever the read pool says: a
// replica that has not replayed the create yet has no INBOX, so a SELECT INBOX read
// from it answered NO [NONEXISTENT] and LIST returned nothing until it caught up.
//
// Every login path is covered: LOGIN and AUTHENTICATE PLAIN (login.go), the master
// username form over LOGIN (login.go) and AUTHENTICATE PLAIN (sasl.go), and master
// SASL with an authorization identity (sasl.go).
func TestIMAP_FirstLoginReadsTheDefaultMailboxesFromTheWriter(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	const (
		masterUser = "replica-master"
		masterPass = "replica-master-pw"
		saslUser   = "replica-sasl"
		saslPass   = "replica-sasl-pw"
	)
	address := startIMAPWithMasterLogins(t, rdb, masterUser, masterPass, saslUser, saslPass)

	logins := []struct {
		name  string
		login func(c *imapclient.Client, email, password string) error
	}{
		{"LOGIN", func(c *imapclient.Client, email, password string) error {
			return c.Login(email, password).Wait()
		}},
		{"AUTHENTICATE_PLAIN", func(c *imapclient.Client, email, password string) error {
			return c.Authenticate(sasl.NewPlainClient("", email, password))
		}},
		{"master_username_LOGIN", func(c *imapclient.Client, email, _ string) error {
			return c.Login(email+"@"+masterUser, masterPass).Wait()
		}},
		{"master_username_AUTHENTICATE_PLAIN", func(c *imapclient.Client, email, _ string) error {
			return c.Authenticate(sasl.NewPlainClient("", email+"@"+masterUser, masterPass))
		}},
		{"master_SASL_AUTHENTICATE_PLAIN", func(c *imapclient.Client, email, _ string) error {
			return c.Authenticate(sasl.NewPlainClient(email, saslUser, saslPass))
		}},
	}

	for _, l := range logins {
		t.Run(l.name, func(t *testing.T) {
			email, password := createAccountWithoutMailboxes(t, rdb)
			defer installLaggingReplica(t, &common.TestServer{ResilientDB: rdb}, replicaLagOnFirstLogin, nil, false)()

			c, err := imapclient.DialInsecure(address, nil)
			if err != nil {
				t.Fatalf("Failed to dial IMAP server: %v", err)
			}
			defer c.Logout()

			if err := l.login(c, email, password); err != nil {
				t.Fatalf("login failed: %v", err)
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("SELECT INBOX in the account's first session: %v", err)
			}
			if _, err := c.Status("Sent", &imap.StatusOptions{NumMessages: true}).Wait(); err != nil {
				t.Errorf("STATUS Sent in the account's first session: %v", err)
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
					t.Errorf("default mailbox %q missing from LIST in the account's first session (LIST returned %d mailboxes)", name, len(listed))
				}
			}
		})
	}

	// Only the login that had to create the mailboxes moves the session to the
	// writer. An account whose INBOX the replica already has (every login but the
	// first) keeps reading from the replica, so a mailbox the replica has not
	// replayed yet is not listed.
	t.Run("existing_account_keeps_reading_the_replica", func(t *testing.T) {
		email, password := createAccountWithoutMailboxes(t, rdb)
		ctx := context.Background()
		accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
		if err != nil {
			t.Fatalf("account lookup: %v", err)
		}
		if err := rdb.CreateDefaultMailboxesWithRetry(ctx, accountID); err != nil {
			t.Fatalf("create the default mailboxes: %v", err)
		}
		defer installLaggingReplica(t, &common.TestServer{ResilientDB: rdb}, nil, []string{"mailboxes"}, false)()
		if err := rdb.CreateMailboxWithRetry(ctx, accountID, "NotReplayed", nil); err != nil {
			t.Fatalf("create a mailbox on the writer: %v", err)
		}

		c, err := imapclient.DialInsecure(address, nil)
		if err != nil {
			t.Fatalf("Failed to dial IMAP server: %v", err)
		}
		defer c.Logout()
		if err := c.Login(email, password).Wait(); err != nil {
			t.Fatalf("login failed: %v", err)
		}

		listed, err := c.List("", "*", nil).Collect()
		if err != nil {
			t.Fatalf("LIST failed: %v", err)
		}
		if len(listed) != len(consts.DefaultMailboxes) {
			t.Errorf("LIST returned %d mailboxes, want the %d the replica has: a login that created nothing must not move the session to the writer",
				len(listed), len(consts.DefaultMailboxes))
		}
	})
}

// startIMAPWithMasterLogins starts an IMAP backend that accepts the master username
// form and master SASL.
func startIMAPWithMasterLogins(t *testing.T, rdb *resilient.ResilientDatabase, masterUser, masterPass, saslUser, saslPass string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := serverImap.New(
		context.Background(),
		fmt.Sprintf("test-first-login-replica-%d", time.Now().UnixNano()),
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // upload worker
		nil, // cache
		serverImap.IMAPServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			MasterUsername:     []byte(masterUser),
			MasterPassword:     []byte(masterPass),
			MasterSASLUsername: []byte(saslUser),
			MasterSASLPassword: []byte(saslPass),
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
	t.Cleanup(func() { srv.Close() })

	return address
}
