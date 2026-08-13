//go:build integration

package imap_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/migadu/sora/integration_tests/common"
	serverPkg "github.com/migadu/sora/server"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// setupIMAPServerWithMasterAndTracking creates an IMAP server with master
// credentials AND a local connection tracker (the delivery path for kicks).
func setupIMAPServerWithMasterAndTracking(t *testing.T) (*common.TestServer, common.TestAccount, *serverPkg.ConnectionTracker) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := serverImap.New(
		context.Background(),
		"test-master-kick",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // upload worker
		nil, // cache
		serverImap.IMAPServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			MasterUsername:     []byte(masterUsername),
			MasterPassword:     []byte(masterPassword),
			MasterSASLUsername: []byte(masterSASLUsername),
			MasterSASLPassword: []byte(masterSASLPassword),
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	tracker := serverPkg.NewConnectionTracker("IMAP", "", "", "test-master-kick-instance", nil, 0, 0, 0, false)
	if tracker == nil {
		t.Fatal("Failed to create connection tracker")
	}
	srv.SetConnTracker(tracker)

	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() {
		tracker.Stop()
		srv.Close()
	})

	return &common.TestServer{
		Server:      srv,
		Address:     address,
		ResilientDB: rdb,
	}, account, tracker
}

// TestIMAP_MasterAuthenticate_SessionIsKickable proves that sessions established
// through the master-impersonation AUTHENTICATE paths are reachable by a kick.
//
// Both master paths in the SASL PLAIN callback registered the connection and
// triggered cache warmup but never called startTerminationPoller — the only delivery
// path for kicks — while the equivalent paths in LOGIN did. Since the IMAP proxy
// authenticates to its backends with exactly this master SASL AUTHENTICATE, every
// proxied backend session was tracked but deaf to kicks.
func TestIMAP_MasterAuthenticate_SessionIsKickable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	variants := map[string]func(account common.TestAccount) sasl.Client{
		// AUTHENTICATE PLAIN with the master SASL credentials and the target user as
		// the authorization identity — exactly what imapproxy sends to a backend.
		"master SASL impersonation": func(account common.TestAccount) sasl.Client {
			return &plainSASLClient{
				identity: account.Email,
				username: masterSASLUsername,
				password: masterSASLPassword,
			}
		},
		// AUTHENTICATE PLAIN with the user@domain@MASTER_USERNAME form.
		"master username suffix": func(account common.TestAccount) sasl.Client {
			return sasl.NewPlainClient("", account.Email+"@"+masterUsername, masterPassword)
		},
	}

	for name, newSASLClient := range variants {
		t.Run(name, func(t *testing.T) {
			srv, account, tracker := setupIMAPServerWithMasterAndTracking(t)
			defer srv.Close()

			accountID, err := srv.ResilientDB.GetAccountIDByEmailWithRetry(context.Background(), account.Email)
			if err != nil {
				t.Fatalf("Failed to get account ID: %v", err)
			}

			c, err := imapclient.DialInsecure(srv.Address, nil)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer c.Close()

			if err := c.Authenticate(newSASLClient(account)); err != nil {
				t.Fatalf("master AUTHENTICATE failed: %v", err)
			}

			// The session must be alive before the kick.
			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Fatalf("SELECT before kick should succeed: %v", err)
			}

			if err := tracker.KickUser(accountID, "IMAP"); err != nil {
				t.Fatalf("KickUser: %v", err)
			}

			// The kick closes the session's channel synchronously; the session's
			// termination poller then closes the socket. Poll for the session to die
			// (generous bound — a liveness assertion, not a timing threshold).
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := c.Select("INBOX", nil).Wait(); err != nil {
					t.Logf("✓ master-authenticated session closed after kick: %v", err)
					return
				}
				if time.Now().After(deadline) {
					t.Fatal("session survived the kick: the master AUTHENTICATE path never started the termination poller, so kicks are never delivered to it")
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
