//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// setupIMAPServerWithMasterSASLRateLimiting creates an IMAP server that has BOTH
// master SASL credentials and authentication rate limiting configured.
func setupIMAPServerWithMasterSASLRateLimiting(t *testing.T, rateLimitConfig server.AuthRateLimiterConfig, saslUser, saslPass string) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := serverImap.New(
		context.Background(),
		"test-master-sasl-rate-limit",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // upload worker
		nil, // cache
		serverImap.IMAPServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			AuthRateLimit:      rateLimitConfig,
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

	return &common.TestServer{
		Server:      srv,
		Address:     address,
		ResilientDB: rdb,
	}, account
}

// TestIMAP_MasterSASL_WrongPasswordIsRateLimited proves that a wrong master SASL
// password is recorded as an authentication failure and is therefore subject to
// the same blocking as any other failed login.
//
// The master SASL credential is a tenant-wide impersonation capability. Before the
// fix, the master SASL block was one compound condition requiring BOTH a matching
// username AND a matching password: a correct username with a wrong password fell
// through to the regular path, which returned AUTHORIZATIONFAILED without ever
// calling RecordAuthAttempt*. Nothing was recorded, nothing was blocked, and the
// credential was brute-forceable at connection rate.
func TestIMAP_MasterSASL_WrongPasswordIsRateLimited(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Deliberately NOT an email address, matching the documented
	// master_sasl_username = "proxyuser" shape: the canonicalisation path fails
	// for it, so it must still get a stable rate-limiting key of its own.
	const saslUser = "proxyuser"
	const saslPass = "master_sasl_secret_pw"

	// Tier 1 only (IP+username), Tier 2 and progressive delays disabled so the
	// assertion is on blocking alone and never on timing.
	srv, account := setupIMAPServerWithMasterSASLRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}, saslUser, saslPass)
	defer srv.Close()

	// AUTHENTICATE PLAIN as the master SASL user, impersonating the test account.
	authAsMaster := func(password string) error {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer c.Close()
		return c.Authenticate(&plainSASLClient{
			identity: account.Email,
			username: saslUser,
			password: password,
		})
	}

	// Burn the Tier-1 budget for the master credential with wrong passwords.
	for i := 0; i < 3; i++ {
		if err := authAsMaster(fmt.Sprintf("wrong-master-pw-%d", i)); err == nil {
			t.Fatalf("attempt %d: master SASL auth with a wrong password must fail", i+1)
		}
	}

	// The impersonation target must NOT be collateral damage: the failures belong
	// to the master credential, not to the victim's address.
	cVictim, err := imapclient.DialInsecure(srv.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := cVictim.Login(account.Email, account.Password).Wait(); err != nil {
		cVictim.Close()
		t.Fatalf("impersonation target was locked out by master SASL failures: %v", err)
	}
	cVictim.Logout()

	// Now the master credential itself must be blocked — even the CORRECT password
	// must be refused, which is only possible if the failures above were recorded.
	if err := authAsMaster(saslPass); err == nil {
		t.Fatal("master SASL auth succeeded after 3 recorded failures: wrong master password is not rate limited (brute-forceable tenant-wide credential)")
	} else {
		t.Logf("✓ master SASL blocked after 3 failures: %v", err)
	}
}
