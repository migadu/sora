//go:build integration

package managesieve

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// setupManageSieveServerWithMasterSASLRateLimiting creates a ManageSieve server
// that has BOTH master SASL credentials and authentication rate limiting.
func setupManageSieveServerWithMasterSASLRateLimiting(t *testing.T, rateLimitConfig server.AuthRateLimiterConfig, saslUser, saslPass string) (*common.TestServer, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := managesieve.New(
		context.Background(),
		"test-master-sasl-rate-limit",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:             &config.Config{},
			InsecureAuth:       true, // Allow authentication over non-TLS connection for testing
			AuthRateLimit:      rateLimitConfig,
			MasterSASLUsername: saslUser,
			MasterSASLPassword: saslPass,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)

	t.Cleanup(func() { srv.Close() })

	return &common.TestServer{
		Address:     address,
		Server:      srv,
		ResilientDB: rdb,
	}, account
}

// TestManageSieve_MasterSASL_WrongPasswordIsRateLimited is the ManageSieve
// counterpart: a wrong master SASL password must be recorded as an authentication
// failure and blocked like any other bad credential.
//
// Before the fix the master SASL branch was one compound condition (username AND
// password). A correct username with a wrong password fell through to regular
// authentication, where the non-address master SASL username ("proxyuser") is
// rejected with "Invalid username format" BEFORE the progressive delay, before
// the CanAttempt check and before any RecordAuthAttempt* call — so the
// tenant-wide credential was brute-forceable at connection rate.
func TestManageSieve_MasterSASL_WrongPasswordIsRateLimited(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Deliberately NOT an email address (documented master_sasl_username shape).
	const saslUser = "proxyuser"
	const saslPass = "master_sasl_secret_pw"

	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	srv, account := setupManageSieveServerWithMasterSASLRateLimiting(t, server.AuthRateLimiterConfig{
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
	authPlain := func(authzID, authnID, password string) string {
		client, err := NewManageSieveClient(srv.Address)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer client.Close()

		encoded := base64.StdEncoding.EncodeToString([]byte(authzID + "\x00" + authnID + "\x00" + password))
		if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
			t.Fatalf("AUTHENTICATE: %v", err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("AUTHENTICATE read: %v", err)
		}
		return resp
	}

	// Burn the Tier-1 budget for the master credential with wrong passwords.
	for i := 0; i < 3; i++ {
		if resp := authPlain(account.Email, saslUser, fmt.Sprintf("wrong-master-pw-%d", i)); strings.HasPrefix(resp, "OK") {
			t.Fatalf("attempt %d: master SASL auth with a wrong password must fail, got %q", i+1, resp)
		}
	}

	// The impersonation target must NOT be collateral damage.
	if resp := authPlain("", account.Email, account.Password); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("impersonation target was locked out by master SASL failures: %s", resp)
	}

	// The master credential itself must now be blocked — even the CORRECT password
	// must be refused, which is only possible if the failures above were recorded.
	if resp := authPlain(account.Email, saslUser, saslPass); strings.HasPrefix(resp, "OK") {
		t.Fatalf("master SASL auth succeeded after 3 recorded failures: wrong master password is not rate limited (brute-forceable tenant-wide credential), got %q", resp)
	} else {
		t.Logf("✓ master SASL blocked after 3 failures: %s", resp)
	}
}
