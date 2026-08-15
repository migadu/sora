//go:build integration

package pop3_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// startPOP3WithMasterSASL starts a POP3 backend with the given master SASL
// credentials against an ALREADY created account, so a test can make the master
// SASL username collide with a real account address.
func startPOP3WithMasterSASL(t *testing.T, rdb *resilient.ResilientDatabase, rateLimit server.AuthRateLimiterConfig, saslUser, saslPass string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := pop3.New(
		context.Background(),
		"test-master-sasl-no-authzid",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploadWorker
		nil, // cache
		pop3.POP3ServerOptions{
			InsecureAuth:       true, // Allow PLAIN auth (no TLS in tests)
			Config:             &config.Config{},
			AuthRateLimit:      rateLimit,
			MasterSASLUsername: saslUser,
			MasterSASLPassword: saslPass,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { srv.Close() })

	return address
}

// pop3AuthPlainErr performs one AUTH PLAIN exchange on a fresh connection and
// returns the verbatim response line. Safe to call from a goroutine.
func pop3AuthPlainErr(address, authzID, authnID, password string) (string, error) {
	client, err := NewPOP3Client(address)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	// Drop the socket instead of QUITting: a failed authentication parks the
	// session in Pop3ErrorDelay (3s) before it reads another command, and most
	// probes here are failures by design.
	defer client.conn.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(authzID + "\x00" + authnID + "\x00" + password))
	if err := client.SendCommand("AUTH PLAIN " + encoded); err != nil {
		return "", fmt.Errorf("AUTH PLAIN: %w", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		return "", fmt.Errorf("AUTH PLAIN read: %w", err)
	}
	return resp, nil
}

// pop3UserPassErr performs one USER/PASS exchange on a fresh connection and
// returns the verbatim response line to PASS. USER/PASS carries no authorization
// identity at all, which is exactly the shape that must never be answered by the
// master SASL branch. Safe to call from a goroutine.
func pop3UserPassErr(address, username, password string) (string, error) {
	client, err := NewPOP3Client(address)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer client.conn.Close()

	if err := client.SendCommand("USER " + username); err != nil {
		return "", fmt.Errorf("USER: %w", err)
	}
	if _, err := client.ReadResponse(); err != nil {
		return "", fmt.Errorf("USER read: %w", err)
	}
	if err := client.SendCommand("PASS " + password); err != nil {
		return "", fmt.Errorf("PASS: %w", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		return "", fmt.Errorf("PASS read: %w", err)
	}
	return resp, nil
}

func pop3AuthPlain(t *testing.T, address, authzID, authnID, password string) string {
	t.Helper()

	resp, err := pop3AuthPlainErr(address, authzID, authnID, password)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return resp
}

func pop3UserPass(t *testing.T, address, username, password string) string {
	t.Helper()

	resp, err := pop3UserPassErr(address, username, password)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return resp
}

// TestPOP3_MasterSASL_NoAuthzIDIsNotAPasswordOracle proves that with an EMPTY
// authorization identity the server's answer does not depend on whether the
// master SASL password was correct.
//
// The master credential impersonates any tenant. A reply that is only reachable
// with the correct master password ("Master SASL login requires an authorization
// identity.") let anyone who can reach the port confirm a guessed master
// password without ever completing an authentication.
//
// The two probe sequences run against two servers with IDENTICAL configuration
// so the comparison also covers the rate-limiter state: if only one of the two
// cases were recorded as a failure, the sequences would diverge at the block
// threshold even when every individual message matched.
func TestPOP3_MasterSASL_NoAuthzIDIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)

	const saslPass = "master_sasl_secret_pw"
	// Tier 1 only; Tier 2 and progressive delays disabled so the comparison is on
	// the responses and on blocking, never on timing.
	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}

	shapes := []struct {
		name     string
		saslUser string
	}{
		// Documented master_sasl_username shape: not an email address.
		{"non_address_master_username", fmt.Sprintf("proxyuser-%d", time.Now().UnixNano())},
		// Address-shaped master username (no such account exists).
		{"address_shaped_master_username", fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())},
	}

	// Enough attempts to cross the Tier-1 threshold (3).
	const attempts = 4

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// Sequences are collected concurrently: every failed POP3 command is
			// tarpitted for Pop3ErrorDelay (3s) before the reply.
			t.Parallel()

			for _, method := range []struct {
				name  string
				probe func(address, password string) (string, error)
			}{
				{"AUTH PLAIN", func(address, password string) (string, error) {
					return pop3AuthPlainErr(address, "", shape.saslUser, password)
				}},
				// USER/PASS carries no authorization identity at all.
				{"USER/PASS", func(address, password string) (string, error) {
					return pop3UserPassErr(address, shape.saslUser, password)
				}},
			} {
				// One server per password, so each probe sequence gets its own
				// rate-limiter state.
				correctAddr := startPOP3WithMasterSASL(t, rdb, rateLimit, shape.saslUser, saslPass)
				wrongAddr := startPOP3WithMasterSASL(t, rdb, rateLimit, shape.saslUser, saslPass)

				var withMaster, withWrong [attempts]string
				var probeErr [2]error
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					for i := 0; i < attempts && probeErr[0] == nil; i++ {
						withMaster[i], probeErr[0] = method.probe(correctAddr, saslPass)
					}
				}()
				go func() {
					defer wg.Done()
					for i := 0; i < attempts && probeErr[1] == nil; i++ {
						withWrong[i], probeErr[1] = method.probe(wrongAddr, fmt.Sprintf("wrong-master-pw-%d", i))
					}
				}()
				wg.Wait()

				for _, err := range probeErr {
					if err != nil {
						t.Fatalf("%s probe: %v", method.name, err)
					}
				}

				for i := 0; i < attempts; i++ {
					if strings.HasPrefix(withMaster[i], "+OK") {
						t.Fatalf("%s attempt %d: master SASL password with an empty authorization identity must not authenticate, got %q", method.name, i+1, withMaster[i])
					}
					if withMaster[i] != withWrong[i] {
						t.Fatalf("%s attempt %d: response is a master-password oracle\n  correct master password: %q\n  wrong master password:   %q", method.name, i+1, withMaster[i], withWrong[i])
					}
				}
			}
		})
	}
}

// TestPOP3_MasterSASL_NoAuthzIDCorrectPasswordIsRecorded proves that presenting
// the master SASL password without an authorization identity is recorded as an
// authentication failure and therefore consumes the master credential's
// rate-limit budget, exactly like a wrong password does.
func TestPOP3_MasterSASL_NoAuthzIDCorrectPasswordIsRecorded(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Documented master_sasl_username shape: not an email address, so the regular
	// path cannot record anything for it on its own.
	saslUser := fmt.Sprintf("proxyuser-%d", time.Now().UnixNano())
	const saslPass = "master_sasl_secret_pw"

	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}

	// Control: on an untouched server the master credential WITH an authorization
	// identity authenticates, so the assertion below cannot pass merely because
	// master SASL is broken.
	control := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
	if resp := pop3AuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("control: master SASL impersonation must work, got %q", resp)
	}

	probed := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

	// Burn the Tier-1 budget with the CORRECT master password and no authzid.
	for i := 0; i < 3; i++ {
		if resp := pop3AuthPlain(t, probed, "", saslUser, saslPass); strings.HasPrefix(resp, "+OK") {
			t.Fatalf("attempt %d: master password without an authorization identity must not authenticate, got %q", i+1, resp)
		}
	}

	// The master credential must now be blocked: only possible if the probes above
	// were recorded as authentication failures under the master credential's key.
	if resp := pop3AuthPlain(t, probed, account.Email, saslUser, saslPass); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("master SASL still usable after 3 no-authzid probes with the correct master password: the probes are not recorded/rate limited, got %q", resp)
	} else {
		t.Logf("✓ master SASL blocked after 3 no-authzid probes: %s", resp)
	}
}

// TestPOP3_MasterSASLUsernameIsARealAccount covers the deployment where
// master_sasl_username is also a real account's address (e.g. an operator's own
// mailbox). That account must keep working with its OWN password, over USER/PASS
// and over SASL PLAIN, and the proxy's impersonation of it must keep working too.
func TestPOP3_MasterSASLUsernameIsARealAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// The master SASL username IS this account's address.
	saslUser := account.Email
	const saslPass = "master_sasl_secret_pw"

	address := startPOP3WithMasterSASL(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, saslUser, saslPass)

	// USER/PASS with the account's own password.
	if resp := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("account whose address is master_sasl_username cannot log in with its own password over USER/PASS: %q", resp)
	}

	// SASL PLAIN with an empty authorization identity and the account's own password.
	if resp := pop3AuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("account whose address is master_sasl_username cannot log in with its own password over AUTH PLAIN: %q", resp)
	}

	// SASL PLAIN with authzid == authcid and the account's OWN password. RFC 4616 says an
	// authorization identity equal to the authentication identity means "no impersonation",
	// and several SASL client libraries fill the field in unconditionally, so this is an
	// ordinary login that happens to name itself. Answering it from the master-SASL branch -
	// where the password does not match the master password - locks this account out of its
	// own mailbox permanently.
	if resp := pop3AuthPlain(t, address, account.Email, account.Email, account.Password); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("account whose address is master_sasl_username cannot log in with its own password when "+
			"the client sends authzid == authcid (RFC 4616 'no impersonation'): %q", resp)
	}

	// The proxy flow must survive: pop3proxy sends authzid=<user>, authcid=<master
	// SASL username>, which for this account are the same string.
	if resp := pop3AuthPlain(t, address, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("master SASL impersonation of the account sharing the master username must still work: %q", resp)
	}

	// The master password alone still grants nothing without an authorization identity.
	if resp := pop3AuthPlain(t, address, "", saslUser, saslPass); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("master password with no authorization identity must not authenticate, got %q", resp)
	}
}
