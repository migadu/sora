//go:build integration

package managesieve

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// msRecordingLimiter captures every RecordAuthAttemptWithProxy call. It never blocks, so
// authentication proceeds normally and the test observes accounting alone - which is the
// only place this contract is visible, since a blocked reply and a failed reply are
// deliberately byte-identical on the wire.
type msRecordingLimiter struct {
	mu      sync.Mutex
	records []msAuthRecord
}

type msAuthRecord struct {
	key     string
	success bool
}

func (r *msRecordingLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, key string, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, msAuthRecord{key: key, success: success})
}

func (r *msRecordingLimiter) drain() []msAuthRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]msAuthRecord(nil), r.records...)
	r.records = nil
	return out
}

func (r *msRecordingLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return 0 }
func (r *msRecordingLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (r *msRecordingLimiter) CanAttemptAuth(context.Context, net.Addr, string) error    { return nil }
func (r *msRecordingLimiter) RecordAuthAttempt(context.Context, net.Addr, string, bool) {}
func (r *msRecordingLimiter) IsIPBlocked(net.Addr) bool                                 { return false }
func (r *msRecordingLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (r *msRecordingLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (r *msRecordingLimiter) Stop()                                                  {}

// startManageSieveGateWithLimiter brings up a backend whose master SASL gate excludes the
// loopback test client, with an injected limiter so the test can see what is recorded.
func startManageSieveGateWithLimiter(t *testing.T, limiter server.AuthLimiter, saslUser, saslPass string) (string, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := managesieve.New(
		context.Background(),
		"test-mastersasl-gate-accounting",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:                    &config.Config{},
			MasterSASLUsername:        saslUser,
			MasterSASLPassword:        saslPass,
			MasterSASLAllowedNetworks: []string{"10.0.0.0/8"}, // excludes 127.0.0.1
			InsecureAuth:              true,
			AuthLimiterOverride:       limiter,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { srv.Close() })

	return address, account
}

// TestManageSieve_MasterSASLGate_RefusalIsMetered pins that a refusal at the master SASL
// network gate is recorded exactly like a wrong master password.
//
// The gate is reachable ONLY with the correct master password, so a failure it does not
// charge for diverges from a wrong password at the block threshold: an off-network peer
// holding the correct password probes unmetered forever while a guesser is blocked after N.
// ManageSieve recorded at neither of its two gate sites.
func TestManageSieve_MasterSASLGate_RefusalIsMetered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const saslUser = "sasl_gate_admin"
	const saslPass = "master_sasl_secret_pw"

	limiter := &msRecordingLimiter{}
	address, account := startManageSieveGateWithLimiter(t, limiter, saslUser, saslPass)

	// Baseline: what a WRONG master password records. Measured rather than assumed.
	if resp := msAuthPlain(t, address, account.Email, saslUser, "definitely-not-the-master-password"); strings.HasPrefix(resp, "OK") {
		t.Fatalf("wrong master password was not refused: %q", resp)
	}
	wrongPasswordRecords := limiter.drain()
	if len(wrongPasswordRecords) == 0 {
		t.Fatal("control: a wrong master password recorded nothing, so this test cannot discriminate")
	}

	// The gate path: CORRECT master password, off-network peer.
	if resp := msAuthPlain(t, address, account.Email, saslUser, saslPass); strings.HasPrefix(resp, "OK") {
		t.Fatalf("master SASL succeeded from an off-network peer - the gate did not hold: %q", resp)
	}
	gateRecords := limiter.drain()

	if len(gateRecords) == 0 {
		t.Fatalf("a refusal at the network gate recorded nothing, while a wrong password recorded %v - "+
			"the two diverge at the block threshold, so an off-network holder of the correct master "+
			"password can probe unmetered", wrongPasswordRecords)
	}
	if !reflect.DeepEqual(gateRecords, wrongPasswordRecords) {
		t.Errorf("gate refusal is accounted differently from a wrong password:\n\twrong password: %v\n\tgate refusal:   %v",
			wrongPasswordRecords, gateRecords)
	}
	for _, rec := range gateRecords {
		if rec.success {
			t.Errorf("gate refusal recorded a SUCCESS (%v) - that clears the credential's counter and the IP block", rec)
		}
		if rec.key == account.Email {
			t.Errorf("gate refusal recorded under the impersonation target %q rather than the master "+
				"credential - that account can be locked out by anyone naming it", rec.key)
		}
	}
}

// TestManageSieve_MasterSASLGate_LoginVerbIsMeteredToo covers the fifth and last gate site:
// the one inside the LOGIN verb, which is a different function from AuthenticatePlain and
// derives its own key and its own replies.
//
// This site has a precondition the AUTHENTICATE one does not: Login parses the submitted
// username with server.NewAddress before any master handling, so a bare token like
// "sasl_admin" is rejected as an invalid address and never reaches the master block. The
// site is therefore only live when master_sasl_username is itself address-shaped, which is
// a supported configuration (an operator's own mailbox) - and exactly the configuration in
// which an unmetered, distinguishable refusal matters, because the same string is also a
// real account name.
func TestManageSieve_MasterSASLGate_LoginVerbIsMeteredToo(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Address-shaped, so NewAddress accepts it and the master block is reachable.
	const saslUser = "saslmaster@example.com"
	const saslPass = "master_sasl_secret_pw"

	limiter := &msRecordingLimiter{}
	address, _ := startManageSieveGateWithLimiter(t, limiter, saslUser, saslPass)

	// Baseline: a wrong master password on the same verb.
	wrongPassword := msLogin(t, address, saslUser, "definitely-not-the-master-password")
	if strings.HasPrefix(wrongPassword, "OK") {
		t.Fatalf("wrong master password was not refused: %q", wrongPassword)
	}
	wrongPasswordRecords := limiter.drain()

	// The gate path: correct master password, off-network peer.
	correctPassword := msLogin(t, address, saslUser, saslPass)
	if strings.HasPrefix(correctPassword, "OK") {
		t.Fatalf("master SASL succeeded from an off-network peer - the gate did not hold: %q", correctPassword)
	}
	gateRecords := limiter.drain()

	if correctPassword != wrongPassword {
		t.Errorf("the LOGIN verb's gate refusal is distinguishable from a bad-credential refusal, so it "+
			"confirms a guessed master password to a peer that is not even allowed to use it:\n"+
			"\twrong password:   %q\n\tcorrect password: %q", wrongPassword, correctPassword)
	}
	if len(wrongPasswordRecords) > 0 && len(gateRecords) == 0 {
		t.Errorf("the LOGIN verb's gate refusal recorded nothing, while a wrong password recorded %v - "+
			"the two diverge at the block threshold, so an off-network holder of the correct master "+
			"password can probe unmetered", wrongPasswordRecords)
	}
	if !reflect.DeepEqual(gateRecords, wrongPasswordRecords) {
		t.Errorf("gate refusal is accounted differently from a wrong password:\n\twrong password: %v\n\tgate refusal:   %v",
			wrongPasswordRecords, gateRecords)
	}
}
