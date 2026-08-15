//go:build integration

package pop3_test

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
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// pop3RecordingLimiter captures every RecordAuthAttemptWithProxy call. It never blocks, so
// authentication proceeds normally and the test observes accounting alone.
//
// The limiter is the only place this contract is visible. A blocked reply and a failed
// reply are deliberately byte-identical, so nothing on the wire distinguishes "recorded"
// from "not recorded" - which is exactly why the gap existed unnoticed.
type pop3RecordingLimiter struct {
	mu      sync.Mutex
	records []pop3AuthRecord
}

type pop3AuthRecord struct {
	key     string
	success bool
}

func (r *pop3RecordingLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, key string, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, pop3AuthRecord{key: key, success: success})
}

func (r *pop3RecordingLimiter) drain() []pop3AuthRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]pop3AuthRecord(nil), r.records...)
	r.records = nil
	return out
}

func (r *pop3RecordingLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return 0 }
func (r *pop3RecordingLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (r *pop3RecordingLimiter) CanAttemptAuth(context.Context, net.Addr, string) error    { return nil }
func (r *pop3RecordingLimiter) RecordAuthAttempt(context.Context, net.Addr, string, bool) {}
func (r *pop3RecordingLimiter) IsIPBlocked(net.Addr) bool                                 { return false }
func (r *pop3RecordingLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (r *pop3RecordingLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (r *pop3RecordingLimiter) Stop()                                                  {}

// TestPOP3_MasterSASLGate_RefusalIsMetered pins that a refusal at the master SASL network
// gate is recorded exactly like a wrong master password.
//
// The gate is reachable ONLY with the correct master password. If that path records
// nothing while the wrong-password path records, the two diverge at the block threshold:
// an off-network peer holding the correct password probes unmetered forever, while a
// guesser is blocked after N. POP3's master-USERNAME gate already recorded; its master
// SASL gate did not, and that asymmetry within one file is what made it easy to miss.
func TestPOP3_MasterSASLGate_RefusalIsMetered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	limiter := &pop3RecordingLimiter{}

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := pop3.New(
		context.Background(), "test", "localhost", address,
		&storage.S3Storage{}, rdb, nil, nil,
		pop3.POP3ServerOptions{
			InsecureAuth:       true,
			Config:             &config.Config{},
			MasterUsername:     masterUsername,
			MasterPassword:     masterPassword,
			MasterSASLUsername: masterSASLUsername,
			MasterSASLPassword: masterSASLPassword,
			// Loopback is NOT in this range, so every attempt below is off-network.
			MasterSASLAllowedNetworks: []string{"10.0.0.0/8"},
			AuthLimiterOverride:       limiter,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	defer srv.Close()

	// Baseline: what a WRONG master password records. Measured, not assumed, so the
	// assertion tracks the established behaviour rather than a hard-coded expectation.
	if resp := pop3AuthPlain(t, address, account.Email, string(masterSASLUsername), "definitely-not-the-master-password"); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("wrong master password was not refused: %q", resp)
	}
	wrongPasswordRecords := limiter.drain()
	if len(wrongPasswordRecords) == 0 {
		t.Fatal("control: a wrong master password recorded nothing, so this test cannot discriminate")
	}

	// The gate path: CORRECT master password, off-network peer.
	if resp := pop3AuthPlain(t, address, account.Email, string(masterSASLUsername), string(masterSASLPassword)); strings.HasPrefix(resp, "+OK") {
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
