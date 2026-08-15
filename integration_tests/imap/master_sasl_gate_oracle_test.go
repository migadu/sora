//go:build integration

package imap_test

import (
	"context"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestIMAP_MasterSASLGate_IsNotAPasswordOracle closes the last reply in the master-auth
// family that is reachable ONLY with the correct master password.
//
// master_sasl_allowed_networks restricts where the tenant-wide impersonation capability
// may be used from. An off-network peer that guesses the master password therefore cannot
// impersonate anyone - but if the gate's refusal is worded differently from an ordinary
// bad-credential refusal, the attacker learns the guess was right anyway. That is the same
// oracle as answering "Invalid impersonation target", just moved one step later: the reply
// is a function of the password, so it discloses the password.
//
// The wrong-password and correct-password-off-network replies must therefore be byte
// identical. They are compared directly rather than matched against an expected string, so
// the test keeps holding if the bad-credential wording ever changes.
func TestIMAP_MasterSASLGate_IsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Loopback is NOT inside this range, so every attempt below is off-network.
	server, account := setupIMAPServerWithMasterSASLGate(t, []string{"10.99.0.0/16"})

	wrongPassword := imapAuthPlain(t, server.Address, account.Email, masterSASLUsername, "definitely-not-the-master-password")
	if !strings.HasPrefix(wrongPassword, "A001 NO") {
		t.Fatalf("wrong master password was not refused: %q", wrongPassword)
	}

	correctPassword := imapAuthPlain(t, server.Address, account.Email, masterSASLUsername, masterSASLPassword)
	if !strings.HasPrefix(correctPassword, "A001 NO") {
		t.Fatalf("master SASL succeeded from an off-network peer - the gate did not hold: %q", correctPassword)
	}

	if correctPassword != wrongPassword {
		t.Errorf("the network gate's refusal is distinguishable from a bad-credential refusal, so it "+
			"confirms a guessed master password to a peer that is not even allowed to use it:\n"+
			"\twrong password:   %q\n"+
			"\tcorrect password: %q", wrongPassword, correctPassword)
	}
}

// recordingAuthLimiter captures every RecordAuthAttemptWithProxy call. It never blocks,
// so authentication proceeds normally and the test observes accounting alone.
type recordingAuthLimiter struct {
	mu      sync.Mutex
	records []authRecord
}

type authRecord struct {
	key     string
	success bool
}

func (r *recordingAuthLimiter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, key string, success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, authRecord{key: key, success: success})
}

func (r *recordingAuthLimiter) drain() []authRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]authRecord(nil), r.records...)
	r.records = nil
	return out
}

func (r *recordingAuthLimiter) GetAuthenticationDelay(net.Addr) time.Duration { return 0 }
func (r *recordingAuthLimiter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	return nil
}
func (r *recordingAuthLimiter) CanAttemptAuth(context.Context, net.Addr, string) error    { return nil }
func (r *recordingAuthLimiter) RecordAuthAttempt(context.Context, net.Addr, string, bool) {}
func (r *recordingAuthLimiter) IsIPBlocked(net.Addr) bool                                 { return false }
func (r *recordingAuthLimiter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool {
	return false
}
func (r *recordingAuthLimiter) GetStats(context.Context, time.Duration) map[string]any { return nil }
func (r *recordingAuthLimiter) Stop()                                                  {}

// TestIMAP_MasterSASLGate_RefusalIsMetered pins that a refusal at the network gate is
// recorded as a failed attempt under the same key as a wrong master password.
//
// Accounting is the second half of "indistinguishable". The replies are byte-identical
// after the fix above, but if the gate path records nothing while the wrong-password path
// records, the two diverge at the block threshold: an off-network peer holding the correct
// master password could probe forever, while a wrong-password guesser is blocked after N.
//
// This is asserted on the limiter rather than through a blocked connection, deliberately.
// The obvious end-to-end canary - "the source IP stops being able to log in" - was tried
// first and turned out not to discriminate: with this harness even the wrong-password path,
// which has always recorded, leaves an ordinary login working, so the canary would have
// passed whether or not the gate recorded anything. The DI seam observes the actual
// contract instead of a downstream effect that may or may not be wired.
func TestIMAP_MasterSASLGate_RefusalIsMetered(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	limiter := &recordingAuthLimiter{}
	srv, account := setupIMAPServerWithMasterSASLGateAndLimiter(t, []string{"10.99.0.0/16"}, limiter)

	// Baseline: what a WRONG master password records. This is the established behaviour
	// the gate path has to match, so it is measured rather than assumed.
	if resp := imapAuthPlain(t, srv.Address, account.Email, masterSASLUsername, "definitely-not-the-master-password"); !strings.HasPrefix(resp, "A001 NO") {
		t.Fatalf("wrong master password was not refused: %q", resp)
	}
	wrongPasswordRecords := limiter.drain()
	if len(wrongPasswordRecords) == 0 {
		t.Fatal("control: a wrong master password recorded nothing, so this test cannot discriminate")
	}

	// The gate path, with the CORRECT master password from an off-network peer.
	if resp := imapAuthPlain(t, srv.Address, account.Email, masterSASLUsername, masterSASLPassword); !strings.HasPrefix(resp, "A001 NO") {
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
		// The key must be the master credential's, never the impersonation target's:
		// charging it to the named account lets anyone who can reach the port lock that
		// account out, and hands each guess a fresh bucket by varying the target.
		//
		// Note this is NOT a check for the "master:" namespace. That prefix exists for the
		// user@domain@MASTERUSER suffix form, whose canonical key would otherwise resolve
		// to the target. A master SASL username is a bare non-address token, so it is
		// already a bucket of its own and is used verbatim.
		if rec.key == account.Email {
			t.Errorf("gate refusal recorded under the impersonation target %q rather than the "+
				"master credential - that account can be locked out by anyone naming it", rec.key)
		}
	}
}
