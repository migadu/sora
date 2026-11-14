//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/testutils"
)

// TestPOP3_MasterSASLSelfLoginTimingIsNotAPasswordOracle (#760): a master SASL
// self-login (authorization identity = authentication identity = the master SASL
// username) with an address-shaped master SASL username that names no account costs
// one password verification whatever the password, with or without
// master_sasl_allowed_networks. Any other password is answered by regular
// authentication, which verifies a dummy hash for an address it does not know; the
// master SASL password used to be answered from the master SASL block without one
// (the target lookup found nothing, or the gate refused the peer), so the response
// time confirmed a guessed master SASL password. Both cache modes are covered:
// backend negative entries revalidate on every attempt. The
// session is driven directly: over the wire every failed command is held back by
// the POP3 error delay, which would hide the difference. The verifications are
// counted, not timed (#782): a wall-clock floor calibrated under CPU contention fails
// a correct login that runs after the contention eases.
func TestPOP3_MasterSASLSelfLoginTimingIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	saslUser := fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())
	const saslPass = "master-sasl-secret"

	for _, gate := range []struct {
		name         string
		networks     []string
		cacheEnabled bool
	}{
		{"no_allowed_networks", nil, false},
		// The session runs on a net.Pipe, whose peer is in no network.
		{"peer_outside_allowed_networks", []string{"192.0.2.0/24"}, false},
		{"cached_no_allowed_networks", nil, true},
		{"cached_peer_outside_allowed_networks", []string{"192.0.2.0/24"}, true},
	} {
		t.Run(gate.name, func(t *testing.T) {
			srv, err := pop3.New(context.Background(), "test-master-sasl-self-login-timing", "localhost", common.GetRandomAddress(t),
				&storage.S3Storage{}, rdb, nil, nil,
				pop3.POP3ServerOptions{
					InsecureAuth:              true,
					Config:                    &config.Config{},
					MasterSASLUsername:        saslUser,
					MasterSASLPassword:        saslPass,
					MasterSASLAllowedNetworks: gate.networks,
					LookupCache:               &config.LookupCacheConfig{Enabled: gate.cacheEnabled},
				})
			if err != nil {
				t.Fatalf("Failed to create POP3 server: %v", err)
			}
			t.Cleanup(srv.Close)

			counted := func(password string) (string, int) {
				c1, c2 := net.Pipe()
				defer c1.Close()
				defer c2.Close()
				session := pop3.NewSessionForTest(srv, c1)
				before := testutils.PasswordVerifications()
				err := session.AuthenticatePlain(context.Background(), saslUser, saslUser, password)
				return fmt.Sprintf("%#v", err), testutils.PasswordVerifications() - before
			}
			wrongReply, wrongVerified := counted("wrong-password")
			masterReply, masterVerified := counted(saslPass)

			if masterReply != wrongReply {
				t.Fatalf("self-login answered differently by password:\n  wrong password:  %s\n  master password: %s", wrongReply, masterReply)
			}
			if wrongVerified != 1 {
				t.Fatalf("wrong password answered after %d password verifications, want 1", wrongVerified)
			}
			if masterVerified != wrongVerified {
				t.Errorf("master SASL password answered after %d password verifications, wrong password after %d: the response time confirms the master SASL password", masterVerified, wrongVerified)
			}
		})
	}
}
