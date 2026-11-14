//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// TestPOP3_MasterSASLSelfLoginTimingIsNotAPasswordOracle (#760): a master SASL
// self-login (authorization identity = authentication identity = the master SASL
// username) with an address-shaped master SASL username that names no account costs
// one password verification whatever the password, with or without
// master_sasl_allowed_networks. Any other password is answered by regular
// authentication, which verifies a dummy hash for an address it does not know; the
// master SASL password used to be answered from the master SASL block without one
// (the target lookup found nothing, or the gate refused the peer), so the response
// time confirmed a guessed master SASL password. The lookup cache is off, as in the
// report: with it on, only the first wrong attempt per negative TTL verifies. The
// session is driven directly: over the wire every failed command is held back by
// the POP3 error delay, which would hide the difference.
func TestPOP3_MasterSASLSelfLoginTimingIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	// The integration harness runs bcrypt at the minimum cost, where a verification is
	// no slower than a database round trip.
	saved := db.BcryptCost
	db.BcryptCost = 10
	t.Cleanup(func() { db.BcryptCost = saved })
	// One password verification. Load only ever adds time, so the fastest of a few runs
	// is the floor.
	db.DummyVerifyPassword("warm-up") // generates the dummy hash at this cost
	verification := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		db.DummyVerifyPassword("wrong-password")
		if took := time.Since(start); took < verification {
			verification = took
		}
	}

	saslUser := fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())
	const saslPass = "master-sasl-secret"

	for _, gate := range []struct {
		name     string
		networks []string
	}{
		{"no_allowed_networks", nil},
		// The session runs on a net.Pipe, whose peer is in no network.
		{"peer_outside_allowed_networks", []string{"192.0.2.0/24"}},
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
					LookupCache:               &config.LookupCacheConfig{Enabled: false},
				})
			if err != nil {
				t.Fatalf("Failed to create POP3 server: %v", err)
			}
			t.Cleanup(srv.Close)

			timed := func(password string) (string, time.Duration) {
				c1, c2 := net.Pipe()
				defer c1.Close()
				defer c2.Close()
				session := pop3.NewSessionForTest(srv, c1)
				start := time.Now()
				err := session.AuthenticatePlain(context.Background(), saslUser, saslUser, password)
				return fmt.Sprintf("%#v", err), time.Since(start)
			}
			wrongReply, wrongTook := timed("wrong-password")
			masterReply, masterTook := timed(saslPass)

			if masterReply != wrongReply {
				t.Fatalf("self-login answered differently by password:\n  wrong password:  %s\n  master password: %s", wrongReply, masterReply)
			}
			if wrongTook < verification/2 {
				t.Fatalf("wrong password answered in %v, under half a password verification (%v)", wrongTook, verification)
			}
			if masterTook < verification/2 {
				t.Errorf("master SASL password answered in %v, wrong password in %v (one password verification: %v): the response time confirms the master SASL password", masterTook, wrongTook, verification)
			}
		})
	}
}
