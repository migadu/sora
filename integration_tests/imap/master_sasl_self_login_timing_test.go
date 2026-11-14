//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
)

// passwordVerification raises the bcrypt cost for the rest of the test (the
// integration harness runs at the minimum, where a verification is no slower than
// a database round trip) and returns the time one password verification takes. Load
// only ever adds time, so the fastest of a few runs is the floor.
func passwordVerification(t *testing.T) time.Duration {
	saved := db.BcryptCost
	db.BcryptCost = 10
	t.Cleanup(func() { db.BcryptCost = saved })

	db.DummyVerifyPassword("warm-up") // generates the dummy hash at this cost
	floor := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		db.DummyVerifyPassword("wrong-password")
		if took := time.Since(start); took < floor {
			floor = took
		}
	}
	return floor
}

// TestIMAP_MasterSASLSelfLoginTimingIsNotAPasswordOracle (#760): a master SASL
// self-login (authorization identity = authentication identity = the master SASL
// username) with an address-shaped master SASL username that names no account costs
// one password verification whatever the password, with or without
// master_sasl_allowed_networks. Any other password is answered by regular
// authentication, which verifies a dummy hash for an address it does not know; the
// master SASL password used to be answered from the master SASL block without one
// (the target lookup found nothing, or the gate refused the peer), so the response
// time confirmed a guessed master SASL password. The lookup cache is off, as in the
// report: with it on, only the first wrong attempt per negative TTL verifies.
func TestIMAP_MasterSASLSelfLoginTimingIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	verification := passwordVerification(t)
	saslUser := fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())
	const saslPass = "master-sasl-secret"

	for _, gate := range []struct {
		name     string
		networks []string
	}{
		{"no_allowed_networks", nil},
		{"peer_outside_allowed_networks", []string{"192.0.2.0/24"}},
	} {
		t.Run(gate.name, func(t *testing.T) {
			address := common.GetRandomAddress(t)
			srv, err := serverImap.New(context.Background(), "test-master-sasl-self-login-timing", "localhost", address,
				&storage.S3Storage{}, rdb, nil, nil,
				serverImap.IMAPServerOptions{
					InsecureAuth:              true,
					MasterSASLUsername:        []byte(saslUser),
					MasterSASLPassword:        []byte(saslPass),
					MasterSASLAllowedNetworks: gate.networks,
					LookupCache:               &config.LookupCacheConfig{Enabled: false},
				})
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

			timed := func(password string) (string, time.Duration) {
				start := time.Now()
				reply := imapAuthPlain(t, address, saslUser, saslUser, password)
				return reply, time.Since(start)
			}
			wrongReply, wrongTook := timed("wrong-password")
			masterReply, masterTook := timed(saslPass)

			if masterReply != wrongReply {
				t.Fatalf("self-login answered differently by password:\n  wrong password:  %q\n  master password: %q", wrongReply, masterReply)
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
