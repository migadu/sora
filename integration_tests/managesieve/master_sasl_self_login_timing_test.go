//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// gateCounter counts the progressive-delay lookups, the rate-limit checks and the
// recorded failures of the logins it limits, and never delays or blocks.
type gateCounter struct {
	delays, checks, failures atomic.Int32
}

func (g *gateCounter) GetAuthenticationDelay(net.Addr) time.Duration {
	g.delays.Add(1)
	return 0
}
func (g *gateCounter) CanAttemptAuthWithProxy(context.Context, net.Conn, *server.ProxyProtocolInfo, string) error {
	g.checks.Add(1)
	return nil
}
func (g *gateCounter) RecordAuthAttemptWithProxy(_ context.Context, _ net.Conn, _ *server.ProxyProtocolInfo, _ string, success bool) {
	if !success {
		g.failures.Add(1)
	}
}
func (g *gateCounter) CanAttemptAuth(context.Context, net.Addr, string) error        { return nil }
func (g *gateCounter) RecordAuthAttempt(context.Context, net.Addr, string, bool)     {}
func (g *gateCounter) IsIPBlocked(net.Addr) bool                                     { return false }
func (g *gateCounter) IsIPBlockedWithProxy(net.Conn, *server.ProxyProtocolInfo) bool { return false }
func (g *gateCounter) GetStats(context.Context, time.Duration) map[string]any        { return nil }
func (g *gateCounter) Stop()                                                         {}

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

// TestManageSieve_MasterSASLSelfLoginTimingIsNotAPasswordOracle (#760): a master
// SASL self-login (authorization identity = authentication identity = the master
// SASL username) with an address-shaped master SASL username that names no account
// costs one password verification whatever the password, with or without
// master_sasl_allowed_networks. Any other password is answered by regular
// authentication, which verifies a dummy hash for an address it does not know; the
// master SASL password used to be answered from the master SASL block without one
// (the target lookup found nothing, or the gate refused the peer), so the response
// time confirmed a guessed master SASL password. The lookup cache is off, as in the
// report: with it on, only the first wrong attempt per negative TTL verifies. Both
// passwords also pass the progressive delay and the rate-limit check once and are
// recorded once: a master SASL self-login handed on to regular authentication must not
// be delayed or checked a second time there.
func TestManageSieve_MasterSASLSelfLoginTimingIsNotAPasswordOracle(t *testing.T) {
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
			limiter := &gateCounter{}
			srv, err := managesieve.New(context.Background(), "test-master-sasl-self-login-timing", "localhost", address, rdb,
				managesieve.ManageSieveServerOptions{
					Config:                    &config.Config{},
					InsecureAuth:              true,
					MasterSASLUsername:        saslUser,
					MasterSASLPassword:        saslPass,
					MasterSASLAllowedNetworks: gate.networks,
					LookupCache:               &config.LookupCacheConfig{Enabled: false},
					AuthLimiterOverride:       limiter,
				})
			if err != nil {
				t.Fatalf("Failed to create ManageSieve server: %v", err)
			}
			errChan := make(chan error, 1)
			go func() { srv.Start(errChan) }()
			time.Sleep(100 * time.Millisecond)
			t.Cleanup(func() { srv.Close() })

			type outcome struct {
				reply                    string
				delays, checks, failures int32
			}
			timed := func(password string) (outcome, time.Duration) {
				delays, checks, failures := limiter.delays.Load(), limiter.checks.Load(), limiter.failures.Load()
				start := time.Now()
				reply := msAuthPlain(t, address, saslUser, saslUser, password)
				took := time.Since(start)
				return outcome{
					reply:    reply,
					delays:   limiter.delays.Load() - delays,
					checks:   limiter.checks.Load() - checks,
					failures: limiter.failures.Load() - failures,
				}, took
			}
			wrong, wrongTook := timed("wrong-password")
			master, masterTook := timed(saslPass)

			if master != wrong {
				t.Fatalf("self-login answered differently by password:\n  wrong password:  %+v\n  master password: %+v", wrong, master)
			}
			if want := (outcome{reply: wrong.reply, delays: 1, checks: 1, failures: 1}); wrong != want {
				t.Fatalf("wrong password: %+v, want one delay lookup, one rate-limit check and one recorded failure", wrong)
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
