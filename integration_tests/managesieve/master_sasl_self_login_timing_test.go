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
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/testutils"
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

// TestManageSieve_MasterSASLSelfLoginTimingIsNotAPasswordOracle (#760): a master
// SASL self-login (authorization identity = authentication identity = the master
// SASL username) with an address-shaped master SASL username that names no account
// costs one password verification whatever the password, with or without
// master_sasl_allowed_networks. Any other password is answered by regular
// authentication, which verifies a dummy hash for an address it does not know; the
// master SASL password used to be answered from the master SASL block without one
// (the target lookup found nothing, or the gate refused the peer), so the response
// time confirmed a guessed master SASL password. Both cache modes are covered:
// backend negative entries revalidate on every attempt. Both
// passwords also pass the progressive delay and the rate-limit check once and are
// recorded once: a master SASL self-login handed on to regular authentication must not
// be delayed or checked a second time there. The verifications are counted, not timed
// (#782): a wall-clock floor calibrated under CPU contention fails a correct login that
// runs after the contention eases.
func TestManageSieve_MasterSASLSelfLoginTimingIsNotAPasswordOracle(t *testing.T) {
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
		{"peer_outside_allowed_networks", []string{"192.0.2.0/24"}, false},
		{"cached_no_allowed_networks", nil, true},
		{"cached_peer_outside_allowed_networks", []string{"192.0.2.0/24"}, true},
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
					LookupCache:               &config.LookupCacheConfig{Enabled: gate.cacheEnabled},
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
				verifications            int
			}
			attempt := func(password string) outcome {
				delays, checks, failures := limiter.delays.Load(), limiter.checks.Load(), limiter.failures.Load()
				verifications := testutils.PasswordVerifications()
				reply := msAuthPlain(t, address, saslUser, saslUser, password)
				return outcome{
					reply:         reply,
					delays:        limiter.delays.Load() - delays,
					checks:        limiter.checks.Load() - checks,
					failures:      limiter.failures.Load() - failures,
					verifications: testutils.PasswordVerifications() - verifications,
				}
			}
			wrong := attempt("wrong-password")
			master := attempt(saslPass)

			if master != wrong {
				t.Fatalf("self-login answered differently by password:\n  wrong password:  %+v\n  master password: %+v", wrong, master)
			}
			if want := (outcome{reply: wrong.reply, delays: 1, checks: 1, failures: 1, verifications: 1}); wrong != want {
				t.Fatalf("wrong password: %+v, want one delay lookup, one rate-limit check, one recorded failure and one password verification", wrong)
			}
		})
	}
}

func TestManageSieve_MasterSASLRefusalTimingIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	saslUser := fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())
	unknownTarget := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())
	const saslPass = "master-sasl-secret"

	for _, tc := range []struct {
		name         string
		saslUser     string
		saslPass     string
		networks     []string
		authzID      string
		cacheEnabled bool
		wantVerified int
	}{
		{"peer_outside_allowed_networks", saslUser, saslPass, []string{"192.0.2.0/24"}, account.Email, false, 1},
		{"cached_peer_outside_allowed_networks", saslUser, saslPass, []string{"192.0.2.0/24"}, account.Email, true, 1},
		{"malformed_target", saslUser, saslPass, nil, "not-an-address", false, 1},
		{"cached_malformed_target", saslUser, saslPass, nil, "not-an-address", true, 1},
		{"unknown_target", saslUser, saslPass, nil, unknownTarget, false, 1},
		{"cached_unknown_target", saslUser, saslPass, nil, unknownTarget, true, 1},
		{"non_address_master_username", "proxy-master", saslPass, nil, unknownTarget, false, 0},
		{"account_owned_master_username", account.Email, account.Password, nil, unknownTarget, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := common.GetRandomAddress(t)
			limiter := &gateCounter{}
			srv, err := managesieve.New(context.Background(), "test-master-sasl-refusal-timing", "localhost", address, rdb,
				managesieve.ManageSieveServerOptions{
					Config:                    &config.Config{},
					InsecureAuth:              true,
					MasterSASLUsername:        tc.saslUser,
					MasterSASLPassword:        tc.saslPass,
					MasterSASLAllowedNetworks: tc.networks,
					LookupCache:               &config.LookupCacheConfig{Enabled: tc.cacheEnabled},
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
				verifications            int
			}
			attempt := func(password string) outcome {
				delays, checks, failures := limiter.delays.Load(), limiter.checks.Load(), limiter.failures.Load()
				verifications := testutils.PasswordVerifications()
				reply := msAuthPlain(t, address, tc.authzID, tc.saslUser, password)
				return outcome{
					reply:         reply,
					delays:        limiter.delays.Load() - delays,
					checks:        limiter.checks.Load() - checks,
					failures:      limiter.failures.Load() - failures,
					verifications: testutils.PasswordVerifications() - verifications,
				}
			}
			wrong := attempt("wrong-password")
			master := attempt(tc.saslPass)

			if want := (outcome{reply: wrong.reply, delays: 1, checks: 1, failures: 1, verifications: tc.wantVerified}); wrong != want {
				t.Fatalf("wrong password: %+v, want one delay lookup, one rate-limit check, one recorded failure and %d password verification(s)", wrong, tc.wantVerified)
			}
			if master != wrong {
				t.Errorf("master SASL refusal answered differently by password:\n  wrong password:  %+v\n  master password: %+v", wrong, master)
			}
		})
	}
}
