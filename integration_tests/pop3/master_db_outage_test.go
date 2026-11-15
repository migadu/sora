//go:build integration

package pop3_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3MasterLoginDuringDatabaseOutage: a master login whose impersonation target
// the database cannot look up is a temporary failure, -ERR [SYS/TEMP] (RFC 3206
// section 4), not [AUTH], and it is not counted against the master credential by the
// auth rate limiter, so the master login works once the database is back. The master
// SASL and master username paths look the target up separately, so both are probed,
// each on its own database connection so the outages do not add up to an open circuit
// breaker.
func TestPOP3MasterLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const (
		masterUser = "master_admin"
		masterPass = "master_secret_pw"
		saslUser   = "master_sasl"
		saslPass   = "master_sasl_secret_pw"
	)

	forms := []struct {
		name  string
		probe func(t *testing.T, address, target string) string
	}{
		{"USER_PASS_master_username", func(t *testing.T, address, target string) string {
			return pop3UserPass(t, address, target+"@"+masterUser, masterPass)
		}},
		{"AUTH_PLAIN_master_username", func(t *testing.T, address, target string) string {
			return pop3AuthPlain(t, address, "", target+"@"+masterUser, masterPass)
		}},
		{"AUTH_PLAIN_master_SASL", func(t *testing.T, address, target string) string {
			return pop3AuthPlain(t, address, target, saslUser, saslPass)
		}},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			rdb, outage := common.SetupTestDatabaseWithOutage(t)
			account := common.CreateTestAccount(t, rdb)
			address := common.GetRandomAddress(t)

			srv, err := pop3.New(context.Background(), "test-master-db-outage", "localhost", address,
				&storage.S3Storage{}, rdb, nil, nil,
				pop3.POP3ServerOptions{
					InsecureAuth:       true,
					Config:             &config.Config{},
					AuthRateLimit:      common.DBOutageAuthRateLimit(),
					MasterUsername:     masterUser,
					MasterPassword:     masterPass,
					MasterSASLUsername: saslUser,
					MasterSASLPassword: saslPass,
				})
			if err != nil {
				t.Fatalf("Failed to create POP3 server: %v", err)
			}
			errChan := make(chan error, 1)
			go func() { srv.Start(errChan) }()
			t.Cleanup(func() { srv.Close() })
			time.Sleep(100 * time.Millisecond)

			authenticationAttempts := func(result string) float64 {
				return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3", "test-master-db-outage", "localhost", result))
			}
			unavailableBefore, failuresBefore := authenticationAttempts("unavailable"), authenticationAttempts("failure")

			outage.Begin()
			for i := 1; i <= 3; i++ {
				if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
					t.Errorf("master login %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
				}
			}
			outage.End()

			if grew := authenticationAttempts("unavailable") - unavailableBefore; grew != 3 {
				t.Errorf("outage logins counted as unavailable: %v, want 3", grew)
			}
			if grew := authenticationAttempts("failure") - failuresBefore; grew != 0 {
				t.Errorf("outage logins counted as credential failures: %v, want 0", grew)
			}

			if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "+OK") {
				t.Errorf("master login after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
			}
		})
	}
}

// TestPOP3LoginDuringDatabaseStall: a login whose credential or impersonation target
// lookup runs into its timeout because the database hangs is a database outage,
// -ERR [SYS/TEMP] and counted as unavailable, not a server shutdown, which is not
// counted at all. The regular login and each master path look the account up
// separately, so each is probed, each on its own database connection.
func TestPOP3LoginDuringDatabaseStall(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const (
		masterUser = "master_admin"
		masterPass = "master_secret_pw"
		saslUser   = "master_sasl"
		saslPass   = "master_sasl_secret_pw"
	)

	forms := []struct {
		name  string
		probe func(t *testing.T, address string, account common.TestAccount) string
	}{
		{"USER_PASS", func(t *testing.T, address string, account common.TestAccount) string {
			return pop3UserPass(t, address, account.Email, account.Password)
		}},
		{"USER_PASS_master_username", func(t *testing.T, address string, account common.TestAccount) string {
			return pop3UserPass(t, address, account.Email+"@"+masterUser, masterPass)
		}},
		{"AUTH_PLAIN_master_username", func(t *testing.T, address string, account common.TestAccount) string {
			return pop3AuthPlain(t, address, "", account.Email+"@"+masterUser, masterPass)
		}},
		{"AUTH_PLAIN_master_SASL", func(t *testing.T, address string, account common.TestAccount) string {
			return pop3AuthPlain(t, address, account.Email, saslUser, saslPass)
		}},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			rdb, outage := common.SetupTestDatabaseWithOutage(t)
			account := common.CreateTestAccount(t, rdb)
			address := common.GetRandomAddress(t)

			srv, err := pop3.New(context.Background(), "test-db-stall", "localhost", address,
				&storage.S3Storage{}, rdb, nil, nil,
				pop3.POP3ServerOptions{
					InsecureAuth:       true,
					Config:             &config.Config{},
					AuthRateLimit:      common.DBOutageAuthRateLimit(),
					MasterUsername:     masterUser,
					MasterPassword:     masterPass,
					MasterSASLUsername: saslUser,
					MasterSASLPassword: saslPass,
				})
			if err != nil {
				t.Fatalf("Failed to create POP3 server: %v", err)
			}
			errChan := make(chan error, 1)
			go func() { srv.Start(errChan) }()
			t.Cleanup(func() { srv.Close() })
			time.Sleep(100 * time.Millisecond)

			unavailable := func() float64 {
				return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("pop3", "test-db-stall", "localhost", "unavailable"))
			}
			before := unavailable()

			outage.Stall()
			// The first lookup may find its pooled connection dropped; the next ones stall.
			for i := 1; i <= 3; i++ {
				if reply := form.probe(t, address, account); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
					t.Errorf("login %d while the database stalls: %q, want -ERR [SYS/TEMP] ...", i, reply)
				}
			}
			outage.End()

			if grew := unavailable() - before; grew != 3 {
				t.Errorf("logins while the database stalls counted as unavailable: %v, want 3 (a lookup timeout was taken for a server shutdown)", grew)
			}

			if reply := form.probe(t, address, account); !strings.HasPrefix(reply, "+OK") {
				t.Errorf("login after the stall: %q, want +OK", reply)
			}
		})
	}
}
