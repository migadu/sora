//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestIMAPMasterLoginDuringDatabaseOutage: a master login whose impersonation target
// the database cannot look up is a temporary failure, NO [UNAVAILABLE] (RFC 5530
// section 3), not a bad credential, and it is not counted against the master
// credential by the auth rate limiter, so the master login works once the database is
// back. LOGIN (login.go) and AUTHENTICATE (sasl.go, master username and master SASL)
// look the target up in three places, so each is probed, each on its own database
// connection so the outages do not add up to an open circuit breaker.
func TestIMAPMasterLoginDuringDatabaseOutage(t *testing.T) {
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
		{"LOGIN_master_username", func(t *testing.T, address, target string) string {
			return imapRawCommand(t, address, fmt.Sprintf("LOGIN %q %q", target+"@"+masterUser, masterPass))
		}},
		{"AUTHENTICATE_master_username", func(t *testing.T, address, target string) string {
			return imapAuthPlain(t, address, "", target+"@"+masterUser, masterPass)
		}},
		{"AUTHENTICATE_master_SASL", func(t *testing.T, address, target string) string {
			return imapAuthPlain(t, address, target, saslUser, saslPass)
		}},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			rdb, outage := common.SetupTestDatabaseWithOutage(t)
			account := common.CreateTestAccount(t, rdb)
			address := common.GetRandomAddress(t)

			srv, err := serverImap.New(context.Background(), "test-master-db-outage", "localhost", address,
				&storage.S3Storage{}, rdb, nil, nil,
				serverImap.IMAPServerOptions{
					InsecureAuth:       true,
					AuthRateLimit:      common.DBOutageAuthRateLimit(),
					MasterUsername:     []byte(masterUser),
					MasterPassword:     []byte(masterPass),
					MasterSASLUsername: []byte(saslUser),
					MasterSASLPassword: []byte(saslPass),
				})
			if err != nil {
				t.Fatalf("Failed to create IMAP server: %v", err)
			}
			go func() { _ = srv.Serve(address) }()
			t.Cleanup(func() { srv.Close() })
			time.Sleep(100 * time.Millisecond)

			authenticationAttempts := func(result string) float64 {
				return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap", "test-master-db-outage", "localhost", result))
			}
			unavailableBefore, failuresBefore := authenticationAttempts("unavailable"), authenticationAttempts("failure")

			outage.Begin()
			for i := 1; i <= 3; i++ {
				if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "A001 NO [UNAVAILABLE]") {
					t.Errorf("master login %d during a database outage: %q, want A001 NO [UNAVAILABLE] ...", i, reply)
				}
			}
			outage.End()

			if grew := authenticationAttempts("unavailable") - unavailableBefore; grew != 3 {
				t.Errorf("outage logins counted as unavailable: %v, want 3", grew)
			}
			if grew := authenticationAttempts("failure") - failuresBefore; grew != 0 {
				t.Errorf("outage logins counted as credential failures: %v, want 0", grew)
			}

			if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "A001 OK") {
				t.Errorf("master login after the outage: %q, want A001 OK (the outage was counted as failed logins)", reply)
			}
		})
	}
}
