//go:build integration

package pop3_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
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

			outage.Begin()
			for i := 1; i <= 3; i++ {
				if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
					t.Errorf("master login %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
				}
			}
			outage.End()

			if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "+OK") {
				t.Errorf("master login after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
			}
		})
	}
}
