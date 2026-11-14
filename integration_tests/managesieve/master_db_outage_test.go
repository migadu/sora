//go:build integration

package managesieve

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
)

// TestManageSieveMasterLoginDuringDatabaseOutage: a master login whose impersonation
// target the database cannot look up is a temporary failure, NO (TRYLATER) (RFC 5804
// section 1.3), not a failed authentication, and it is not counted against the master
// credential by the auth rate limiter, so the master login works once the database is
// back. AUTHENTICATE (master username and master SASL) and LOGIN (master username)
// look the target up in three places, so each is probed, each on its own database
// connection so the outages do not add up to an open circuit breaker.
func TestManageSieveMasterLoginDuringDatabaseOutage(t *testing.T) {
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
		{"AUTHENTICATE_master_username", func(t *testing.T, address, target string) string {
			return msAuthPlain(t, address, "", target+"@"+masterUser, masterPass)
		}},
		{"AUTHENTICATE_master_SASL", func(t *testing.T, address, target string) string {
			return msAuthPlain(t, address, target, saslUser, saslPass)
		}},
		{"LOGIN_master_username", func(t *testing.T, address, target string) string {
			return msLogin(t, address, target+"@"+masterUser, masterPass)
		}},
	}

	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			rdb, outage := common.SetupTestDatabaseWithOutage(t)
			account := common.CreateTestAccount(t, rdb)
			address := common.GetRandomAddress(t)

			srv, err := managesieve.New(context.Background(), "test-master-db-outage", "localhost", address, rdb,
				managesieve.ManageSieveServerOptions{
					Config:             &config.Config{},
					InsecureAuth:       true,
					AuthRateLimit:      common.DBOutageAuthRateLimit(),
					MasterUsername:     masterUser,
					MasterPassword:     masterPass,
					MasterSASLUsername: saslUser,
					MasterSASLPassword: saslPass,
				})
			if err != nil {
				t.Fatalf("Failed to create ManageSieve server: %v", err)
			}
			errChan := make(chan error, 1)
			go func() { srv.Start(errChan) }()
			t.Cleanup(func() { srv.Close() })
			time.Sleep(100 * time.Millisecond)

			outage.Begin()
			for i := 1; i <= 3; i++ {
				if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "NO (TRYLATER)") {
					t.Errorf("master login %d during a database outage: %q, want NO (TRYLATER) ...", i, reply)
				}
			}
			outage.End()

			if reply := form.probe(t, address, account.Email); !strings.HasPrefix(reply, "OK") {
				t.Errorf("master login after the outage: %q, want OK (the outage was counted as failed logins)", reply)
			}
		})
	}
}
