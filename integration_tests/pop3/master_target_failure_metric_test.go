//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// startPOP3WithMasterCredentials starts a POP3 backend named name with both master
// credentials, its master logins confined to allowedNetworks (nil: any source).
func startPOP3WithMasterCredentials(t *testing.T, rdb *resilient.ResilientDatabase, name string, allowedNetworks []string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := pop3.New(context.Background(), name, "localhost", address,
		&storage.S3Storage{}, rdb, nil, nil,
		pop3.POP3ServerOptions{
			InsecureAuth:              true,
			Config:                    &config.Config{},
			MasterUsername:            masterUsername,
			MasterPassword:            masterPassword,
			MasterSASLUsername:        masterSASLUsername,
			MasterSASLPassword:        masterSASLPassword,
			MasterSASLAllowedNetworks: allowedNetworks,
		})
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	t.Cleanup(srv.Close)
	waitForPOP3Listener(t, address, errChan)
	return address
}

// TestPOP3_MasterTargetRejectionsCountAsFailedLogins: a master login with the CORRECT
// master credential that is then refused (its source is outside
// master_sasl_allowed_networks, its impersonation target does not parse, or the target
// has no account) is answered and recorded exactly like a wrong master password, so it
// must also be counted like one in
// sora_authentication_attempts_total{protocol="pop3",result="failure"}. Otherwise
// probing with a guessed master password is invisible to failed-login monitoring, while
// the same probe with a wrong password is not.
func TestPOP3_MasterTargetRejectionsCountAsFailedLogins(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const openName, gatedName = "test-master-target-failures", "test-master-target-failures-gated"
	open := startPOP3WithMasterCredentials(t, rdb, openName, nil)
	// Loopback is not in this range, so every master login on this server is refused
	// after its credential checked out.
	gated := startPOP3WithMasterCredentials(t, rdb, gatedName, []string{"10.0.0.0/8"})

	unknown := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())
	authPlain := func(authzID, authnID, password string) func(address string) string {
		return func(address string) string { return pop3AuthPlain(t, address, authzID, authnID, password) }
	}
	userPass := func(username, password string) func(address string) string {
		return func(address string) string { return pop3UserPass(t, address, username, password) }
	}

	// Controls: both master credentials impersonate a real account on the open server,
	// so a rejection below is caused by the case under test.
	if reply := authPlain(account.Email, masterSASLUsername, masterSASLPassword)(open); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("control: master SASL login: %q, want +OK", reply)
	}
	if reply := userPass(account.Email+"@"+masterUsername, masterPassword)(open); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("control: master username login: %q, want +OK", reply)
	}

	cases := []struct {
		name   string
		server string // label of the server's counter
		addr   string
		probe  func(address string) string
	}{
		// Controls: a wrong master password is counted on both paths.
		{"master_SASL/wrong_password", openName, open, authPlain(account.Email, masterSASLUsername, "wrong-master-sasl-password")},
		{"master_username/wrong_password", openName, open, userPass(account.Email+"@"+masterUsername, "wrong-master-password")},

		{"master_SASL/source_not_allowed", gatedName, gated, authPlain(account.Email, masterSASLUsername, masterSASLPassword)},
		{"master_SASL/malformed_target", openName, open, authPlain("not-an-address", masterSASLUsername, masterSASLPassword)},
		{"master_SASL/unknown_target", openName, open, authPlain(unknown, masterSASLUsername, masterSASLPassword)},
		{"master_username/source_not_allowed", gatedName, gated, userPass(account.Email+"@"+masterUsername, masterPassword)},
		{"master_username/malformed_target", openName, open, authPlain("not-an-address", account.Email+"@"+masterUsername, masterPassword)},
		{"master_username/unknown_target", openName, open, userPass(unknown+"@"+masterUsername, masterPassword)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			counter := metrics.AuthenticationAttempts.WithLabelValues("pop3", tc.server, "localhost", "failure")
			before := testutil.ToFloat64(counter)
			reply := tc.probe(tc.addr)
			grew := testutil.ToFloat64(counter) - before

			if !strings.HasPrefix(reply, "-ERR [AUTH]") {
				t.Fatalf("reply %q, want -ERR [AUTH] ...", reply)
			}
			if grew != 1 {
				t.Errorf("sora_authentication_attempts_total{protocol=\"pop3\",result=\"failure\"} grew by %v, want 1", grew)
			}
		})
	}
}
