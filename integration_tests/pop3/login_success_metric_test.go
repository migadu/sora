//go:build integration

package pop3_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPOP3_SuccessfulLoginsAreCounted: the POP3 backend counted rate-limited, failed
// and unavailable logins in sora_authentication_attempts_total but never a successful
// one, so a success ratio or a "no successful POP3 logins" alert read 0 while users
// were logging in. Every way in counts once, as on the IMAP and ManageSieve backends.
func TestPOP3_SuccessfulLoginsAreCounted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	const name = "test-pop3-login-success"
	address := startPOP3WithMasterCredentials(t, rdb, name, nil)

	success := metrics.AuthenticationAttempts.WithLabelValues("pop3", name, "localhost", "success")
	failure := metrics.AuthenticationAttempts.WithLabelValues("pop3", name, "localhost", "failure")

	for _, c := range []struct {
		name  string
		login func() string
	}{
		{"USER/PASS", func() string { return pop3UserPass(t, address, account.Email, account.Password) }},
		{"AUTH PLAIN", func() string { return pop3AuthPlain(t, address, "", account.Email, account.Password) }},
		{"master username", func() string { return pop3UserPass(t, address, account.Email+"@"+masterUsername, masterPassword) }},
		{"master SASL", func() string { return pop3AuthPlain(t, address, account.Email, masterSASLUsername, masterSASLPassword) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			successBefore, failureBefore := testutil.ToFloat64(success), testutil.ToFloat64(failure)
			if reply := c.login(); !strings.HasPrefix(reply, "+OK") {
				t.Fatalf("login: %q, want +OK", reply)
			}
			if d := testutil.ToFloat64(success) - successBefore; d != 1 {
				t.Errorf(`sora_authentication_attempts_total{protocol="pop3",result="success"} grew by %v, want 1`, d)
			}
			if d := testutil.ToFloat64(failure) - failureBefore; d != 0 {
				t.Errorf(`sora_authentication_attempts_total{protocol="pop3",result="failure"} grew by %v, want 0`, d)
			}
		})
	}
}
