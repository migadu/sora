//go:build integration

package imap_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// imapMasterUsernameVerbs are the two commands that accept the master-username form
// "user@domain@MASTER_USERNAME". They reach it through different code (LOGIN in
// login.go, the AUTHENTICATE PLAIN callback in sasl.go), so both are probed.
var imapMasterUsernameVerbs = []struct {
	name  string
	probe func(t *testing.T, address, username, password string) string
}{
	{"LOGIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return imapRawCommand(t, address, fmt.Sprintf("LOGIN %q %q", username, password))
	}},
	{"AUTHENTICATE_PLAIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return imapAuthPlain(t, address, "", username, password)
	}},
}

// TestIMAP_MasterUsernameGate_BlocksOffNetwork pins that master_sasl_allowed_networks
// restricts the master-username form exactly as it restricts master SASL, as it already
// did on POP3: both impersonate any account with one tenant-wide password.
//
// The refusal is reachable only with the CORRECT master password, so it must be answered
// and recorded exactly like a wrong one; otherwise the gate confirms a guessed password to
// a peer that is not even allowed to use it.
func TestIMAP_MasterUsernameGate_BlocksOffNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Loopback is NOT inside this range, so every attempt below is off-network.
	limiter := &recordingAuthLimiter{}
	srv, account := setupIMAPServerWithMasterSASLGateAndLimiter(t, []string{"10.99.0.0/16"}, limiter)
	masterForm := account.Email + "@" + masterUsername

	for _, verb := range imapMasterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			limiter.drain()

			wrongPassword := verb.probe(t, srv.Address, masterForm, "definitely-not-the-master-password")
			if !strings.HasPrefix(wrongPassword, "A001 NO") {
				t.Fatalf("wrong master password was not refused: %q", wrongPassword)
			}
			wrongPasswordRecords := limiter.drain()
			if len(wrongPasswordRecords) == 0 {
				t.Fatal("control: a wrong master password recorded nothing, so this test cannot discriminate")
			}

			correctPassword := verb.probe(t, srv.Address, masterForm, masterPassword)
			if !strings.HasPrefix(correctPassword, "A001 NO") {
				t.Fatalf("master-username login succeeded from a peer outside master_sasl_allowed_networks: %q", correctPassword)
			}
			gateRecords := limiter.drain()

			if correctPassword != wrongPassword {
				t.Errorf("the gate's refusal is distinguishable from a wrong master password:\n"+
					"\twrong password:   %q\n\tcorrect password: %q", wrongPassword, correctPassword)
			}
			if !reflect.DeepEqual(gateRecords, wrongPasswordRecords) {
				t.Errorf("gate refusal is accounted differently from a wrong password:\n\twrong password: %v\n\tgate refusal:   %v",
					wrongPasswordRecords, gateRecords)
			}
		})
	}
}

// TestIMAP_MasterUsernameGate_AllowsOnNetwork is the control: from inside the allowed
// networks the master-username form logs in on both verbs.
func TestIMAP_MasterUsernameGate_AllowsOnNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := setupIMAPServerWithMasterSASLGate(t, []string{"127.0.0.0/8", "::1/128"})
	masterForm := account.Email + "@" + masterUsername

	for _, verb := range imapMasterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			if resp := verb.probe(t, srv.Address, masterForm, masterPassword); !strings.HasPrefix(resp, "A001 OK") {
				t.Fatalf("master-username login from an allowed network was refused: %q", resp)
			}
		})
	}
}
