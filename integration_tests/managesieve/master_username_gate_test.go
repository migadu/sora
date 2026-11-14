//go:build integration

package managesieve

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// startManageSieveMasterUsernameGate brings up a backend with the master-username form
// configured and master_sasl_allowed_networks set to allowedNetworks. A non-nil limiter
// replaces the real one so a test can see what is recorded.
func startManageSieveMasterUsernameGate(t *testing.T, allowedNetworks []string, limiter server.AuthLimiter) (string, common.TestAccount) {
	t.Helper()

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	srv, err := managesieve.New(
		context.Background(),
		"test-master-username-gate",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:                    &config.Config{},
			MasterUsername:            masterUsername,
			MasterPassword:            masterPassword,
			MasterSASLUsername:        masterSASLUsername,
			MasterSASLPassword:        masterSASLPassword,
			MasterSASLAllowedNetworks: allowedNetworks,
			InsecureAuth:              true,
			AuthLimiterOverride:       limiter,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { srv.Close() })

	return address, account
}

// TestManageSieve_MasterUsernameGate_BlocksOffNetwork pins that master_sasl_allowed_networks
// restricts the master-username form "user@domain@MASTER_USERNAME" exactly as it restricts
// master SASL, as it already did on POP3: both impersonate any account with one tenant-wide
// password. Both verbs are probed (masterUsernameVerbs): they are different functions.
//
// The refusal is reachable only with the CORRECT master password, so it must be answered
// and recorded exactly like a wrong one; otherwise the gate confirms a guessed password to a
// peer that is not even allowed to use it.
func TestManageSieve_MasterUsernameGate_BlocksOffNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	limiter := &msRecordingLimiter{}
	address, account := startManageSieveMasterUsernameGate(t, []string{"10.0.0.0/8"}, limiter) // excludes 127.0.0.1
	masterForm := account.Email + "@" + masterUsername

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			limiter.drain()

			wrongPassword := verb.probe(t, address, masterForm, "definitely-not-the-master-password")
			if !strings.HasPrefix(wrongPassword, "NO") {
				t.Fatalf("wrong master password was not refused: %q", wrongPassword)
			}
			wrongPasswordRecords := limiter.drain()
			if len(wrongPasswordRecords) == 0 {
				t.Fatal("control: a wrong master password recorded nothing, so this test cannot discriminate")
			}

			correctPassword := verb.probe(t, address, masterForm, masterPassword)
			if !strings.HasPrefix(correctPassword, "NO") {
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

// TestManageSieve_MasterUsernameGate_AllowsOnNetwork is the control: from inside the
// allowed networks the master-username form logs in on both verbs.
func TestManageSieve_MasterUsernameGate_AllowsOnNetwork(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	address, account := startManageSieveMasterUsernameGate(t, []string{"127.0.0.0/8", "::1/128"}, nil)
	masterForm := account.Email + "@" + masterUsername

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			if resp := verb.probe(t, address, masterForm, masterPassword); !strings.HasPrefix(resp, "OK") {
				t.Fatalf("master-username login from an allowed network was refused: %q", resp)
			}
		})
	}
}
