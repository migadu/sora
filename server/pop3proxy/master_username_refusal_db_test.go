//go:build integration

package pop3proxy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3ProxyWrongMasterPasswordLooksLikeAnotherSuffixInTheDatabase is
// TestPOP3ProxyWrongMasterPasswordLooksLikeAnotherSuffix (#801) for a proxy that
// authenticates against the database, for an unknown address and for an account.
func TestPOP3ProxyWrongMasterPasswordLooksLikeAnotherSuffixInTheDatabase(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// A proxy per login pair: the lookup cache is the subject, so no pair sees another's.
	refuse := func(username, password string) lookupRefusal {
		srv, err := New(context.Background(), "localhost", "127.0.0.1:0", rdb, POP3ProxyServerOptions{
			Name: "master-refusal-db", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
			InsecureAuth:   true,
			MasterUsername: testMasterUsername,
			MasterPassword: testMasterPassword,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer srv.Stop()
		return refuseTwiceAs(t, srv, username, password)
	}

	unknown := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())
	for _, c := range []struct{ name, base, password string }{
		{"unknown_address", unknown, "wrong-password"},
		{"wrong_password", account.Email, "wrong-password"},
		{"account_password", account.Email, account.Password},
	} {
		t.Run(c.name, func(t *testing.T) {
			other := refuse(c.base+"@other", "wrong-password")
			if other.verifications != [2]int{1, 0} || !other.cached {
				t.Fatalf("wrong password under another suffix: %+v; want one verification and a cached refusal", other)
			}
			if got := refuse(c.base+"@"+testMasterUsername, c.password); got != other {
				t.Errorf("%q under the master suffix: %+v\nwrong password under another suffix: %+v", c.password, got, other)
			}
		})
	}
}
