//go:build integration

package imapproxy

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestIMAPProxyWrongMasterPasswordLooksLikeAnotherSuffixInTheDatabase is
// TestIMAPProxyWrongMasterPasswordLooksLikeAnotherSuffix (#801) for a proxy that
// authenticates against the database, for an unknown address and for an account. The
// account's own password logs in under the master suffix as under any other (#949).
func TestIMAPProxyWrongMasterPasswordLooksLikeAnotherSuffixInTheDatabase(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// A proxy per login pair: the lookup cache is the subject, so no pair sees another's.
	refuse := func(username, password string) lookupRefusal {
		srv, err := New(context.Background(), rdb, "localhost", ServerOptions{
			Name: "master-refusal-db", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
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
	for _, c := range []struct {
		name, base, password string
		logsIn               bool
	}{
		{"unknown_address", unknown, "wrong-password", false},
		{"wrong_password", account.Email, "wrong-password", false},
		{"account_password", account.Email, account.Password, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			other := refuse(c.base+"@other", c.password)
			if c.logsIn {
				if key := server.AuthRateLimitKey(c.base); other.successKeys != key+","+key {
					t.Fatalf("%q under another suffix: %+v; want two successes recorded under %q", c.password, other, key)
				}
			} else if other.verifications != [2]int{1, 0} || !other.cached {
				t.Fatalf("%q under another suffix: %+v; want one verification and a cached refusal", c.password, other)
			}
			if got := refuse(c.base+"@"+testMasterUsername, c.password); got != other {
				t.Errorf("%q under the master suffix: %+v\nunder another suffix: %+v", c.password, got, other)
			}
		})
	}
}
