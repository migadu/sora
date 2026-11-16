//go:build integration

package managesieve

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestManageSieve_AuthzIDRefusalNeedsCredentials: an AUTHENTICATE PLAIN that asks to
// act as another user is refused for authorization only once its credentials checked
// out (RFC 4616 section 2 verifies the authentication identity and password first,
// then the authorization identity). Without valid credentials it is a failed login
// like any other, answered and recorded alike whether or not the authentication
// identity is the master SASL username: refusing every other authentication identity
// before the password, unrecorded, confirmed a guessed master SASL username to anyone
// who could reach the port. The refusal no longer claims the master SASL settings are
// missing, which was false whenever they were configured.
func TestManageSieve_AuthzIDRefusalNeedsCredentials(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	victim := common.CreateTestAccount(t, rdb)

	const saslPass = "master_sasl_secret_pw"
	const badCredential = `NO "Authentication failed"`
	// Tier 1 only; Tier 2 and progressive delays disabled.
	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}
	n := time.Now().UnixNano()

	t.Run("valid_credentials_get_the_authorization_refusal", func(t *testing.T) {
		addr := startManageSieveWithMasterSASL(t, rdb, rateLimit, fmt.Sprintf("proxyuser-%d", n), saslPass)
		want := `NO "Proxy authentication requires master credentials"`
		if resp := msAuthPlain(t, addr, victim.Email, account.Email, account.Password); resp != want {
			t.Fatalf("valid credentials asking to act as another user: %q, want %q", resp, want)
		}
	})

	t.Run("wrong_password_is_a_failed_login", func(t *testing.T) {
		addr := startManageSieveWithMasterSASL(t, rdb, rateLimit, fmt.Sprintf("proxyuser-%d", n), saslPass)
		for i := 0; i < 3; i++ {
			if resp := msAuthPlain(t, addr, victim.Email, account.Email, fmt.Sprintf("wrong-%d", i)); resp != badCredential {
				t.Fatalf("attempt %d, wrong password asking to act as another user: %q, want the bad-credential reply %q", i+1, resp, badCredential)
			}
		}
		// Recorded: the three failures block the account's own key, so even its
		// correct password is refused now.
		if resp := msAuthPlain(t, addr, "", account.Email, account.Password); strings.HasPrefix(resp, "OK") {
			t.Fatalf("login still allowed after 3 wrong passwords that asked to act as another user: the failures were not recorded (got %q)", resp)
		}
	})

	for _, shape := range []struct{ name, master, other string }{
		{"non_address", fmt.Sprintf("proxyuser-%d", n), fmt.Sprintf("notmaster-%d", n)},
		{"address_shaped", fmt.Sprintf("proxy-%d@example.com", n), fmt.Sprintf("notmaster-%d@example.com", n)},
	} {
		t.Run("master_sasl_username_not_told_apart_"+shape.name, func(t *testing.T) {
			addr := startManageSieveWithMasterSASL(t, rdb, rateLimit, shape.master, saslPass)
			master := msAuthPlain(t, addr, victim.Email, shape.master, "wrong")
			other := msAuthPlain(t, addr, victim.Email, shape.other, "wrong")
			if master != badCredential || other != badCredential {
				t.Fatalf("wrong password asking to act as another user must get the bad-credential reply %q whatever the authentication identity:\n  master SASL username: %q\n  other username:       %q", badCredential, master, other)
			}
		})
	}

	// The same holds for the master username form "user@domain@MASTER_USERNAME": the
	// master username with a wrong master password got the bad-credential reply, any
	// other suffix the authorization refusal before its password was checked.
	t.Run("master_username_not_told_apart", func(t *testing.T) {
		masterUser := fmt.Sprintf("masteruser-%d", n)
		addr := startManageSieveWithMasterUsername(t, rdb, rateLimit, masterUser, "master_secret_pw")
		master := msAuthPlain(t, addr, victim.Email, account.Email+"@"+masterUser, "wrong")
		other := msAuthPlain(t, addr, victim.Email, account.Email+"@"+fmt.Sprintf("notmaster-%d", n), "wrong")
		if master != badCredential || other != badCredential {
			t.Fatalf("wrong password asking to act as another user must get the bad-credential reply %q whatever the master username suffix:\n  master username: %q\n  other suffix:    %q", badCredential, master, other)
		}
	})
}
