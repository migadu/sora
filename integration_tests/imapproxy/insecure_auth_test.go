//go:build integration

package imapproxy_test

import (
	"context"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyInsecureAuthAutoEnabled tests that when TLS is not configured,
// InsecureAuth is automatically enabled regardless of the setting.
func TestIMAPProxyInsecureAuthAutoEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	proxyAddr := common.GetRandomAddress(t)

	proxy, err := imapproxy.New(
		context.Background(),
		rdb,
		"localhost",
		imapproxy.ServerOptions{
			Name:               "test-insecure-auth",
			Addr:               proxyAddr,
			RemoteAddrs:        []string{"127.0.0.1:9999"},
			InsecureAuth:       false, // Explicitly false, but TLS not configured
			MasterSASLUsername: "master",
			MasterSASLPassword: "master",
			MaxAuthErrors:      5,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	c, err := imapclient.DialInsecure(proxyAddr, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	// LOGIN should succeed because TLS is not configured → insecureAuth auto-enabled
	// (Will fail at backend connection, but should NOT fail at auth rejection)
	err = c.Login(account.Email, account.Password).Wait()
	if err != nil {
		errStr := err.Error()
		// If it fails with PRIVACYREQUIRED, the auto-enable didn't work
		if stringContainsProxy(errStr, "PRIVACYREQUIRED") || stringContainsProxy(errStr, "requires TLS") {
			t.Fatalf("InsecureAuth auto-enable failed: LOGIN rejected with TLS requirement even though TLS is not configured: %v", err)
		}
		// Other errors (e.g., backend unavailable) are expected since we use a dummy backend
		t.Logf("✓ LOGIN was not rejected for TLS (failed for other reason as expected): %v", err)
	} else {
		t.Log("✓ LOGIN succeeded (insecureAuth auto-enabled)")
	}
}

func stringContainsProxy(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
