//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyInsecureAuthAutoEnabled tests that when TLS is not configured,
// InsecureAuth is automatically enabled regardless of the setting.
func TestPOP3ProxyInsecureAuthAutoEnabled(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	proxyAddr := common.GetRandomAddress(t)

	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		rdb,
		pop3proxy.POP3ProxyServerOptions{
			Name:               "test-insecure-auth",
			RemoteAddrs:        []string{"127.0.0.1:9999"},
			InsecureAuth:       false, // Explicitly false, but TLS not configured
			MasterSASLUsername: "master",
			MasterSASLPassword: "master",
			MaxAuthErrors:      5,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		proxy.Start()
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Unexpected greeting: %s", greeting)
	}

	// Send USER
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	userResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read USER response: %v", err)
	}
	if !strings.HasPrefix(userResp, "+OK") {
		t.Fatalf("USER should succeed, got: %s", userResp)
	}

	// Send PASS — should NOT be rejected for TLS (auto-enabled when TLS not configured)
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	passResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read PASS response: %v", err)
	}

	if strings.Contains(passResp, "TLS") {
		t.Fatalf("InsecureAuth auto-enable failed: PASS rejected with TLS requirement: %s", strings.TrimSpace(passResp))
	}

	// Other errors are expected (dummy backend)
	t.Logf("✓ PASS not rejected for TLS (insecureAuth auto-enabled): %s", strings.TrimSpace(passResp))
}
