//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"encoding/base64"
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

// TestPOP3ProxyRejectsControlCharUsername covers L9: a NUL (or other control
// char) in the username would add an extra field to the authz\0authn\0pass
// master-SASL frame the proxy builds for the backend, so it is rejected at USER.
func TestPOP3ProxyRejectsControlCharUsername(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)
	proxy, err := pop3proxy.New(
		context.Background(), "localhost", proxyAddr, rdb,
		pop3proxy.POP3ProxyServerOptions{
			Name:          "test-nul",
			RemoteAddrs:   []string{"127.0.0.1:9999"},
			InsecureAuth:  true,
			MaxAuthErrors: 5,
		},
	)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}

	if _, err := conn.Write([]byte("USER a\x00b@example.com\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasPrefix(resp, "-ERR") {
		t.Fatalf("USER with a NUL must be rejected, got: %q", resp)
	}
}

// TestPOP3ProxyCAPAAdvertisesTransactionCaps pins the proxy's pre-auth CAPA
// set: the transaction-phase capabilities every backend honors
// (TOP/UIDL/PIPELINING) must be advertised, while UTF8 and LANG must NOT be.
// Classic Outlook reacts to a UTF8 advert by sending the command after PASS —
// through the raw relay a Dovecot backend answers "-ERR Unknown command:
// UTF8" and Outlook aborts the download with 0x800CCC90 (prod incident
// 2026-07-06). The commands themselves still work pre-auth (answered locally,
// UTF8 mirrored to the backend); only the advertisement is suppressed.
func TestPOP3ProxyCAPAAdvertisesTransactionCaps(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)

	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		rdb,
		pop3proxy.POP3ProxyServerOptions{
			Name:          "test-capa",
			RemoteAddrs:   []string{"127.0.0.1:9999"},
			InsecureAuth:  true,
			MaxAuthErrors: 5,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}
	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if _, err := reader.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting read failed: %v", err)
	}
	fmt.Fprintf(conn, "CAPA\r\n")
	status, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "+OK") {
		t.Fatalf("CAPA status: %q err=%v", status, err)
	}
	caps := map[string]bool{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CAPA list: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "." {
			break
		}
		caps[strings.ToUpper(line)] = true
	}
	for _, want := range []string{"TOP", "UIDL", "PIPELINING"} {
		if !caps[want] {
			t.Errorf("proxy CAPA missing %q; got %v", want, caps)
		}
	}
	// UTF8/LANG must stay hidden: advertising them makes classic Outlook send
	// UTF8 post-auth, which non-sora backends reject fatally (see test doc).
	for _, banned := range []string{"UTF8", "LANG"} {
		if caps[banned] {
			t.Errorf("proxy CAPA must not advertise %q (Outlook post-auth UTF8 incident); got %v", banned, caps)
		}
	}
}

// TestPOP3ProxyInsecureAuthAutoEnabledAUTH is the SASL AUTH counterpart to the
// PASS test above. It guards the H1 fix: the proxy AUTH handler now carries the
// same TLS gate as PASS, and both must honor the insecure_auth auto-enable so a
// plaintext listener still accepts AUTH PLAIN (the gate must not over-fire).
func TestPOP3ProxyInsecureAuthAutoEnabledAUTH(t *testing.T) {
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
			Name:               "test-insecure-auth-sasl",
			RemoteAddrs:        []string{"127.0.0.1:9999"},
			InsecureAuth:       false, // Explicitly false, but TLS not configured → auto-enabled
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

	// Send AUTH PLAIN with an inline initial response — should NOT be rejected
	// for TLS (auto-enabled when TLS not configured).
	authData := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	fmt.Fprintf(conn, "AUTH PLAIN %s\r\n", authData)
	authResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read AUTH response: %v", err)
	}

	if strings.Contains(authResp, "TLS") {
		t.Fatalf("InsecureAuth auto-enable failed: AUTH rejected with TLS requirement: %s", strings.TrimSpace(authResp))
	}

	// Other errors are expected (dummy backend); the point is it was not TLS-gated.
	t.Logf("✓ AUTH not rejected for TLS (insecureAuth auto-enabled): %s", strings.TrimSpace(authResp))
}
