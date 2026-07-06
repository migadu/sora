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
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// readLineWithDeadline reads one CRLF-terminated line with a deadline so a
// dropped command can never hang the test.
func readLineWithDeadline(t *testing.T, conn net.Conn, reader *bufio.Reader, what string) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading %s: %v", what, err)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestPOP3ProxyOutlookPostAuthUTF8 replays the exact classic-Outlook sequence
// from the 2026-07-06 prod incident: CAPA, USER, PASS, then UTF8 *after*
// authentication. Two properties are pinned:
//
//  1. The proxy's pre-auth CAPA must not advertise UTF8 (so a CAPA-driven
//     Outlook never sends the command against a backend that cannot honor
//     it — e.g. Dovecot, which answers "-ERR Unknown command: UTF8" and
//     makes Outlook abort the download with 0x800CCC90).
//  2. If a client sends post-auth UTF8 anyway, a sora backend must accept it
//     (+OK through the relay), Gmail-style, instead of the RFC-strict -ERR.
func TestPOP3ProxyOutlookPostAuthUTF8(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if line := readLineWithDeadline(t, conn, reader, "greeting"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("bad greeting: %q", line)
	}

	// CAPA: UTF8/LANG must not be advertised.
	fmt.Fprintf(conn, "CAPA\r\n")
	if line := readLineWithDeadline(t, conn, reader, "CAPA status"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("CAPA failed: %q", line)
	}
	for {
		line := readLineWithDeadline(t, conn, reader, "CAPA list")
		if line == "." {
			break
		}
		name := strings.ToUpper(strings.Fields(line)[0])
		if name == "UTF8" || name == "LANG" {
			t.Fatalf("proxy CAPA advertises %s — this re-triggers the Outlook post-auth UTF8 incident", name)
		}
	}

	// Outlook's sequence: USER, PASS, then UTF8 post-auth.
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if line := readLineWithDeadline(t, conn, reader, "USER response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER failed: %q", line)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if line := readLineWithDeadline(t, conn, reader, "PASS response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("PASS failed: %q", line)
	}

	// Post-auth UTF8 goes through the raw relay to the sora backend, which
	// must accept it (Outlook treats -ERR here as fatal).
	fmt.Fprintf(conn, "UTF8\r\n")
	if line := readLineWithDeadline(t, conn, reader, "post-auth UTF8 response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("post-auth UTF8 rejected (%q) — classic Outlook aborts the download on this", line)
	}

	// The session must remain fully usable.
	fmt.Fprintf(conn, "STAT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "STAT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STAT after UTF8 failed: %q", line)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "QUIT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("QUIT failed: %q", line)
	}
	t.Log("✓ Outlook post-auth UTF8 sequence completed successfully")
}

// TestPOP3ProxyPreAuthUTF8Mirror pins the RFC 6856 path: a blind pre-auth
// UTF8 (not advertised, but some clients probe) is answered +OK locally and
// mirrored to the backend before AUTH, and the session works normally after.
func TestPOP3ProxyPreAuthUTF8Mirror(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyWithPROXY(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if line := readLineWithDeadline(t, conn, reader, "greeting"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("bad greeting: %q", line)
	}

	fmt.Fprintf(conn, "UTF8\r\n")
	if line := readLineWithDeadline(t, conn, reader, "pre-auth UTF8 response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("pre-auth UTF8 must succeed even though unadvertised: %q", line)
	}

	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if line := readLineWithDeadline(t, conn, reader, "USER response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER failed: %q", line)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if line := readLineWithDeadline(t, conn, reader, "PASS response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("PASS after pre-auth UTF8 failed (mirror broke the backend handshake?): %q", line)
	}

	fmt.Fprintf(conn, "STAT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "STAT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STAT failed: %q", line)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "QUIT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("QUIT failed: %q", line)
	}
	t.Log("✓ pre-auth UTF8 mirrored and session healthy")
}

// setupPOP3ProxyUTF8Enabled mirrors setupPOP3ProxyWithPROXY but opts in to
// remote_use_utf8 — the all-sora-fleet configuration where UTF8/LANG are
// advertised and the pre-auth UTF8 is mirrored to pool backends.
func setupPOP3ProxyUTF8Enabled(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string) *common.TestServer {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-proxy-utf8",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		RemoteUseUTF8:          true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := pop3proxy.New(context.Background(), "test-proxy-utf8", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create UTF8-enabled POP3 proxy: %v", err)
	}
	go func() { _ = proxy.Start() }()
	time.Sleep(200 * time.Millisecond)

	wrapper := &POP3ProxyWrapper{proxy: proxy, addr: proxyAddr, rdb: rdb}
	ts := &common.TestServer{Address: proxyAddr, Server: wrapper, ResilientDB: rdb}
	ts.SetCleanup(func() { wrapper.Stop() })
	return ts
}

// TestPOP3ProxyUTF8EnabledFleet pins the opt-in path (remote_use_utf8 = true,
// only valid when every backend is sora): UTF8/LANG are advertised again, a
// pre-auth UTF8 is mirrored to the backend, and the full RFC 6856 flow works.
func TestPOP3ProxyUTF8EnabledFleet(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			if strings.Contains(fmt.Sprintf("%v", r), "WaitGroup") {
				t.Log("Ignoring WaitGroup race condition during test cleanup")
				return
			}
			panic(r)
		}
	}()

	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyUTF8Enabled(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address})
	defer proxy.Close()

	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		t.Fatalf("Failed to dial POP3 proxy: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	if line := readLineWithDeadline(t, conn, reader, "greeting"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("bad greeting: %q", line)
	}

	// With remote_use_utf8 enabled the caps are advertised again.
	fmt.Fprintf(conn, "CAPA\r\n")
	if line := readLineWithDeadline(t, conn, reader, "CAPA status"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("CAPA failed: %q", line)
	}
	seen := map[string]bool{}
	for {
		line := readLineWithDeadline(t, conn, reader, "CAPA list")
		if line == "." {
			break
		}
		seen[strings.ToUpper(strings.Fields(line)[0])] = true
	}
	for _, want := range []string{"UTF8", "LANG"} {
		if !seen[want] {
			t.Fatalf("remote_use_utf8=true must advertise %s; got %v", want, seen)
		}
	}

	// RFC 6856 flow: UTF8 pre-auth (mirrored to the sora backend), then login.
	fmt.Fprintf(conn, "UTF8\r\n")
	if line := readLineWithDeadline(t, conn, reader, "pre-auth UTF8 response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("pre-auth UTF8 failed: %q", line)
	}
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if line := readLineWithDeadline(t, conn, reader, "USER response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("USER failed: %q", line)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if line := readLineWithDeadline(t, conn, reader, "PASS response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("PASS failed (UTF8 mirror broke backend handshake?): %q", line)
	}
	fmt.Fprintf(conn, "STAT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "STAT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("STAT failed: %q", line)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if line := readLineWithDeadline(t, conn, reader, "QUIT response"); !strings.HasPrefix(line, "+OK") {
		t.Fatalf("QUIT failed: %q", line)
	}
	t.Log("✓ UTF8-enabled fleet: advertised, negotiated, mirrored")
}
