//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
)

// readTLSTestResponse reads one (possibly multiline) SMTP-style response and
// returns the final line (the one without a dash after the code).
func readTLSTestResponse(t *testing.T, reader *bufio.Reader, what string) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading %s: %v", what, err)
		}
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 4 && trimmed[3] == '-' {
			continue // multiline continuation
		}
		return trimmed
	}
}

// TestLMTPProxyImplicitTLSWithProxyProtocol covers PROXY protocol + implicit
// TLS on the LMTP proxy: the PROXY header is read from the raw stream first,
// then the deferred TLS handshake runs over the remaining bytes — including
// the case where the client coalesces the header and the ClientHello into one
// segment. Before the listener-composition fix, the accept loop read the
// PROXY header through the SoraTLSConn and the handshake assertion then
// failed silently, sending the greeting in plaintext.
func TestLMTPProxyImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend with PROXY protocol support for the proxy's backend leg.
	backendServer, account := common.SetupLMTPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	proxy, err := lmtpproxy.New(
		context.Background(),
		backendServer.ResilientDB,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-lmtp-proxy-tls-proxyproto",
			Addr:                   proxyAddr,
			RemoteAddrs:            []string{backendServer.Address},
			RemotePort:             24,
			RemoteUseProxyProtocol: true,
			ConnectTimeout:         10 * time.Second,
			AuthIdleTimeout:        30 * time.Second,
			TLS:                    true,
			TLSUseStartTLS:         false, // implicit TLS listener
			TLSCertFile:            certFile,
			TLSKeyFile:             keyFile,
			ProxyProtocol:          true,
			ProxyProtocolTimeout:   "5s",
			// The LMTP proxy's PROXY-protocol reader trusts TrustedProxies,
			// which also gates which peers may connect at all.
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy with TLS+PROXY: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 24\r\n"

	run := func(t *testing.T, coalesced bool) {
		raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer raw.Close()

		var tlsBase net.Conn = raw
		if coalesced {
			tlsBase = common.NewPrefixConn(raw, []byte(header))
		} else {
			if _, err := raw.Write([]byte(header)); err != nil {
				t.Fatalf("Failed to write PROXY header: %v", err)
			}
			time.Sleep(50 * time.Millisecond) // let the header travel alone
		}

		// tls.Client (unlike tls.Dial) does not infer ServerName; set it so
		// verification against the ephemeral cert's IP SAN is exercised.
		conn := tls.Client(tlsBase, &tls.Config{RootCAs: certPool, ServerName: "127.0.0.1"})
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := conn.Handshake(); err != nil {
			t.Fatalf("TLS handshake behind PROXY header failed (coalesced=%v): %v", coalesced, err)
		}
		reader := bufio.NewReader(conn)

		if resp := readTLSTestResponse(t, reader, "greeting"); !strings.HasPrefix(resp, "220") {
			t.Fatalf("Unexpected greeting: %q", resp)
		}

		fmt.Fprintf(conn, "LHLO client.example.com\r\n")
		if resp := readTLSTestResponse(t, reader, "LHLO response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("LHLO over TLS+PROXY failed: %q", resp)
		}

		// MAIL/RCPT drives the proxy's routing lookup and backend connection,
		// proving the whole session works over the TLS+PROXY composition.
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		if resp := readTLSTestResponse(t, reader, "MAIL response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("MAIL FROM over TLS+PROXY failed: %q", resp)
		}
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", account.Email)
		if resp := readTLSTestResponse(t, reader, "RCPT response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("RCPT TO through proxy failed: %q", resp)
		}

		fmt.Fprintf(conn, "QUIT\r\n")
		if resp := readTLSTestResponse(t, reader, "QUIT response"); !strings.HasPrefix(resp, "221") {
			t.Fatalf("QUIT failed: %q", resp)
		}
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })

	// Regression assertion: a plaintext client that completes the PROXY
	// exchange but never starts TLS must not receive the LMTP greeting in
	// plaintext (the pre-fix failure mode was a silently skipped handshake
	// followed by a plaintext "220").
	t.Run("plaintext after PROXY header must not leak greeting", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer raw.Close()
		if _, err := raw.Write([]byte(header)); err != nil {
			t.Fatalf("Failed to write PROXY header: %v", err)
		}
		fmt.Fprintf(raw, "LHLO client.example.com\r\n")
		raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := raw.Read(buf)
		if leaked := string(buf[:n]); strings.Contains(leaked, "220") {
			t.Fatalf("plaintext greeting leaked on TLS+PROXY port: %q", leaked)
		}
	})
}
