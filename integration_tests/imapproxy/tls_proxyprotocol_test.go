//go:build integration

package imapproxy_test

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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyImplicitTLSWithProxyProtocol covers PROXY protocol + implicit
// TLS on the IMAP proxy: the PROXY header is read from the raw stream first,
// then the deferred TLS handshake runs over the remaining bytes — including
// the case where the client coalesces the header and the ClientHello into one
// segment — and a full login relays to the backend. Before the
// listener-composition fix, newSession read the PROXY header through the
// SoraTLSConn and the handshake assertion then failed silently, sending the
// greeting in plaintext.
func TestIMAPProxyImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend with master SASL credentials and PROXY protocol for the
	// proxy's backend leg.
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	hostname := "test-proxy-tls-proxyproto"

	opts := imapproxy.ServerOptions{
		Name:                   hostname,
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    true,
		TLSCertFile:            certFile,
		TLSKeyFile:             keyFile,
		InsecureAuth:           false, // auth must still work: the connection IS TLS
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		// The IMAP proxy's PROXY-protocol reader trusts TrustedNetworks.
		TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy with TLS+PROXY: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 993\r\n"

	run := func(t *testing.T, coalesced bool) {
		raw, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
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

		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting over TLS: %v", err)
		}
		if !strings.HasPrefix(greeting, "* OK") {
			t.Fatalf("Unexpected greeting: %q", greeting)
		}

		// Full LOGIN: proxy authenticates locally, connects to the backend
		// with master SASL, and switches to the relay.
		fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading LOGIN response: %v", err)
			}
			if strings.HasPrefix(line, "a1 ") {
				if !strings.HasPrefix(line, "a1 OK") {
					t.Fatalf("LOGIN over TLS+PROXY failed: %q", strings.TrimSpace(line))
				}
				break
			}
		}

		// A post-auth command exercises the raw relay to the backend.
		fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("reading SELECT response: %v", err)
			}
			if strings.HasPrefix(line, "a2 ") {
				if !strings.HasPrefix(line, "a2 OK") {
					t.Fatalf("SELECT through relay failed: %q", strings.TrimSpace(line))
				}
				break
			}
		}
		fmt.Fprintf(conn, "a3 LOGOUT\r\n")
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })

	// Regression assertion: a plaintext client that completes the PROXY
	// exchange but never starts TLS must not receive the IMAP greeting in
	// plaintext (the pre-fix failure mode was a silently skipped handshake
	// followed by a plaintext "* OK").
	t.Run("plaintext after PROXY header must not leak greeting", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", proxyAddress, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer raw.Close()
		if _, err := raw.Write([]byte(header)); err != nil {
			t.Fatalf("Failed to write PROXY header: %v", err)
		}
		fmt.Fprintf(raw, "a1 CAPABILITY\r\n")
		raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := raw.Read(buf)
		if leaked := string(buf[:n]); strings.Contains(leaked, "* OK") {
			t.Fatalf("plaintext greeting leaked on TLS+PROXY port: %q", leaked)
		}
	})
}
