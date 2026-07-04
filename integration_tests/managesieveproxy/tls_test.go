//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// readUntilOK reads greeting/response lines until an OK/NO/BYE line arrives.
func readUntilOK(t *testing.T, reader *bufio.Reader, what string) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading %s: %v", what, err)
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "OK") || strings.HasPrefix(trimmed, "NO") || strings.HasPrefix(trimmed, "BYE") {
			return trimmed
		}
	}
}

// TestManageSieveProxyImplicitTLSWithProxyProtocol covers PROXY protocol +
// implicit TLS on the ManageSieve proxy: the PROXY header is read from the
// raw stream first, then the deferred TLS handshake runs over the remaining
// bytes — including the case where the client coalesces the header and the
// ClientHello into one segment — and a full authentication relays to the
// backend. Before the listener-composition fix, the accept loop read the
// PROXY header through the SoraTLSConn and the handshake assertion then
// failed silently, sending the capability greeting in plaintext.
func TestManageSieveProxyImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend with master SASL credentials for the proxy's backend leg.
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	hostname := "test-sieve-proxy-tls-proxyproto"

	opts := managesieveproxy.ServerOptions{
		Name:               hostname,
		Addr:               proxyAddr,
		RemoteAddrs:        []string{backendServer.Address},
		RemotePort:         4190,
		MasterSASLUsername: "master_sasl",
		MasterSASLPassword: "master_sasl_secret",
		TLS:                true,
		TLSUseStartTLS:     false, // implicit TLS listener
		TLSCertFile:        certFile,
		TLSKeyFile:         keyFile,
		InsecureAuth:       false, // auth must still work: the connection IS TLS
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		ProxyProtocol:        true,
		ProxyProtocolTimeout: "5s",
		// The ManageSieve proxy's PROXY-protocol reader trusts TrustedNetworks.
		TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := managesieveproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy with TLS+PROXY: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 4190\r\n"

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

		// Capability greeting ends with OK.
		if resp := readUntilOK(t, reader, "greeting"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("Unexpected greeting completion: %q", resp)
		}

		// Full AUTHENTICATE PLAIN: the proxy authenticates locally, connects
		// to the backend with master SASL, and switches to the relay.
		creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds)
		if resp := readUntilOK(t, reader, "AUTHENTICATE response"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("AUTHENTICATE over TLS+PROXY failed: %q", resp)
		}

		// A post-auth command exercises the relay to the backend.
		fmt.Fprintf(conn, "LISTSCRIPTS\r\n")
		if resp := readUntilOK(t, reader, "LISTSCRIPTS response"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("LISTSCRIPTS through relay failed: %q", resp)
		}

		fmt.Fprintf(conn, "LOGOUT\r\n")
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })

	// Regression assertion: a plaintext client that completes the PROXY
	// exchange but never starts TLS must not receive the capability greeting
	// in plaintext (the pre-fix failure mode was a silently skipped handshake
	// followed by plaintext capabilities).
	t.Run("plaintext after PROXY header must not leak greeting", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer raw.Close()
		if _, err := raw.Write([]byte(header)); err != nil {
			t.Fatalf("Failed to write PROXY header: %v", err)
		}
		fmt.Fprintf(raw, "CAPABILITY\r\n")
		raw.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		n, _ := raw.Read(buf)
		if leaked := string(buf[:n]); strings.Contains(leaked, "IMPLEMENTATION") {
			t.Fatalf("plaintext greeting leaked on TLS+PROXY port: %q", leaked)
		}
	})
}
