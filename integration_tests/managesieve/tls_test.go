//go:build integration

package managesieve_test

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
	"github.com/migadu/sora/server/managesieve"
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

// TestManageSieveImplicitTLSWithProxyProtocol covers the PROXY protocol +
// implicit TLS combination on the ManageSieve backend: the PROXY header is
// read from the raw stream first, then the deferred TLS handshake runs over
// the remaining bytes — including the case where the client coalesces the
// header and the ClientHello into one segment. Before the
// listener-composition fix the handshake was silently skipped (the PROXY
// wrapper hid the SoraTLSConn from the type assertion) and the capability
// greeting went out in plaintext. STARTTLS mode is unaffected by the fix.
func TestManageSieveImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	server, err := managesieve.New(
		context.Background(),
		"test-tls-proxyproto",
		"localhost",
		addr,
		rdb,
		managesieve.ManageSieveServerOptions{
			TLS:                  true,
			TLSCertFile:          certFile,
			TLSKeyFile:           keyFile,
			TLSUseStartTLS:       false, // implicit TLS listener
			InsecureAuth:         false, // auth must still work: the connection IS TLS
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server with TLS+PROXY: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { server.Start(errChan) }()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 4190\r\n"

	run := func(t *testing.T, coalesced bool) {
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
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

		// Full AUTHENTICATE PLAIN with insecure_auth disabled: the server must
		// see the session as TLS even under the PROXY wrapper.
		creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds)
		if resp := readUntilOK(t, reader, "AUTHENTICATE response"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("AUTHENTICATE over TLS+PROXY failed: %q", resp)
		}

		fmt.Fprintf(conn, "LISTSCRIPTS\r\n")
		if resp := readUntilOK(t, reader, "LISTSCRIPTS response"); !strings.HasPrefix(resp, "OK") {
			t.Fatalf("LISTSCRIPTS over TLS+PROXY failed: %q", resp)
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
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
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
