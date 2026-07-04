//go:build integration

package pop3_test

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
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// TestPOP3ImplicitTLS covers the implicit-TLS (POP3S) listener end to end:
// the greeting must arrive over a completed TLS session (the SoraTLSListener
// defers the handshake, so the server must trigger it before any write — a
// regression here sends the greeting in plaintext and breaks every TLS
// client), authentication must be permitted without insecure_auth (the
// library must see the connection as TLS), and CAPA must not advertise STLS
// on an already-TLS connection.
func TestPOP3ImplicitTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	server, err := pop3.New(
		context.Background(),
		"test-tls",
		"localhost",
		addr,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			TLS:          true,
			TLSCertFile:  certFile,
			TLSKeyFile:   keyFile,
			InsecureAuth: false, // auth must still work: the connection IS TLS
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with TLS: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { server.Start(errChan) }()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	// Phase 1: a plaintext client on the TLS port must never receive the
	// plaintext greeting (this is the regression assertion).
	rawConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial raw TCP: %v", err)
	}
	fmt.Fprintf(rawConn, "USER %s\r\n", account.Email)
	rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, _ := rawConn.Read(buf)
	if leaked := string(buf[:n]); strings.Contains(leaked, "+OK") {
		t.Fatalf("plaintext greeting leaked on TLS port: %q", leaked)
	}
	rawConn.Close()

	// Phase 2: a TLS client gets the greeting over TLS and can authenticate.
	// Full verification: the ephemeral cert covers 127.0.0.1, so no
	// InsecureSkipVerify — chain and host are checked for real.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{RootCAs: certPool})
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting over TLS: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Unexpected greeting: %q", greeting)
	}

	// CAPA over implicit TLS: auth capabilities present, STLS absent.
	fmt.Fprintf(conn, "CAPA\r\n")
	capaResp, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(capaResp, "+OK") {
		t.Fatalf("CAPA failed: %q, %v", capaResp, err)
	}
	var caps []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed reading CAPA list: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "." {
			break
		}
		caps = append(caps, line)
	}
	capaAll := strings.Join(caps, "\n")
	if !strings.Contains(capaAll, "USER") {
		t.Errorf("CAPA over TLS must advertise USER (auth allowed), got:\n%s", capaAll)
	}
	if !strings.Contains(capaAll, "SASL") {
		t.Errorf("CAPA over TLS must advertise SASL (auth allowed), got:\n%s", capaAll)
	}
	if strings.Contains(capaAll, "STLS") {
		t.Errorf("CAPA must not advertise STLS on an implicit-TLS connection, got:\n%s", capaAll)
	}

	// Full USER/PASS authentication with insecure_auth disabled.
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER over TLS failed: %q", resp)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS over TLS failed: %q", resp)
	}
	fmt.Fprintf(conn, "STAT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT over TLS failed: %q", resp)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT over TLS failed: %q", resp)
	}
}

// TestPOP3ImplicitTLSWithProxyProtocol covers the PROXY protocol + implicit
// TLS combination: the PROXY header is read from the raw stream first, then
// the TLS handshake runs over the remaining bytes — including the case where
// the client coalesces the header and the ClientHello into one segment.
func TestPOP3ImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	server, err := pop3.New(
		context.Background(),
		"test-tls-proxy",
		"localhost",
		addr,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			TLS:                  true,
			TLSCertFile:          certFile,
			TLSKeyFile:           keyFile,
			InsecureAuth:         false,
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server with TLS+PROXY: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { server.Start(errChan) }()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 995\r\n"

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
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := conn.Handshake(); err != nil {
			t.Fatalf("TLS handshake behind PROXY header failed (coalesced=%v): %v", coalesced, err)
		}
		reader := bufio.NewReader(conn)

		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("greeting: %q, %v", resp, err)
		}
		fmt.Fprintf(conn, "USER %s\r\n", account.Email)
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("USER failed: %q", resp)
		}
		fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("PASS failed: %q", resp)
		}
		fmt.Fprintf(conn, "QUIT\r\n")
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("QUIT failed: %q", resp)
		}
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })
}
