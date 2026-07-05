//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// readTaggedResponse reads lines until the response for the given tag arrives.
func readTaggedResponse(t *testing.T, reader *bufio.Reader, tag string) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading response for %s: %v", tag, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			return strings.TrimSpace(line)
		}
	}
}

// TestIMAPImplicitTLSWithProxyProtocol covers the PROXY protocol + implicit
// TLS combination on the IMAP backend: the PROXY header is read from the raw
// stream first, then the deferred TLS handshake runs over the remaining bytes
// — including the case where the client coalesces the header and the
// ClientHello into one segment. Before the listener-composition fix the
// handshake was silently skipped (the PROXY wrapper hid the SoraTLSConn from
// the type assertion) and the greeting went out in plaintext.
func TestIMAPImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-tlsproxy-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		0,                    // maxStagingSize
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imap.New(
		context.Background(),
		"test-tls-proxyproto",
		"localhost",
		addr,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imap.IMAPServerOptions{
			TLS:                  true,
			TLSCertFile:          certFile,
			TLSKeyFile:           keyFile,
			InsecureAuth:         false, // auth must still work: the connection IS TLS
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server with TLS+PROXY: %v", err)
	}

	go func() {
		if err := server.Serve(addr); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server error: %v", err)
		}
	}()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 993\r\n"

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

		greeting, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read greeting over TLS: %v", err)
		}
		if !strings.HasPrefix(greeting, "* OK") {
			t.Fatalf("Unexpected greeting: %q", greeting)
		}

		// Full LOGIN with insecure_auth disabled: the server must see the
		// session as TLS even under the PROXY wrapper.
		fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password)
		if resp := readTaggedResponse(t, reader, "a1"); !strings.HasPrefix(resp, "a1 OK") {
			t.Fatalf("LOGIN over TLS+PROXY failed: %q", resp)
		}
		fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
		if resp := readTaggedResponse(t, reader, "a2"); !strings.HasPrefix(resp, "a2 OK") {
			t.Fatalf("SELECT over TLS+PROXY failed: %q", resp)
		}
		fmt.Fprintf(conn, "a3 LOGOUT\r\n")
		if resp := readTaggedResponse(t, reader, "a3"); !strings.HasPrefix(resp, "a3 OK") {
			t.Fatalf("LOGOUT failed: %q", resp)
		}
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })

	// Regression assertion: a plaintext client that completes the PROXY
	// exchange but never starts TLS must not receive the IMAP greeting in
	// plaintext (the pre-fix failure mode was a silently skipped handshake
	// followed by a plaintext "* OK").
	t.Run("plaintext after PROXY header must not leak greeting", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
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

// TestIMAPTLSSlowClientNoAcceptBlocking pins the IMAP-specific accept-path
// fix: the deferred TLS handshake runs in go-imap's per-connection goroutine
// (newSession), NOT in connectionLimitingListener.Accept. Before the fix a
// single client that connected and never sent its ClientHello held the
// accept loop for the full handshake deadline (~10s), stalling every other
// client — the same serial-accept collapse class as the 2026-07-05 incident.
// With the fix, a well-behaved TLS client logs in immediately while the
// silent one is still burning its handshake deadline.
func TestIMAPTLSSlowClientNoAcceptBlocking(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	tempDir, err := os.MkdirTemp("", "sora-test-upload-tls-slow-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir, 10, 1, 3, time.Second, 0, "test-instance",
		rdb, &storage.S3Storage{}, nil, errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := imap.New(
		context.Background(),
		"test-tls-slow-client",
		"localhost",
		addr,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil,
		imap.IMAPServerOptions{
			TLS:          true,
			TLSCertFile:  certFile,
			TLSKeyFile:   keyFile,
			InsecureAuth: false,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server with TLS: %v", err)
	}
	go func() {
		if err := server.Serve(addr); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server error: %v", err)
		}
	}()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	// Slow client: TCP connect, never send a ClientHello. Its handshake
	// burns the 10s deadline in its own goroutine.
	slow, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("slow dial failed: %v", err)
	}
	defer slow.Close()
	time.Sleep(200 * time.Millisecond) // let the server accept it and park in the handshake

	// Well-behaved client: full TLS login must complete promptly.
	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{RootCAs: certPool})
	if err != nil {
		t.Fatalf("TLS dial while slow client pending failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)

	if greeting, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "* OK") {
		t.Fatalf("greeting while slow client pending: %q, %v", greeting, err)
	}
	fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password)
	if resp := readTaggedResponse(t, reader, "a1"); !strings.HasPrefix(resp, "a1 OK") {
		t.Fatalf("LOGIN while slow client pending failed: %q", resp)
	}
	elapsed := time.Since(start)
	fmt.Fprintf(conn, "a2 LOGOUT\r\n")

	// Pre-fix the slow client held the accept loop for its ~10s handshake
	// deadline; post-fix the good client is untouched by it.
	if elapsed > 5*time.Second {
		t.Errorf("TLS login took %v while a silent client was pending; handshake is back in the accept path", elapsed)
	}
	t.Logf("✓ full TLS login in %v while a silent TLS client was mid-handshake", elapsed)
}
