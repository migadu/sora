//go:build integration

package lmtp_test

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
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// readSMTPResponse reads one (possibly multiline) SMTP-style response and
// returns the final line (the one without a dash after the code).
func readSMTPResponse(t *testing.T, reader *bufio.Reader, what string) string {
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

// TestLMTPImplicitTLSWithProxyProtocol covers the PROXY protocol + implicit
// TLS combination on the LMTP backend. Unlike the other protocols, LMTP uses
// crypto/tls's eager listener (no deferred handshake): before the
// listener-composition fix the PROXY reader sat OUTSIDE the TLS conn, so its
// first read triggered the server-side handshake against the plaintext
// "PROXY ..." line and every connection failed (Shape B). With the PROXY
// listener inside, crypto/tls handshakes lazily through the PROXY conn —
// including when the client coalesces the header and ClientHello into one
// segment. STARTTLS mode is unaffected by the fix.
func TestLMTPImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	addr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	tempDir, err := os.MkdirTemp("", "lmtp-tls-proxy-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	s3Storage := &storage.S3Storage{}
	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,         // path
		10,              // batchSize
		2,               // concurrency
		3,               // maxAttempts
		5*time.Second,   // retryInterval
		0,               // maxStagingSize
		"test-instance", // instanceID
		rdb,             // database
		s3Storage,       // s3
		nil,             // cache
		errCh,           // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	server, err := lmtp.New(
		context.Background(),
		"test-tls-proxyproto",
		"localhost",
		addr,
		s3Storage,
		rdb,
		uploadWorker,
		lmtp.LMTPServerOptions{
			TLS:                  true,
			TLSCertFile:          certFile,
			TLSKeyFile:           keyFile,
			TLSUseStartTLS:       false, // implicit TLS listener
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server with TLS+PROXY: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { server.Start(errChan) }()
	defer server.Close()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 24\r\n"

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

		if resp := readSMTPResponse(t, reader, "greeting"); !strings.HasPrefix(resp, "220") {
			t.Fatalf("Unexpected greeting: %q", resp)
		}

		fmt.Fprintf(conn, "LHLO client.example.com\r\n")
		if resp := readSMTPResponse(t, reader, "LHLO response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("LHLO over TLS+PROXY failed: %q", resp)
		}

		// A MAIL/RCPT round-trip proves the session is fully functional over
		// the TLS+PROXY composition (RCPT resolves the account in the DB).
		fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
		if resp := readSMTPResponse(t, reader, "MAIL response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("MAIL FROM over TLS+PROXY failed: %q", resp)
		}
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", account.Email)
		if resp := readSMTPResponse(t, reader, "RCPT response"); !strings.HasPrefix(resp, "250") {
			t.Fatalf("RCPT TO over TLS+PROXY failed: %q", resp)
		}

		fmt.Fprintf(conn, "QUIT\r\n")
		if resp := readSMTPResponse(t, reader, "QUIT response"); !strings.HasPrefix(resp, "221") {
			t.Fatalf("QUIT failed: %q", resp)
		}
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })

	// Regression assertion: a plaintext client that completes the PROXY
	// exchange but never starts TLS must not receive the LMTP greeting in
	// plaintext.
	t.Run("plaintext after PROXY header must not leak greeting", func(t *testing.T) {
		raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
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
