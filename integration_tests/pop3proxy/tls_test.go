//go:build integration

package pop3proxy_test

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
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/storage"
)

// TestPOP3ProxyImplicitTLS covers the proxy's implicit-TLS listener end to
// end: the greeting must arrive over a completed TLS session (the
// SoraTLSListener defers the handshake, so the proxy must trigger it before
// any write — a regression here sends the greeting in plaintext and breaks
// every TLS client), authentication must be permitted without insecure_auth,
// CAPA must not advertise STLS, and a full login must relay to the backend.
func TestPOP3ProxyImplicitTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend with master SASL credentials for the proxy's backend leg.
	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		backend.ResilientDB,
		pop3proxy.POP3ProxyServerOptions{
			Name:               "test-proxy-tls",
			RemoteAddrs:        []string{backend.Address},
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
			TLS:                true,
			TLSCertFile:        certFile,
			TLSKeyFile:         keyFile,
			InsecureAuth:       false, // auth must still work: the connection IS TLS
			ConnectTimeout:     10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with TLS: %v", err)
	}

	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	// Phase 1: a plaintext client on the TLS port must never receive the
	// plaintext greeting (this is the regression assertion).
	rawConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
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

	// Phase 2: a TLS client authenticates through the proxy to the backend.
	// Full verification: the ephemeral cert covers 127.0.0.1.
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyAddr,
		&tls.Config{RootCAs: certPool})
	if err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)

	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read greeting over TLS: %v", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("Unexpected greeting: %q", greeting)
	}

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
	if strings.Contains(capaAll, "STLS") {
		t.Errorf("CAPA must not advertise STLS on an implicit-TLS connection, got:\n%s", capaAll)
	}

	// Full login: proxy authenticates locally, then re-authenticates to the
	// backend with master SASL and switches to the relay.
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER over TLS failed: %q", resp)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS over TLS failed: %q", resp)
	}

	// A post-auth command exercises the raw relay to the backend.
	fmt.Fprintf(conn, "STAT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT through relay failed: %q", resp)
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT through relay failed: %q", resp)
	}
}

// TestPOP3ProxyRemoteTLS proves the proxy↔backend leg over TLS: the client
// connects to the proxy over implicit TLS, the proxy authenticates against a
// TLS-only backend (its AUTH PLAIN master-SASL exchange and the whole relay
// run inside the backend TLS session), and post-auth commands round-trip
// through both encrypted legs.
func TestPOP3ProxyRemoteTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	backendAddr := common.GetRandomAddress(t)
	backendCert, backendKey, _ := common.GenerateTestTLSCert(t, nil, nil)

	backend, err := pop3.New(
		context.Background(),
		"test-backend-tls",
		"localhost",
		backendAddr,
		&storage.S3Storage{},
		rdb,
		nil, // uploader.UploadWorker
		nil, // cache.Cache
		pop3.POP3ServerOptions{
			TLS:                true,
			TLSCertFile:        backendCert,
			TLSKeyFile:         backendKey,
			InsecureAuth:       false, // auth only because the backend leg IS TLS
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
		},
	)
	if err != nil {
		t.Fatalf("Failed to create TLS backend: %v", err)
	}
	backendErrChan := make(chan error, 1)
	go func() { backend.Start(backendErrChan) }()
	defer backend.Close()
	time.Sleep(200 * time.Millisecond)

	proxyAddr := common.GetRandomAddress(t)
	proxyCert, proxyKey, proxyPool := common.GenerateTestTLSCert(t, nil, nil)
	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		rdb,
		pop3proxy.POP3ProxyServerOptions{
			Name:               "test-proxy-remote-tls",
			RemoteAddrs:        []string{backendAddr},
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
			TLS:                true,
			TLSCertFile:        proxyCert,
			TLSKeyFile:         proxyKey,
			InsecureAuth:       false,
			RemoteTLS:          true,  // backend leg over TLS
			RemoteTLSVerify:    false, // the verify-off variant deployments commonly run; see TestPOP3ProxyRemoteTLSVerified for verify-on
			ConnectTimeout:     10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create proxy with RemoteTLS: %v", err)
	}
	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyAddr,
		&tls.Config{RootCAs: proxyPool})
	if err != nil {
		t.Fatalf("TLS handshake to proxy failed: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)

	if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("greeting: %q, %v", resp, err)
	}
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER failed: %q", resp)
	}
	// PASS drives the whole chain: local auth, TLS connect to the backend,
	// master-SASL AUTH PLAIN inside that TLS session, then the relay switch.
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS through TLS backend leg failed: %q", resp)
	}
	fmt.Fprintf(conn, "STAT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT through double-TLS relay failed: %q", resp)
	}
	fmt.Fprintf(conn, "UIDL\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("UIDL through double-TLS relay failed: %q", resp)
	}
	for { // drain UIDL multiline
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("reading UIDL list: %v", err)
		}
		if strings.TrimSpace(line) == "." {
			break
		}
	}
	fmt.Fprintf(conn, "QUIT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("QUIT failed: %q", resp)
	}
}

// TestPOP3ProxyRemoteTLSVerified proves the backend leg with certificate
// verification ENABLED (remote_tls_verify=true + remote_tls_ca_file):
//   - a backend certificate valid for the dialed host verifies and the full
//     login chain works;
//   - a certificate with a valid chain but the WRONG identity is rejected by
//     the ServerName pinning (the proxy dials 127.0.0.1, the cert says
//     wrong.example.com), so authentication must fail with a backend error.
//
// The negative case is the one that proves verification actually runs: with
// InsecureSkipVerify (or a missing ServerName) it would pass.
func TestPOP3ProxyRemoteTLSVerified(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	run := func(t *testing.T, backendCert, backendKey string, wantAuthSuccess bool) {
		rdb := common.SetupTestDatabase(t)
		account := common.CreateTestAccount(t, rdb)
		backendAddr := common.GetRandomAddress(t)

		backend, err := pop3.New(
			context.Background(),
			"test-backend-tls-verified",
			"localhost",
			backendAddr,
			&storage.S3Storage{},
			rdb,
			nil, // uploader.UploadWorker
			nil, // cache.Cache
			pop3.POP3ServerOptions{
				TLS:                true,
				TLSCertFile:        backendCert,
				TLSKeyFile:         backendKey,
				InsecureAuth:       false,
				MasterSASLUsername: "proxyuser",
				MasterSASLPassword: "proxypass",
			},
		)
		if err != nil {
			t.Fatalf("Failed to create TLS backend: %v", err)
		}
		backendErrChan := make(chan error, 1)
		go func() { backend.Start(backendErrChan) }()
		defer backend.Close()
		time.Sleep(200 * time.Millisecond)

		proxyAddr := common.GetRandomAddress(t)
		proxyCert, proxyKey, proxyPool := common.GenerateTestTLSCert(t, nil, nil)
		proxy, err := pop3proxy.New(
			context.Background(),
			"localhost",
			proxyAddr,
			rdb,
			pop3proxy.POP3ProxyServerOptions{
				Name:               "test-proxy-remote-tls-verified",
				RemoteAddrs:        []string{backendAddr},
				MasterSASLUsername: "proxyuser",
				MasterSASLPassword: "proxypass",
				TLS:                true,
				TLSCertFile:        proxyCert,
				TLSKeyFile:         proxyKey,
				InsecureAuth:       false,
				RemoteTLS:          true,
				RemoteTLSVerify:    true,        // full verification on the backend leg
				RemoteTLSCAFile:    backendCert, // trust anchor = the backend's self-signed cert
				ConnectTimeout:     10 * time.Second,
			},
		)
		if err != nil {
			t.Fatalf("Failed to create proxy with verified RemoteTLS: %v", err)
		}
		go func() { proxy.Start() }()
		defer proxy.Stop()
		time.Sleep(200 * time.Millisecond)

		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", proxyAddr,
			&tls.Config{RootCAs: proxyPool})
		if err != nil {
			t.Fatalf("TLS handshake to proxy failed: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(15 * time.Second))
		reader := bufio.NewReader(conn)

		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("greeting: %q, %v", resp, err)
		}
		fmt.Fprintf(conn, "USER %s\r\n", account.Email)
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("USER failed: %q", resp)
		}
		// PASS drives the verified TLS connect to the backend.
		fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
		resp, _ := reader.ReadString('\n')
		if wantAuthSuccess {
			if !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("PASS through verified TLS backend leg failed: %q", resp)
			}
			fmt.Fprintf(conn, "STAT\r\n")
			if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("STAT through verified relay failed: %q", resp)
			}
			fmt.Fprintf(conn, "QUIT\r\n")
			if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("QUIT failed: %q", resp)
			}
			return
		}
		if !strings.HasPrefix(resp, "-ERR") {
			t.Fatalf("PASS must fail when the backend certificate identity does not match, got %q", resp)
		}
	}

	t.Run("valid backend certificate verifies", func(t *testing.T) {
		cert, key, _ := common.GenerateTestTLSCert(t, nil, nil) // SANs: localhost, 127.0.0.1, ::1
		run(t, cert, key, true)
	})

	t.Run("wrong identity rejected by ServerName pinning", func(t *testing.T) {
		// Valid, trusted chain — but the certificate names a different host
		// than the one the proxy dials, so hostname verification must fail.
		cert, key, _ := common.GenerateTestTLSCert(t, []string{"wrong.example.com"}, nil)
		run(t, cert, key, false)
	})
}

// TestPOP3ProxyImplicitTLSWithProxyProtocol covers PROXY protocol + implicit
// TLS on the proxy: the PROXY header is read from the raw stream first, then
// the TLS handshake runs over the remaining bytes — including the case where
// the client coalesces the header and the ClientHello into one segment — and
// a full login relays to the backend.
func TestPOP3ProxyImplicitTLSWithProxyProtocol(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, account := common.SetupPOP3ServerWithMaster(t)
	defer backend.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		backend.ResilientDB,
		pop3proxy.POP3ProxyServerOptions{
			Name:                 "test-proxy-tls-proxyproto",
			RemoteAddrs:          []string{backend.Address},
			MasterSASLUsername:   "proxyuser",
			MasterSASLPassword:   "proxypass",
			TLS:                  true,
			TLSCertFile:          certFile,
			TLSKeyFile:           keyFile,
			InsecureAuth:         false,
			ConnectTimeout:       10 * time.Second,
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
			// The proxy's PROXY-protocol reader trusts TrustedNetworks.
			TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
			TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy with TLS+PROXY: %v", err)
	}

	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	header := "PROXY TCP4 192.0.2.7 127.0.0.1 51000 995\r\n"

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
		fmt.Fprintf(conn, "STAT\r\n")
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("STAT through relay failed: %q", resp)
		}
		fmt.Fprintf(conn, "QUIT\r\n")
		if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("QUIT through relay failed: %q", resp)
		}
	}

	t.Run("header in separate segment", func(t *testing.T) { run(t, false) })
	t.Run("header coalesced with ClientHello", func(t *testing.T) { run(t, true) })
}
