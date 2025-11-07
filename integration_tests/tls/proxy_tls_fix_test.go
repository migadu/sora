//go:build integration

package tls_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	lmtpproxy "github.com/migadu/sora/server/lmtpproxy"
	managesieveserver "github.com/migadu/sora/server/managesieve"
	managesieveproxy "github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTPProxyTLSConfigSTARTTLS tests the fix for LMTP proxy STARTTLS mode
// REGRESSION TEST: Before the fix, LMTP proxy only used global TLS config for implicit TLS
// After fix: Global TLS config works for both implicit TLS and STARTTLS
func TestLMTPProxyTLSConfigSTARTTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Setup real LMTP backend server
	backendAddr := common.GetRandomAddress(t)
	_ = setupRealLMTPBackend(t, rdb, backendAddr)

	// Create LMTP proxy with STARTTLS mode + global TLS config
	// This was broken before the fix!
	proxyAddr := common.GetRandomAddress(t)
	t.Logf("Creating LMTP proxy: %s -> %s", proxyAddr, backendAddr)
	proxy, err := lmtpproxy.New(
		context.Background(),
		rdb,
		"localhost",
		lmtpproxy.ServerOptions{
			Name:                   "test-lmtp-starttls",
			Addr:                   proxyAddr,
			RemoteAddrs:            []string{backendAddr},
			RemotePort:             0, // Use port from RemoteAddrs
			TLS:                    true,
			TLSUseStartTLS:         true,      // Use STARTTLS, not implicit TLS
			TLSConfig:              tlsConfig, // Global TLS config (e.g., Let's Encrypt)
			Debug:                  true,
			RemoteUseProxyProtocol: true,
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"}, // Allow localhost
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- proxy.Start()
	}()
	defer proxy.Stop()

	// Give proxy time to start
	time.Sleep(500 * time.Millisecond)

	// Check for startup errors
	select {
	case err := <-errCh:
		t.Fatalf("Proxy startup error: %v", err)
	default:
		t.Logf("Proxy started successfully")
	}

	// Connect without TLS initially
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy at %s: %v", proxyAddr, err)
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read greeting
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read greeting from proxy at %s: %v (backend: %s)", proxyAddr, err, backendAddr)
	}
	greeting := string(buf[:n])
	if !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("Invalid LMTP greeting: %s", greeting)
	}

	// Send LHLO to get capabilities
	conn.Write([]byte("LHLO test\r\n"))

	// Read the full multi-line LHLO response (250-... format ends with 250 ...)
	var lhloResp strings.Builder
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read LHLO response: %v", err)
		}
		lhloResp.WriteString(line)
		// LMTP uses 250-... for continuation and 250 ... for the last line
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	lhloRespStr := lhloResp.String()

	// CRITICAL TEST: STARTTLS must be advertised
	// Before the fix, this would fail because tlsConfig was nil for STARTTLS mode
	if !strings.Contains(lhloRespStr, "STARTTLS") {
		t.Fatalf("REGRESSION: STARTTLS not advertised when using global TLS config in STARTTLS mode.\n"+
			"This indicates the fix is broken. Response: %s", lhloRespStr)
	}

	// Send STARTTLS command
	conn.Write([]byte("STARTTLS\r\n"))

	// Read STARTTLS response (single line)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read STARTTLS response: %v", err)
	}
	if !strings.HasPrefix(line, "220 ") {
		t.Fatalf("STARTTLS failed. Response: %s", line)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("REGRESSION: TLS handshake failed after STARTTLS.\n"+
			"This indicates the global TLS config is not being used. Error: %v", err)
	}

	if !tlsConn.ConnectionState().HandshakeComplete {
		t.Fatal("Expected TLS handshake to be complete")
	}

	t.Logf("✓ LMTP proxy STARTTLS with global TLS config works - FIX VERIFIED!")
	t.Logf("✓ Cipher suite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
}

// TestManageSieveProxyTLSConfigSTARTTLS tests the fix for ManageSieve proxy STARTTLS mode
// REGRESSION TEST: Before the fix, ManageSieve proxy only used global TLS config for implicit TLS
// After fix: Global TLS config works for both implicit TLS and STARTTLS
func TestManageSieveProxyTLSConfigSTARTTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	cert, err := tls.LoadX509KeyPair("../../testdata/sora.crt", "../../testdata/sora.key")
	if err != nil {
		t.Fatalf("Failed to load certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Setup real ManageSieve backend server
	backendAddr := common.GetRandomAddress(t)
	_ = setupRealManageSieveBackend(t, rdb, backendAddr)

	// Create ManageSieve proxy with STARTTLS mode + global TLS config
	// This was broken before the fix!
	proxyAddr := common.GetRandomAddress(t)
	proxy, err := managesieveproxy.New(
		context.Background(),
		rdb,
		"localhost",
		managesieveproxy.ServerOptions{
			Name:                   "test-managesieve-starttls",
			Addr:                   proxyAddr,
			RemoteAddrs:            []string{backendAddr},
			RemoteTLS:              false,
			RemotePort:             0, // Use port from RemoteAddrs
			RemoteTLSUseStartTLS:   false,
			RemoteUseProxyProtocol: true,
			TLS:                    true,
			TLSUseStartTLS:         true,                               // STARTTLS mode
			TLSConfig:              tlsConfig,                          // Global TLS config (e.g., Let's Encrypt)
			TrustedProxies:         []string{"127.0.0.0/8", "::1/128"}, // Allow localhost
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go proxy.Start()
	defer proxy.Stop()
	time.Sleep(500 * time.Millisecond)

	// Connect without TLS initially
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy at %s: %v", proxyAddr, err)
	}
	defer conn.Close()

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read greeting (should include capabilities with STARTTLS)
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read greeting from proxy at %s: %v (backend: %s)", proxyAddr, err, backendAddr)
	}
	greeting := string(buf[:n])

	// CRITICAL TEST: STARTTLS must be advertised
	// Before the fix, this would fail because tlsConfig was nil for STARTTLS mode
	if !strings.Contains(greeting, "STARTTLS") {
		t.Fatalf("REGRESSION: STARTTLS not advertised when using global TLS config in STARTTLS mode.\n"+
			"This indicates the fix is broken. Greeting: %s", greeting)
	}

	// Send STARTTLS command
	conn.Write([]byte("STARTTLS\r\n"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read STARTTLS response: %v", err)
	}
	starttlsResp := string(buf[:n])
	if !strings.Contains(starttlsResp, "OK") {
		t.Fatalf("STARTTLS failed. Response: %s", starttlsResp)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("REGRESSION: TLS handshake failed after STARTTLS.\n"+
			"This indicates the global TLS config is not being used. Error: %v", err)
	}

	if !tlsConn.ConnectionState().HandshakeComplete {
		t.Fatal("Expected TLS handshake to be complete")
	}

	t.Logf("✓ ManageSieve proxy STARTTLS with global TLS config works - FIX VERIFIED!")
	t.Logf("✓ Cipher suite: %s", tls.CipherSuiteName(tlsConn.ConnectionState().CipherSuite))
}

// setupRealLMTPBackend creates a real LMTP backend server for testing
func setupRealLMTPBackend(t *testing.T, rdb *resilient.ResilientDatabase, addr string) *lmtpserver.LMTPServerBackend {
	t.Helper()

	// Create upload worker
	tempDir, err := os.MkdirTemp("", "sora-test-lmtp-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tempDir) })

	errCh := make(chan error, 1)
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		1,
		3,
		time.Second,
		"test-lmtp-backend",
		rdb,
		&storage.S3Storage{},
		nil,
		errCh,
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Create LMTP server
	backend, err := lmtpserver.New(
		context.Background(),
		"test-lmtp-backend",
		"localhost",
		addr,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		lmtpserver.LMTPServerOptions{
			TLS:           false,
			ProxyProtocol: true,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP backend: %v", err)
	}

	// Start server in background
	go backend.Start(errCh)

	t.Cleanup(func() {
		// LMTP server stops when context is canceled
	})

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	return backend
}

// setupRealManageSieveBackend creates a real ManageSieve backend server for testing
func setupRealManageSieveBackend(t *testing.T, rdb *resilient.ResilientDatabase, addr string) *managesieveserver.ManageSieveServer {
	t.Helper()

	// Create ManageSieve server
	backend, err := managesieveserver.New(
		context.Background(),
		"test-managesieve-backend",
		"localhost",
		addr,
		rdb,
		managesieveserver.ManageSieveServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve backend: %v", err)
	}

	// Start server in background
	errCh := make(chan error, 1)
	go backend.Start(errCh)

	t.Cleanup(func() {
		// ManageSieve server stops when context is canceled
	})

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	return backend
}
