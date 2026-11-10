//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
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

// startSTARTTLSSieveProxy starts a backend with master SASL and, in front of
// it, a ManageSieve proxy with a generated certificate and tls_use_starttls
// (insecure_auth off, as with tls = true).
func startSTARTTLSSieveProxy(t *testing.T, configure func(*managesieveproxy.ServerOptions)) (*managesieveproxy.Server, string, common.TestAccount, *x509.CertPool) {
	t.Helper()
	backendServer, account := common.SetupManageSieveServerWithMaster(t)
	t.Cleanup(backendServer.Close)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	proxyAddr := common.GetRandomAddress(t)
	opts := managesieveproxy.ServerOptions{
		Name:               "test-sieve-proxy-starttls",
		Addr:               proxyAddr,
		RemoteAddrs:        []string{backendServer.Address},
		RemotePort:         4190,
		MasterSASLUsername: "master_sasl",
		MasterSASLPassword: "master_sasl_secret",
		TLS:                true,
		TLSUseStartTLS:     true,
		TLSCertFile:        certFile,
		TLSKeyFile:         keyFile,
		InsecureAuth:       false,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Second,
		CommandTimeout:     time.Minute,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
	}
	if configure != nil {
		configure(&opts)
	}
	proxy, err := managesieveproxy.New(context.Background(), backendServer.ResilientDB, "test-sieve-proxy-starttls", opts)
	if err != nil {
		t.Fatalf("managesieveproxy.New: %v", err)
	}
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy: %v", err)
		}
	}()
	t.Cleanup(func() { proxy.Stop() })
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", proxyAddr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return proxy, proxyAddr, account, certPool
}

// dialSieveSTARTTLS connects in plaintext, upgrades with certificate
// verification and runs a CAPABILITY through TLS, so the session has read from
// the library's TLS connection.
func dialSieveSTARTTLS(t *testing.T, addr string, certPool *x509.CertPool) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)
	readUntilOK(t, reader, "plaintext greeting")
	fmt.Fprint(conn, "STARTTLS\r\n")
	if resp := readUntilOK(t, reader, "STARTTLS response"); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("STARTTLS = %q", resp)
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: certPool, ServerName: "127.0.0.1"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS (certificate verified): %v", err)
	}
	tlsReader := bufio.NewReader(tlsConn)
	readUntilOK(t, tlsReader, "capabilities after STARTTLS") // RFC 5804 §2.2
	fmt.Fprint(tlsConn, "CAPABILITY\r\n")
	readUntilOK(t, tlsReader, "CAPABILITY through TLS")
	return tlsConn, tlsReader
}

// The shutdown BYE is written from the goroutine that stops the proxy. Before
// login the session's clientConn is the SoraConn, below the library's TLS
// connection after STARTTLS: a BYE written there arrives as plaintext inside
// the TLS stream and the client sees a TLS record error.
func TestManageSieveProxyShutdownByeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	proxy, addr, _, certPool := startSTARTTLSSieveProxy(t, nil)
	_, reader := dialSieveSTARTTLS(t, addr, certPool)

	go proxy.Stop()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown BYE through TLS: %v", err)
	}
	if want := "BYE (TRYLATER) \"Server shutting down, please reconnect\"\r\n"; line != want {
		t.Fatalf("shutdown BYE through TLS = %q, want %q", line, want)
	}
}

// The idle BYE is written by the SoraConn's timeout goroutine, below the TLS
// connection the library layered on after STARTTLS (#163).
func TestManageSieveProxyIdleNoticeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	_, addr, _, certPool := startSTARTTLSSieveProxy(t, func(o *managesieveproxy.ServerOptions) {
		o.CommandTimeout = 2 * time.Second // the SoraConn's idle timeout, before auth_idle_timeout
	})
	_, reader := dialSieveSTARTTLS(t, addr, certPool)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the idle notice through TLS: %v", err)
	}
	if want := "BYE (TRYLATER) \"Idle timeout, please reconnect\"\r\n"; line != want {
		t.Fatalf("idle notice through TLS = %q, want %q", line, want)
	}
}

// After STARTTLS the relay runs on the TLS connection the proxy hijacked from
// the library, which carries neither the client's JA4 nor a username. The
// session must keep logging the JA4, recorded during the STARTTLS handshake on
// the listener's SoraConn, and the SoraConn must know the user its timeout
// closes.
func TestManageSieveProxyLogsJA4AndUserAfterSTARTTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	logs := common.CaptureLogs(t)
	_, addr, account, certPool := startSTARTTLSSieveProxy(t, func(o *managesieveproxy.ServerOptions) {
		o.CommandTimeout = 2 * time.Second
	})
	conn, reader := dialSieveSTARTTLS(t, addr, certPool)
	creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds)
	if resp := readUntilOK(t, reader, "AUTHENTICATE response"); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("AUTHENTICATE after STARTTLS: %q", resp)
	}

	// Logged after the hijack, once the client has its OK.
	if line := logs.WaitForLine(t, "proto=managesieve_proxy", "authentication complete"); !strings.Contains(line, "ja4=t13") {
		t.Errorf("the post-login log line names no JA4 after STARTTLS: %s", line)
	}
	if line := logs.WaitForLine(t, "proto=managesieve_proxy", "Connection closed - timeout"); !strings.Contains(line, "user="+account.Email) {
		t.Errorf("the timeout log line does not name the user after STARTTLS: %s", line)
	}
}
