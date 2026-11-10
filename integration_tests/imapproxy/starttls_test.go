//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	imapserver "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
)

// startSTARTTLSProxy starts a PROXY-protocol backend and, in front of it, an
// IMAP proxy with a generated certificate and tls_use_starttls (insecure_auth
// off, as with tls = true). It returns the proxy, its address, the account and
// the pool that verifies the proxy's certificate.
func startSTARTTLSProxy(t *testing.T, backend func(*imapserver.IMAPServerOptions), configure func(*imapproxy.ServerOptions)) (*imapproxy.Server, string, common.TestAccount, *x509.CertPool) {
	t.Helper()
	backendServer, account := common.SetupIMAPServerWithPROXYOptions(t, backend)
	t.Cleanup(backendServer.Close)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	proxyAddress := common.GetRandomAddress(t)
	opts := imapproxy.ServerOptions{
		Name:                   "test-proxy-starttls",
		Addr:                   proxyAddress,
		RemoteAddrs:            []string{backendServer.Address},
		RemotePort:             143,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		TLS:                    true,
		TLSCertFile:            certFile,
		TLSKeyFile:             keyFile,
		TLSUseStartTLS:         true,
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Second,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
	}
	if configure != nil {
		configure(&opts)
	}
	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, "test-proxy-starttls", opts)
	if err != nil {
		t.Fatalf("imapproxy.New: %v", err)
	}
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Errorf("IMAP proxy: %v", err)
		}
	}()
	t.Cleanup(func() { proxy.Stop() })
	for deadline := time.Now().Add(3 * time.Second); ; {
		c, err := net.Dial("tcp", proxyAddress)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return proxy, proxyAddress, account, certPool
}

// dialProxySTARTTLS connects in plaintext, checks the greeting offers STARTTLS
// and LOGINDISABLED, upgrades with certificate verification and runs a NOOP
// through TLS, so the session has read from its TLS connection.
func dialProxySTARTTLS(t *testing.T, addr string, certPool *x509.CertPool) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("plaintext greeting: %v", err)
	}
	if !strings.Contains(greeting, " STARTTLS") || !strings.Contains(greeting, " LOGINDISABLED") || strings.Contains(greeting, "AUTH=") {
		t.Errorf("plaintext greeting must offer STARTTLS and LOGINDISABLED and no AUTH=, got %q", greeting)
	}
	fmt.Fprint(conn, "s STARTTLS\r\n")
	if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "s OK") {
		t.Fatalf("STARTTLS = %q, %v", line, err)
	}
	// tls.Client does not infer ServerName from the address; the certificate
	// is valid for 127.0.0.1.
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: certPool, ServerName: "127.0.0.1"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake after STARTTLS (certificate verified): %v", err)
	}
	tlsReader := bufio.NewReader(tlsConn)
	fmt.Fprint(tlsConn, "n NOOP\r\n")
	if line, err := tlsReader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "n OK") {
		t.Fatalf("NOOP through TLS = %q, %v", line, err)
	}
	return tlsConn, tlsReader
}

// tls_use_starttls on an imap_proxy: a plaintext listener that offers STARTTLS
// and LOGINDISABLED, and after the upgrade logs in and relays to the backend.
func TestIMAPProxySTARTTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	_, addr, account, certPool := startSTARTTLSProxy(t, nil, nil)
	dialProxySTARTTLS(t, addr, certPool) // greeting checks

	c, err := imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: &tls.Config{RootCAs: certPool}})
	if err != nil {
		t.Fatalf("DialStartTLS (certificate verified): %v", err)
	}
	defer c.Close()
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY after STARTTLS: %v", err)
	}
	if caps.Has(imap.CapStartTLS) || caps.Has(imap.CapLoginDisabled) || !caps.Has(imap.Cap("AUTH=PLAIN")) {
		t.Errorf("CAPABILITY after STARTTLS must offer AUTH=PLAIN and neither STARTTLS nor LOGINDISABLED, got %v", caps)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("LOGIN after STARTTLS: %v", err)
	}
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX through the proxy: %v", err)
	}
	if err := c.Logout().Wait(); err != nil {
		t.Fatalf("LOGOUT: %v", err)
	}
}

// The proxy's handshake after STARTTLS must yield the JA4 it forwards in the
// PROXY v2 header, so a backend client filter keyed on JA4 applies to a client
// that upgraded at the proxy.
func TestIMAPProxySTARTTLSForwardsJA4ToBackend(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	_, addr, account, certPool := startSTARTTLSProxy(t, func(o *imapserver.IMAPServerOptions) {
		o.CapabilityFilters = []config.ClientCapabilityFilter{{
			JA4Fingerprints: []string{"^t13"}, // any TLS 1.3 client, as Go's is
			DisableCaps:     []string{"IDLE"},
			Reason:          "test",
		}}
	}, nil)

	c, err := imapclient.DialStartTLS(addr, &imapclient.Options{TLSConfig: &tls.Config{RootCAs: certPool}})
	if err != nil {
		t.Fatalf("DialStartTLS: %v", err)
	}
	defer c.Close()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("LOGIN after STARTTLS: %v", err)
	}
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY through the proxy: %v", err)
	}
	if caps.Has(imap.CapIdle) {
		t.Fatalf("the backend's JA4 filter disabling IDLE did not apply to a client that upgraded at the proxy: %v", caps)
	}
}

// The shutdown BYE is written from the goroutine that stops the proxy. After
// STARTTLS it must go through the TLS connection: written below it, it arrives
// as plaintext inside the TLS stream and the client sees a TLS record error.
func TestIMAPProxyShutdownByeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	proxy, addr, _, certPool := startSTARTTLSProxy(t, nil, nil)
	_, reader := dialProxySTARTTLS(t, addr, certPool)

	go proxy.Stop()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the shutdown BYE through TLS: %v", err)
	}
	if want := "* BYE Server shutting down, please reconnect\r\n"; line != want {
		t.Fatalf("shutdown BYE through TLS = %q, want %q", line, want)
	}
}

// The idle BYE is written by the SoraConn's timeout goroutine, below the TLS
// connection the session layered on after STARTTLS (#163).
func TestIMAPProxyIdleNoticeAfterSTARTTLSIsReadableThroughTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	_, addr, _, certPool := startSTARTTLSProxy(t, nil, func(o *imapproxy.ServerOptions) {
		o.CommandTimeout = 2 * time.Second // the SoraConn's idle timeout, before auth_idle_timeout
	})
	_, reader := dialProxySTARTTLS(t, addr, certPool)

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("reading the idle notice through TLS: %v", err)
	}
	if want := "* BYE Idle timeout, please reconnect\r\n"; line != want {
		t.Fatalf("idle notice through TLS = %q, want %q", line, want)
	}
}
