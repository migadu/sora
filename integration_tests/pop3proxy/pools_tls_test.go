//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/storage"
)

// TestPOP3ProxyPoolTLSIsImplicitTLS: one [[pool]] block serves every protocol, so a pool
// that sets remote_tls_use_starttls for LMTP and ManageSieve also sets it for POP3. POP3
// cannot STARTTLS to a backend: for it remote_tls still means TLS from the first byte. A
// TLS-only backend proves it, since a plaintext leg would wait forever for a greeting the
// backend only sends inside TLS (and would carry the master credentials in the clear).
func TestPOP3ProxyPoolTLSIsImplicitTLS(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	backendAddr := common.GetRandomAddress(t)
	backendCert, backendKey, _ := common.GenerateTestTLSCert(t, nil, nil)

	backend, err := pop3.New(context.Background(), "test-backend-pool-tls", "localhost", backendAddr,
		&storage.S3Storage{}, rdb, nil, nil, pop3.POP3ServerOptions{
			TLS:                true,
			TLSCertFile:        backendCert,
			TLSKeyFile:         backendKey,
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
		})
	if err != nil {
		t.Fatalf("Failed to create TLS backend: %v", err)
	}
	go func() { backend.Start(make(chan error, 1)) }()
	defer backend.Close()
	time.Sleep(200 * time.Millisecond)

	proxyAddr := common.GetRandomAddress(t)
	p, err := pop3proxy.New(context.Background(), "localhost", proxyAddr, rdb, pop3proxy.POP3ProxyServerOptions{
		Name: "test-proxy-pool-tls",
		Pools: []proxy.PoolSpec{{Name: "tls", Backends: []string{backendAddr}, Default: true,
			Settings: proxy.BackendSettings{TLS: true, TLSUseStartTLS: true, TLSVerify: false}}},
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		InsecureAuth:       true,
		ConnectTimeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("pop3proxy.New: %v", err)
	}
	go func() { p.Start() }()
	defer p.Stop()
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	reader := bufio.NewReader(conn)
	if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("greeting: %q, %v", resp, err)
	}
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER: %q", resp)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("PASS through the pool's TLS backend leg: %q (a plaintext leg never gets the backend's greeting)", resp)
	}
	fmt.Fprintf(conn, "STAT\r\n")
	if resp, _ := reader.ReadString('\n'); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("STAT: %q", resp)
	}
}
