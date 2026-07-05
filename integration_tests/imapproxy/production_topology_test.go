//go:build integration

package imapproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyProductionTopologyConcurrent replicates the production
// deployment shape UNDER CONCURRENCY: clients speak implicit TLS to the
// proxy, the proxy dials the backend in PLAINTEXT with
// remote_use_proxy_protocol=true, and the backend requires the PROXY header
// (proxy_protocol=true, tls=false).
//
// The concurrency is the point. This exact topology was already covered by
// single-connection tests that stayed green through the 2026-07-05 production
// incident: SoraListener's TLS-on-plaintext probe ran serially in the
// backend's accept loop and — because after the PROXY header the proxy sends
// nothing until the greeting — burned its full 100ms deadline per connection,
// capping the backend at ~10 accepts/s. One login never notices; production
// login volume collapsed the listener (connections stuck in the accept
// backlog past the proxy's greeting deadline → backend marked unhealthy →
// "[UNAVAILABLE]").
//
// This test fires 30 concurrent TLS logins with a deliberately short backend
// connect_timeout (2s, which bounds the proxy's greeting read): under the old
// serial-probe behavior the accept backlog tail exceeds the deadline and
// logins fail with a backend-unavailable error; with the probe skipped for
// PROXY-validated connections, all logins must succeed.
func TestIMAPProxyProductionTopologyConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend: plaintext, PROXY protocol required, master SASL for the proxy.
	backendServer, account := common.SetupIMAPServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	hostname := "test-proxy-prod-topology"

	opts := imapproxy.ServerOptions{
		Name:               hostname,
		Addr:               proxyAddress,
		RemoteAddrs:        []string{backendServer.Address},
		RemotePort:         143,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		TLS:                true,
		TLSCertFile:        certFile,
		TLSKeyFile:         keyFile,
		InsecureAuth:       false,
		// Backend leg: plaintext + PROXY header, like production.
		RemoteTLS:              false,
		RemoteUseProxyProtocol: true,
		// Short on purpose: this bounds the backend greeting read, so backend
		// accept-path stalls surface as login failures instead of hiding
		// behind a generous deadline.
		ConnectTimeout:  2 * time.Second,
		AuthIdleTimeout: 30 * time.Minute,
		EnableAffinity:  true,
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled: false,
		},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
	}

	proxy, err := imapproxy.New(context.Background(), backendServer.ResilientDB, hostname, opts)
	if err != nil {
		t.Fatalf("Failed to create IMAP proxy: %v", err)
	}
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	const clients = 30

	login := func(id int) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", proxyAddress,
			&tls.Config{RootCAs: certPool})
		if err != nil {
			return fmt.Errorf("client %d: TLS dial: %w", id, err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		reader := bufio.NewReader(conn)

		greeting, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("client %d: greeting: %w", id, err)
		}
		if !strings.HasPrefix(greeting, "* OK") {
			return fmt.Errorf("client %d: unexpected greeting: %q", id, greeting)
		}

		// LOGIN drives the whole production chain: local auth, plaintext dial
		// to the backend, PROXY header, greeting read (2s deadline), master
		// SASL, relay switch.
		fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("client %d: reading LOGIN response: %w", id, err)
			}
			if strings.HasPrefix(line, "a1 ") {
				if !strings.HasPrefix(line, "a1 OK") {
					return fmt.Errorf("client %d: LOGIN failed: %q", id, strings.TrimSpace(line))
				}
				break
			}
		}

		// One relayed command proves the backend session is live.
		fmt.Fprintf(conn, "a2 SELECT INBOX\r\n")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("client %d: reading SELECT response: %w", id, err)
			}
			if strings.HasPrefix(line, "a2 ") {
				if !strings.HasPrefix(line, "a2 OK") {
					return fmt.Errorf("client %d: SELECT failed: %q", id, strings.TrimSpace(line))
				}
				break
			}
		}
		fmt.Fprintf(conn, "a3 LOGOUT\r\n")
		return nil
	}

	var wg sync.WaitGroup
	errCh := make(chan error, clients)
	start := time.Now()
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if err := login(id); err != nil {
				errCh <- err
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errCh)

	var failures []string
	for err := range errCh {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		max := len(failures)
		if max > 5 {
			max = 5
		}
		t.Fatalf("%d/%d concurrent logins failed through the production topology (backend accept path stalling?). First failures:\n%s",
			len(failures), clients, strings.Join(failures[:max], "\n"))
	}
	t.Logf("✓ %d concurrent TLS logins via plaintext+PROXY backend leg completed in %v", clients, elapsed)
}
