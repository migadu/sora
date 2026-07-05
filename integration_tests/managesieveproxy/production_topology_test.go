//go:build integration

package managesieveproxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieveproxy"
)

// TestManageSieveProxyProductionTopologyConcurrent replicates the production
// deployment shape UNDER CONCURRENCY: clients speak implicit TLS to the
// proxy, the proxy dials the backend in PLAINTEXT with
// remote_use_proxy_protocol=true, and the backend requires the PROXY header
// (proxy_protocol=true, tls=false).
//
// The concurrency is the point — see TestIMAPProxyProductionTopologyConcurrent
// for the 2026-07-05 incident this guards against (SoraListener's serial
// TLS probe capped PROXY-fed backends at ~10 accepts/s; single-connection
// topology tests stayed green while production collapsed). The short backend
// connect_timeout (2s) bounds the proxy's backend handshake so accept-path
// stalls surface as authentication failures.
func TestManageSieveProxyProductionTopologyConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend: plaintext, PROXY protocol required, master SASL for the proxy.
	backendServer, account := common.SetupManageSieveServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)
	hostname := "test-sieve-proxy-prod-topology"

	proxy, err := managesieveproxy.New(context.Background(), backendServer.ResilientDB, hostname,
		managesieveproxy.ServerOptions{
			Name:               hostname,
			Addr:               proxyAddr,
			RemoteAddrs:        []string{backendServer.Address},
			RemotePort:         4190,
			MasterSASLUsername: "master_sasl",
			MasterSASLPassword: "master_sasl_secret",
			TLS:                true,
			TLSUseStartTLS:     false,
			TLSCertFile:        certFile,
			TLSKeyFile:         keyFile,
			InsecureAuth:       false,
			// Backend leg: plaintext + PROXY header, like production.
			RemoteTLS:              false,
			RemoteUseProxyProtocol: true,
			// Short on purpose: backend accept-path stalls must surface as
			// failures instead of hiding behind a generous deadline.
			ConnectTimeout:  2 * time.Second,
			AuthIdleTimeout: 30 * time.Minute,
			CommandTimeout:  5 * time.Minute,
			EnableAffinity:  true,
			AuthRateLimit: server.AuthRateLimiterConfig{
				Enabled: false,
			},
			TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}
	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	const clients = 30

	// readReply reads lines until an OK/NO/BYE response line arrives.
	readReply := func(reader *bufio.Reader) (string, error) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return "", err
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "OK") || strings.HasPrefix(trimmed, "NO") || strings.HasPrefix(trimmed, "BYE") {
				return trimmed, nil
			}
		}
	}

	login := func(id int) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", proxyAddr,
			&tls.Config{RootCAs: certPool})
		if err != nil {
			return fmt.Errorf("client %d: TLS dial: %w", id, err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		reader := bufio.NewReader(conn)

		if resp, err := readReply(reader); err != nil || !strings.HasPrefix(resp, "OK") {
			return fmt.Errorf("client %d: greeting: %q, %w", id, resp, err)
		}
		// AUTHENTICATE drives the whole production chain: local auth,
		// plaintext dial to the backend, PROXY header, backend capability
		// read (2s deadline), master SASL, relay switch.
		creds := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
		fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", creds)
		if resp, err := readReply(reader); err != nil || !strings.HasPrefix(resp, "OK") {
			return fmt.Errorf("client %d: AUTHENTICATE: %q, %w", id, resp, err)
		}
		// One relayed command proves the backend session is live.
		fmt.Fprintf(conn, "LISTSCRIPTS\r\n")
		if resp, err := readReply(reader); err != nil || !strings.HasPrefix(resp, "OK") {
			return fmt.Errorf("client %d: LISTSCRIPTS through relay: %q, %w", id, resp, err)
		}
		fmt.Fprintf(conn, "LOGOUT\r\n")
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
