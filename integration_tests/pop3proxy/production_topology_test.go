//go:build integration

package pop3proxy_test

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
	"github.com/migadu/sora/server/pop3proxy"
)

// TestPOP3ProxyProductionTopologyConcurrent replicates the production
// deployment shape UNDER CONCURRENCY: clients speak implicit TLS to the
// proxy, the proxy dials the backend in PLAINTEXT with
// remote_use_proxy_protocol=true, and the backend requires the PROXY header
// (proxy_protocol=true, tls=false).
//
// The concurrency is the point — see TestIMAPProxyProductionTopologyConcurrent
// for the 2026-07-05 incident this guards against (SoraListener's serial
// TLS probe capped PROXY-fed backends at ~10 accepts/s; single-connection
// topology tests stayed green while production collapsed). The short backend
// connect_timeout (2s) bounds the proxy's greeting read so backend
// accept-path stalls surface as login failures.
func TestPOP3ProxyProductionTopologyConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Backend: plaintext, PROXY protocol required, master SASL for the proxy.
	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	proxyAddr := common.GetRandomAddress(t)
	certFile, keyFile, certPool := common.GenerateTestTLSCert(t, nil, nil)

	proxy, err := pop3proxy.New(
		context.Background(),
		"localhost",
		proxyAddr,
		backendServer.ResilientDB,
		pop3proxy.POP3ProxyServerOptions{
			Name:               "test-proxy-prod-topology",
			RemoteAddrs:        []string{backendServer.Address},
			MasterSASLUsername: "proxyuser",
			MasterSASLPassword: "proxypass",
			TLS:                true,
			TLSCertFile:        certFile,
			TLSKeyFile:         keyFile,
			InsecureAuth:       false,
			// Backend leg: plaintext + PROXY header, like production.
			RemoteTLS:              false,
			RemoteUseProxyProtocol: true,
			// Short on purpose: backend accept-path stalls must surface as
			// failures instead of hiding behind a generous deadline.
			ConnectTimeout: 2 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}
	go func() { proxy.Start() }()
	defer proxy.Stop()
	time.Sleep(200 * time.Millisecond)

	const clients = 30

	login := func(id int) error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", proxyAddr,
			&tls.Config{RootCAs: certPool})
		if err != nil {
			return fmt.Errorf("client %d: TLS dial: %w", id, err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		reader := bufio.NewReader(conn)

		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("client %d: greeting: %q, %w", id, resp, err)
		}
		fmt.Fprintf(conn, "USER %s\r\n", account.Email)
		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("client %d: USER: %q, %w", id, resp, err)
		}
		// PASS drives the whole production chain: local auth, plaintext dial
		// to the backend, PROXY header, greeting read (2s deadline), master
		// SASL, relay switch.
		fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("client %d: PASS: %q, %w", id, strings.TrimSpace(resp), err)
		}
		// One relayed command proves the backend session is live.
		fmt.Fprintf(conn, "STAT\r\n")
		if resp, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(resp, "+OK") {
			return fmt.Errorf("client %d: STAT through relay: %q, %w", id, resp, err)
		}
		fmt.Fprintf(conn, "QUIT\r\n")
		reader.ReadString('\n')
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
