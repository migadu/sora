//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTPProxyForwardsClientIdentityToReceivedHeader is the end-to-end guard for the trace
// fix: a client delivers through the proxy, and the message the backend stores must carry a
// Received: header naming the CLIENT (its announced LHLO name + IP), not the proxy. This
// exercises the whole chain — proxy forwards HELO/ADDR via XCLIENT, the backend re-applies
// the XCLIENT data onto the post-reset delivery session, and BuildReceivedHeader prefers the
// forwarded HELO. XCLIENT only (no PROXY protocol).
func TestLMTPProxyForwardsClientIdentityToReceivedHeader(t *testing.T) {
	stored := deliverThroughProxyAndReadStored(t, traceTestConfig{
		backendAddr: "127.0.0.1:12431",
		proxyAddr:   "127.0.0.1:12432",
		backendOpts: lmtp.LMTPServerOptions{
			TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
		},
		proxyOpts: lmtpproxy.ServerOptions{
			TrustedProxies:   []string{"127.0.0.1/32"},
			RemoteUseXCLIENT: true,
		},
	})
	assertClientHELOInTrace(t, stored)
}

// TestLMTPProxyForwardsClientIdentityWithProxyProtocol replicates the production combination
// that XCLIENT-only tests miss: the backend has proxy_protocol = true AND the proxy forwards
// BOTH a PROXY protocol header (for the IP) and XCLIENT (for the HELO). The regression risk is
// that PROXY-protocol handling interferes with XCLIENT trust/application and the HELO is lost
// while the IP still survives — exactly the symptom seen in production.
func TestLMTPProxyForwardsClientIdentityWithProxyProtocol(t *testing.T) {
	stored := deliverThroughProxyAndReadStored(t, traceTestConfig{
		backendAddr: "127.0.0.1:12433",
		proxyAddr:   "127.0.0.1:12434",
		backendOpts: lmtp.LMTPServerOptions{
			TrustedNetworks:      []string{"127.0.0.0/8", "::1/128"},
			ProxyProtocol:        true,
			ProxyProtocolTimeout: "5s",
		},
		proxyOpts: lmtpproxy.ServerOptions{
			TrustedProxies:         []string{"127.0.0.1/32"},
			RemoteUseXCLIENT:       true,
			RemoteUseProxyProtocol: true,
		},
	})
	assertClientHELOInTrace(t, stored)
}

const traceClientHELO = "upstream.example.net"

type traceTestConfig struct {
	backendAddr string
	proxyAddr   string
	backendOpts lmtp.LMTPServerOptions
	proxyOpts   lmtpproxy.ServerOptions
}

// deliverThroughProxyAndReadStored brings up a backend + proxy with the given options, delivers
// one message announcing traceClientHELO, and returns the stored message bytes.
func deliverThroughProxyAndReadStored(t *testing.T, cfg traceTestConfig) string {
	t.Helper()
	ctx := context.Background()

	rdb := common.SetupTestDatabase(t)
	testAccount := common.CreateTestAccount(t, rdb)

	s3 := &storage.S3Storage{}
	tempDir := t.TempDir()
	uploadWorker, err := uploader.New(
		ctx, tempDir, 10, 2, 3, 5*time.Second, 0, "test-backend", rdb, s3, nil, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}
	t.Cleanup(func() { uploadWorker.Stop() })

	backendServer, err := lmtp.New(ctx, "test-backend", "storage.example", cfg.backendAddr, s3, rdb, uploadWorker, cfg.backendOpts)
	if err != nil {
		t.Fatalf("Failed to create backend LMTP server: %v", err)
	}
	errChan := make(chan error, 1)
	go func() { backendServer.Start(errChan) }()
	t.Cleanup(func() { backendServer.Close() })
	time.Sleep(200 * time.Millisecond)

	cfg.proxyOpts.Name = "test-proxy"
	cfg.proxyOpts.Addr = cfg.proxyAddr
	cfg.proxyOpts.RemoteAddrs = []string{cfg.backendAddr}
	proxy, err := lmtpproxy.New(ctx, rdb, "proxy.example", cfg.proxyOpts)
	if err != nil {
		t.Fatalf("Failed to create LMTP proxy: %v", err)
	}
	go func() {
		if err := proxy.Start(); err != nil {
			t.Logf("LMTP proxy error: %v", err)
		}
	}()
	t.Cleanup(func() { proxy.Stop() })
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", cfg.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	mustRead := func(what string) string {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s: %v", what, err)
		}
		return line
	}
	mustWrite := func(s string) {
		if _, err := writer.WriteString(s); err != nil {
			t.Fatalf("write %q: %v", s, err)
		}
		if err := writer.Flush(); err != nil {
			t.Fatalf("flush %q: %v", s, err)
		}
	}

	mustRead("greeting")

	// Client announces its own name — this is what must surface in the backend's trace.
	mustWrite("LHLO " + traceClientHELO + "\r\n")
	for {
		line := mustRead("LHLO")
		if len(line) >= 4 && line[3] != '-' {
			break
		}
	}

	mustWrite("MAIL FROM:<sender@example.com>\r\n")
	if resp := mustRead("MAIL FROM"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM not accepted: %s", strings.TrimSpace(resp))
	}
	mustWrite(fmt.Sprintf("RCPT TO:<%s>\r\n", testAccount.Email))
	if resp := mustRead("RCPT TO"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("RCPT TO not accepted: %s", strings.TrimSpace(resp))
	}
	mustWrite("DATA\r\n")
	if resp := mustRead("DATA"); !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA not accepted: %s", strings.TrimSpace(resp))
	}

	msg := strings.Join([]string{
		"From: sender@example.com",
		"To: " + testAccount.Email,
		"Subject: Proxy Trace Test",
		"Message-ID: <ptt-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"",
		"Body delivered through the proxy.",
		".",
		"",
	}, "\r\n")
	mustWrite(msg)
	if resp := mustRead("post-DATA"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("delivery not accepted: %s", strings.TrimSpace(resp))
	}

	// Give the backend a moment to stage the message to disk.
	time.Sleep(500 * time.Millisecond)
	return readBackendStored(t, tempDir)
}

// assertClientHELOInTrace verifies the stored message's Received: from-clause names the
// client's announced HELO and not the proxy/backend identity.
func assertClientHELOInTrace(t *testing.T, stored string) {
	t.Helper()
	if want := "from " + traceClientHELO; !strings.Contains(stored, want) {
		t.Errorf("Received: must name the forwarded client HELO %q\n--- stored head ---\n%s", want, storedHead(stored))
	}
	for _, leak := range []string{"from proxy.example", "from storage.example", "from localhost"} {
		if strings.Contains(stored, leak) {
			t.Errorf("Received: leaked proxy/backend identity %q instead of the client HELO\n--- stored head ---\n%s", leak, storedHead(stored))
		}
	}
}

// readBackendStored returns the single staged message body written under the backend
// uploader's temp dir (files are named by their 64-hex content hash).
func readBackendStored(t *testing.T, tempDir string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && len(filepath.Base(path)) == 64 {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no staged message found under %s", tempDir)
	}
	b, err := os.ReadFile(found)
	if err != nil {
		t.Fatalf("read staged message: %v", err)
	}
	return string(b)
}

func storedHead(s string) string {
	if len(s) > 700 {
		return s[:700]
	}
	return s
}
