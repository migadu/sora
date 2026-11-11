//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// lmtpBackend is a plain LMTP backend with its own spool, so the message it stored can be
// read back.
type lmtpBackend struct {
	addr    string
	tempDir string
}

func startLMTPBackend(t *testing.T, rdb *resilient.ResilientDatabase, name string) *lmtpBackend {
	t.Helper()
	ctx := context.Background()
	s3 := &storage.S3Storage{}
	tempDir := t.TempDir()
	uploadWorker, err := uploader.New(ctx, tempDir, 10, 2, 3, 5*time.Second, 0, name, rdb, s3, nil, make(chan error, 1))
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	t.Cleanup(func() { uploadWorker.Stop() })
	addr := common.GetRandomAddress(t)
	srv, err := lmtp.New(ctx, name, name+".example", addr, s3, rdb, uploadWorker, lmtp.LMTPServerOptions{
		TrustedNetworks: []string{"127.0.0.0/8", "::1/128"},
	})
	if err != nil {
		t.Fatalf("lmtp.New(%s): %v", name, err)
	}
	go func() { srv.Start(make(chan error, 1)) }()
	t.Cleanup(func() { srv.Close() })
	time.Sleep(200 * time.Millisecond)
	return &lmtpBackend{addr: addr, tempDir: tempDir}
}

type countingLookup struct {
	mu    sync.Mutex
	pools map[string]string
	calls atomic.Int64
}

func newCountingLookup(t *testing.T) (*countingLookup, string) {
	t.Helper()
	l := &countingLookup{pools: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.calls.Add(1)
		email := r.URL.Query().Get("email")
		l.mu.Lock()
		pool, known := l.pools[email]
		l.mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		out := map[string]any{"address": email}
		if pool != "" {
			out["pool"] = pool
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return l, srv.URL + "/lookup?email=$email"
}

func (l *countingLookup) set(email, pool string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pools[email] = pool
}

func startLMTPProxyWithPools(t *testing.T, rdb *resilient.ResilientDatabase, pools []proxy.PoolSpec, lookupURL string, cache *config.LookupCacheConfig) string {
	t.Helper()
	addr := common.GetRandomAddress(t)
	p, err := lmtpproxy.New(context.Background(), rdb, "proxy.example", lmtpproxy.ServerOptions{
		Name:            "test-proxy-pools",
		Addr:            addr,
		Pools:           pools,
		RemotePort:      24,
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
		ConnectTimeout:  5 * time.Second,
		AuthIdleTimeout: 30 * time.Second,
		LookupCache:     cache,
		RemoteLookup:    &config.RemoteLookupConfig{Enabled: true, URL: lookupURL, Timeout: "5s"},
	})
	if err != nil {
		t.Fatalf("lmtpproxy.New: %v", err)
	}
	go func() { _ = p.Start() }()
	t.Cleanup(func() { p.Stop() })
	time.Sleep(200 * time.Millisecond)
	return addr
}

// deliverThrough runs one LMTP transaction through the proxy and returns the RCPT reply and,
// when the recipient was accepted, the end-of-DATA reply.
func deliverThrough(t *testing.T, proxyAddr, rcpt string) (rcptReply, dataReply string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	r := bufio.NewReader(conn)
	read := func(what string) string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read %s: %v", what, err)
		}
		return strings.TrimSpace(line)
	}
	read("greeting")
	fmt.Fprintf(conn, "LHLO %s\r\n", traceClientHELO)
	for {
		if line := read("LHLO"); len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	fmt.Fprintf(conn, "MAIL FROM:<sender@example.com>\r\n")
	if resp := read("MAIL FROM"); !strings.HasPrefix(resp, "250") {
		t.Fatalf("MAIL FROM: %s", resp)
	}
	fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", rcpt)
	rcptReply = read("RCPT TO")
	if !strings.HasPrefix(rcptReply, "250") {
		return rcptReply, ""
	}
	fmt.Fprintf(conn, "DATA\r\n")
	if resp := read("DATA"); !strings.HasPrefix(resp, "354") {
		t.Fatalf("DATA: %s", resp)
	}
	fmt.Fprintf(conn, "From: sender@example.com\r\nTo: %s\r\nSubject: pool settings\r\nMessage-ID: <ps-%d@example.com>\r\n\r\nbody\r\n.\r\n", rcpt, time.Now().UnixNano())
	dataReply = read("end of DATA")
	return rcptReply, dataReply
}

// TestLMTPProxyXCLIENTIsPerPool: whether the proxy forwards the client's identity with
// XCLIENT is a per-pool setting. Two identical backends in two pools of one proxy: the
// message delivered through the pool with XCLIENT on carries the client's HELO in its
// Received: header, the one through the pool with XCLIENT off carries the proxy's.
func TestLMTPProxyXCLIENTIsPerPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	backendA := startLMTPBackend(t, rdb, "storage-a")
	backendB := startLMTPBackend(t, rdb, "storage-b")

	stamp := time.Now().UnixNano()
	userA := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("xclient-a-%d@example.com", stamp), "pw")
	userB := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("xclient-b-%d@example.com", stamp), "pw")
	lookup, lookupURL := newCountingLookup(t)
	lookup.set(userA.Email, "pool-a")
	lookup.set(userB.Email, "pool-b")

	proxyAddr := startLMTPProxyWithPools(t, rdb, []proxy.PoolSpec{
		{Name: "pool-a", Backends: []string{backendA.addr}, Settings: proxy.BackendSettings{UseXCLIENT: true}},
		{Name: "pool-b", Backends: []string{backendB.addr}, Settings: proxy.BackendSettings{UseXCLIENT: false}},
	}, lookupURL, nil)

	for _, d := range []struct {
		user    common.TestAccount
		backend *lmtpBackend
		want    string
		not     string
	}{
		{userA, backendA, "from " + traceClientHELO, "from proxy.example"},
		{userB, backendB, "from proxy.example", "from " + traceClientHELO},
	} {
		rcpt, data := deliverThrough(t, proxyAddr, d.user.Email)
		if !strings.HasPrefix(rcpt, "250") || !strings.HasPrefix(data, "250") {
			t.Fatalf("%s: RCPT %q, DATA %q", d.user.Email, rcpt, data)
		}
		time.Sleep(500 * time.Millisecond)
		stored := readBackendStored(t, d.backend.tempDir)
		if !strings.Contains(stored, d.want) {
			t.Errorf("%s: Received: must say %q\n--- stored head ---\n%s", d.user.Email, d.want, storedHead(stored))
		}
		if strings.Contains(stored, d.not) {
			t.Errorf("%s: Received: must not say %q\n--- stored head ---\n%s", d.user.Email, d.not, storedHead(stored))
		}
	}
}

// TestLMTPProxyCachedPoolOutlivesLookupAnswer: within the lookup cache's positive TTL a
// recipient is routed by the pool the cached answer named, without asking the lookup again,
// even after the answer has changed; once the TTL has passed the new answer applies.
func TestLMTPProxyCachedPoolOutlivesLookupAnswer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	backend := startLMTPBackend(t, rdb, "storage-cache")

	user := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-cache-%d@example.com", time.Now().UnixNano()), "pw")
	lookup, lookupURL := newCountingLookup(t)
	lookup.set(user.Email, "live")

	const ttl = 2 * time.Second
	proxyAddr := startLMTPProxyWithPools(t, rdb, []proxy.PoolSpec{
		{Name: "live", Backends: []string{backend.addr}},
		{Name: "dead", Backends: []string{"127.0.0.1:1"}},
	}, lookupURL, &config.LookupCacheConfig{Enabled: true, PositiveTTL: ttl.String(), NegativeTTL: "1s", CleanupInterval: "1s", MaxSize: 100})

	rcpt := func(what string) string {
		t.Helper()
		reply, _ := deliverThrough(t, proxyAddr, user.Email)
		return reply
	}
	if reply := rcpt("first"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("first RCPT: %s", reply)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("first RCPT asked the lookup %d times, want 1", n)
	}
	if reply := rcpt("second"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("second RCPT within the TTL: %s", reply)
	}
	lookup.set(user.Email, "dead")
	if reply := rcpt("after change"); !strings.HasPrefix(reply, "250") {
		t.Fatalf("RCPT within the TTL after the answer changed: %s (the cached pool must still route)", reply)
	}
	if n := lookup.calls.Load(); n != 1 {
		t.Fatalf("RCPTs within the TTL asked the lookup again (%d calls)", n)
	}
	time.Sleep(ttl + 500*time.Millisecond)
	if reply := rcpt("after ttl"); !strings.HasPrefix(reply, "451") {
		t.Fatalf("RCPT after the TTL with the dead-pool answer: %s, want 451", reply)
	}
	if n := lookup.calls.Load(); n != 2 {
		t.Fatalf("RCPT after the TTL asked the lookup %d times in total, want 2", n)
	}
}
