//go:build integration

package lmtpproxy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/proxy"
)

// TestLMTPProxyHeldBackendRefusesRecipientOfADownPool: once every backend of a pool is
// marked unhealthy, routing names no backend for its users at all. A transaction already
// holding another pool's backend must still defer such a recipient (451), not forward it
// to the held backend, which would accept it into the wrong pool.
func TestLMTPProxyHeldBackendRefusesRecipientOfADownPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend, _ := common.SetupLMTPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	stamp := time.Now().UnixNano()
	live := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-held-live-%d@example.com", stamp), "pw")
	down := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-held-down-%d@example.com", stamp), "pw")
	pools := map[string]string{live.Email: "sora-live", down.Email: "sora-down"}

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		pool, known := pools[email]
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": pool})
	}))
	defer lookup.Close()

	proxyAddr := common.GetRandomAddress(t)
	srv, err := lmtpproxy.New(context.Background(), rdb, "localhost", lmtpproxy.ServerOptions{
		Name: "test-proxy-pools-health",
		Addr: proxyAddr,
		Pools: []proxy.PoolSpec{
			{Name: "sora-live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
			{Name: "sora-down", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		},
		RemotePort:               25,
		TrustedProxies:           []string{"127.0.0.0/8", "::1/128"},
		ConnectTimeout:           2 * time.Second,
		AuthIdleTimeout:          30 * time.Second,
		EnableBackendHealthCheck: true,
		RemoteLookup:             &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "5s"},
	})
	if err != nil {
		t.Fatalf("lmtpproxy.New: %v", err)
	}
	go func() { _ = srv.Start() }()
	time.Sleep(100 * time.Millisecond)
	defer srv.Stop()

	open := func() *LMTPClient {
		t.Helper()
		client, err := NewLMTPClient(proxyAddr)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		client.SendCommand("LHLO localhost")
		client.ReadMultilineResponse()
		client.SendCommand("MAIL FROM:<sender@example.com>")
		if resp, _ := client.ReadResponse(); !strings.HasPrefix(resp, "250") {
			t.Fatalf("MAIL FROM: %s", resp)
		}
		return client
	}
	rcpt := func(client *LMTPClient, email string) string {
		t.Helper()
		if err := client.SendCommand(fmt.Sprintf("RCPT TO:<%s>", email)); err != nil {
			t.Fatalf("RCPT TO %s: %v", email, err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("RCPT TO %s response: %v", email, err)
		}
		return resp
	}

	// Deliveries to the down pool fail until its only backend is marked unhealthy
	// (three consecutive failures).
	for i := 0; i < 3; i++ {
		client := open()
		if resp := rcpt(client, down.Email); !strings.HasPrefix(resp, "451") {
			t.Fatalf("attempt %d for the down pool: %s, want 451", i+1, resp)
		}
		client.Close()
	}

	client := open()
	defer client.Close()
	if resp := rcpt(client, live.Email); !strings.HasPrefix(resp, "250") {
		t.Fatalf("recipient in the live pool: %s", resp)
	}
	if resp := rcpt(client, down.Email); !strings.HasPrefix(resp, "451") {
		t.Fatalf("down pool's recipient in a transaction held on the live pool's backend: %s, want 451 (not delivered into the live pool)", resp)
	}
}
