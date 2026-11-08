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

// TestLMTPProxyPools: a recipient whose lookup answer names a pool is delivered through
// that pool's backend; within one transaction a recipient of another pool is deferred
// (451) rather than handed to the backend already held; a pool whose only member is dead,
// an unknown pool and an answer without a pool (no default) are deferred, never routed
// into the live pool.
func TestLMTPProxyPools(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, _ := common.SetupLMTPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	stamp := time.Now().UnixNano()
	live := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-live-%d@example.com", stamp), "pw")
	dead := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-dead-%d@example.com", stamp), "pw")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-unknown-%d@example.com", stamp), "pw")
	nopool := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("lmtp-none-%d@example.com", stamp), "pw")

	pools := map[string]string{live.Email: "sora-live", dead.Email: "sora-dead", unknown.Email: "sora-missing", nopool.Email: ""}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		pool, known := pools[email]
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		answer := map[string]any{"address": email}
		if pool != "" {
			answer["pool"] = pool
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(answer)
	}))
	defer lookup.Close()

	proxyAddr := common.GetRandomAddress(t)
	srv, err := lmtpproxy.New(context.Background(), rdb, "localhost", lmtpproxy.ServerOptions{
		Name: "test-proxy-pools",
		Addr: proxyAddr,
		Pools: []proxy.PoolSpec{
			{Name: "sora-live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
			{Name: "sora-dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		},
		RemotePort:      25,
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
		ConnectTimeout:  5 * time.Second,
		AuthIdleTimeout: 30 * time.Second,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              lookup.URL + "/lookup?email=$email",
			Timeout:          "5s",
			LookupLocalUsers: false,
		},
	})
	if err != nil {
		t.Fatalf("lmtpproxy.New: %v", err)
	}
	go func() { _ = srv.Start() }()
	time.Sleep(100 * time.Millisecond)
	defer srv.Stop()

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

	// One transaction: the live pool's recipient is accepted through its backend; every
	// other recipient is deferred, since the held backend is not in their pool.
	client := open()
	if resp := rcpt(client, live.Email); !strings.HasPrefix(resp, "250") {
		t.Fatalf("recipient in the live pool: %s", resp)
	}
	for name, email := range map[string]string{"dead pool": dead.Email, "unknown pool": unknown.Email, "no pool": nopool.Email} {
		if resp := rcpt(client, email); !strings.HasPrefix(resp, "451") {
			t.Errorf("%s recipient in a transaction held on the live backend: %s, want 451", name, resp)
		}
	}
	client.Close()

	// Fresh transactions: with no backend held yet, the same recipients are still deferred
	// (a dead member, no pool to route into), never delivered through the live pool.
	for name, email := range map[string]string{"dead pool": dead.Email, "unknown pool": unknown.Email, "no pool": nopool.Email} {
		client := open()
		if resp := rcpt(client, email); !strings.HasPrefix(resp, "451") {
			t.Errorf("%s recipient in a fresh transaction: %s, want 451", name, resp)
		}
		client.Close()
	}
}
