package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/proxy"
)

// startTestAdminAPI serves the Admin API built from deps on a free local port and
// returns a GET helper for it.
func startTestAdminAPI(t *testing.T, deps *serverDependencies) func(path string) (int, []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	const apiKey = "test-admin-api-key-0123456789"

	srv, err := adminapi.New(nil, buildAdminAPIServerOptions(deps, config.ServerConfig{Name: "admin-api", Addr: addr, APIKey: apiKey}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Serve(ctx, make(chan error, 1))

	client := &http.Client{Timeout: 5 * time.Second}
	get := func(path string) (int, []byte, error) {
		req, err := http.NewRequest("GET", "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, body, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, err := get("/admin/config"); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("Admin API did not start: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func(path string) (int, []byte) {
		t.Helper()
		code, body, err := get(path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		return code, body
	}
}

// GET /admin/connections/stats reports connections, not accounts: one account with five
// sessions on this node is five connections. An account known here only through another
// node's gossip has no connection on this node, as GET /admin/connections already treats it.
func TestAdminAPIConnectionStatsCountConnections(t *testing.T) {
	tracker := server.NewConnectionTracker("IMAP", "main", "localhost", "node-a", nil, 0, 0, 0, false)
	t.Cleanup(tracker.Stop)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := tracker.RegisterConnection(ctx, 1, "user@example.com", "IMAP", fmt.Sprintf("192.0.2.1:%d", 40000+i)); err != nil {
			t.Fatal(err)
		}
	}
	var event bytes.Buffer
	if err := gob.NewEncoder(&event).Encode(server.ConnectionEvent{
		Type: server.ConnectionEventRegister, EventID: "remote-1", AccountID: 2, Username: "remote@example.com",
		Protocol: "IMAP", ClientAddr: "192.0.2.2:40000", Timestamp: time.Now(), NodeID: "node-b", InstanceID: "node-b",
	}); err != nil {
		t.Fatal(err)
	}
	tracker.HandleClusterEvent(event.Bytes())
	if n := len(tracker.GetAllConnections()); n != 2 {
		t.Fatalf("tracker holds %d accounts, want 2 (one local, one from gossip)", n)
	}

	get := startTestAdminAPI(t, &serverDependencies{
		connectionTrackers: map[string]*server.ConnectionTracker{"IMAP-main": tracker},
		proxyServers:       map[string]adminapi.ProxyServer{},
	})
	code, body := get("/admin/connections/stats")
	var stats struct {
		Total      int            `json:"total_connections"`
		ByProtocol map[string]int `json:"connections_by_protocol"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &stats) != nil {
		t.Fatalf("GET /admin/connections/stats: %d %s", code, body)
	}
	if stats.Total != 5 || stats.ByProtocol["IMAP-main"] != 5 {
		t.Fatalf("total_connections %d, connections_by_protocol %v; want 5 and IMAP-main: 5. Body: %s", stats.Total, stats.ByProtocol, body)
	}
}

type idleProxyServer struct{}

func (idleProxyServer) GetConnectionManager() *proxy.ConnectionManager { return nil }

// Servers register their connection trackers and proxies from their own start goroutines,
// under deps' mutexes, while the Admin API already serves. The Admin API must read those
// maps under the same mutexes (run with -race).
func TestAdminAPIReadsTrackerAndProxyMapsUnderTheirMutex(t *testing.T) {
	deps := &serverDependencies{
		connectionTrackers: make(map[string]*server.ConnectionTracker),
		proxyServers:       make(map[string]adminapi.ProxyServer),
	}
	get := startTestAdminAPI(t, deps)

	trackers := make([]*server.ConnectionTracker, 8)
	for i := range trackers {
		trackers[i] = server.NewConnectionTracker("IMAP", fmt.Sprintf("s%d", i), "localhost", fmt.Sprintf("localhost-s%d", i), nil, 0, 0, 0, true)
		t.Cleanup(trackers[i].Stop)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			n := i % len(trackers)
			deps.connectionTrackersMux.Lock()
			deps.connectionTrackers[fmt.Sprintf("IMAP-s%d", n)] = trackers[n]
			deps.connectionTrackersMux.Unlock()
			deps.proxyServersMux.Lock()
			deps.proxyServers[fmt.Sprintf("IMAP-p%d", n)] = idleProxyServer{}
			deps.proxyServersMux.Unlock()
		}
	}()

	for i := 0; i < 20; i++ {
		for _, path := range []string{"/admin/connections", "/admin/connections/stats", "/admin/connections/user/user@example.com", "/admin/proxy/backends"} {
			if code, body := get(path); code != http.StatusOK {
				t.Errorf("GET %s: %d %s", path, code, body)
			}
		}
	}
	close(stop)
	<-done
}
