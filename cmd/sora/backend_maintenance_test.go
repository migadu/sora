package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
)

// scriptedList is a maintenance list whose answer the test changes between polls.
type scriptedList struct {
	mu    sync.Mutex
	hosts []string
	err   error
	calls int
}

func (s *scriptedList) set(hosts []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts, s.err = hosts, err
}

func (s *scriptedList) load(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.hosts, s.err
}

func (s *scriptedList) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A proxy that restarts while a backend is in maintenance must honor it from its first
// connection, not after its first poll: the list is loaded before runBackendMaintenance
// returns, and the proxy servers start after that.
func TestRunBackendMaintenance_LoadsBeforeReturning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	list := &scriptedList{hosts: []string{"10.0.0.5"}}
	m := runBackendMaintenance(ctx, config.MaintenanceConfig{PollInterval: "1h"}, list.load)

	if !m.Contains("10.0.0.5:143") {
		t.Fatal("backend in maintenance at startup not honored before the first poll")
	}
	if list.callCount() != 1 {
		t.Fatalf("list loaded %d times before returning, want 1", list.callCount())
	}
}

// After startup the list is polled: maintenance turned on, a database failure (which must
// not end it), and maintenance turned off all reach the proxies.
func TestRunBackendMaintenance_FollowsTheListAfterStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	list := &scriptedList{err: errors.New("database unavailable")}
	m := runBackendMaintenance(ctx, config.MaintenanceConfig{PollInterval: "10ms"}, list.load)
	if m.Contains("10.0.0.5:143") {
		t.Fatal("failed initial load produced a maintenance entry")
	}

	list.set([]string{"10.0.0.5"}, nil)
	eventually(t, func() bool { return m.Contains("10.0.0.5:143") }, "maintenance on to be polled")

	list.set(nil, errors.New("database unavailable"))
	calls := list.callCount()
	eventually(t, func() bool { return list.callCount() >= calls+3 }, "polls during the outage")
	if !m.Contains("10.0.0.5:143") {
		t.Fatal("a database outage ended maintenance")
	}

	list.set(nil, nil)
	eventually(t, func() bool { return !m.Contains("10.0.0.5:143") }, "maintenance off to be polled")
}

func TestHasProxyServer(t *testing.T) {
	for _, typ := range []string{"imap_proxy", "pop3_proxy", "managesieve_proxy", "lmtp_proxy", "user_api_proxy"} {
		if !hasProxyServer([]config.ServerConfig{{Type: "imap"}, {Type: typ}}) {
			t.Errorf("%s not recognized as a proxy server", typ)
		}
	}
	if hasProxyServer([]config.ServerConfig{{Type: "imap"}, {Type: "lmtp"}, {Type: "http_admin_api"}, {Type: "metrics"}}) {
		t.Error("a node with backend servers only counted as having a proxy")
	}
}

func TestStartBackendMaintenance_OnlyForProxiesWithADatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The database here is an unconnected stand-in: a backend-only node must return before
	// touching it (it would panic or fail to load if it did not).
	backendOnly := &serverDependencies{
		config: config.Config{DynamicServers: []config.ServerConfig{
			{Type: "imap", Name: "imap", Addr: ":143"},
		}},
		resilientDB: &resilient.ResilientDatabase{},
	}
	if m := startBackendMaintenance(ctx, backendOnly); m != nil {
		t.Fatal("a node without proxy servers started backend maintenance")
	}

	proxyWithoutDB := &serverDependencies{config: config.Config{DynamicServers: []config.ServerConfig{
		{Type: "lmtp_proxy", Name: "lmtp", Addr: ":24"},
	}}}
	if m := startBackendMaintenance(ctx, proxyWithoutDB); m != nil {
		t.Fatal("a proxy without a database started backend maintenance it cannot load")
	}
}

func TestAttachBackendMaintenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cm, err := proxy.NewConnectionManager([]string{"10.0.0.5:143", "10.0.0.6:143"}, 143, false, false, false, time.Second)
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}

	// No maintenance set on this node (no proxies or no database): nothing is attached.
	(&serverDependencies{}).attachBackendMaintenance(ctx, "IMAP-test", cm, nil)
	if cm.InMaintenance("10.0.0.5:143") {
		t.Fatal("attached a maintenance set that does not exist")
	}

	m := proxy.NewMaintenance()
	swept := make(chan struct{})
	var once sync.Once
	deps := &serverDependencies{maintenance: m}
	deps.attachBackendMaintenance(ctx, "IMAP-test", cm, func() []proxy.DrainTarget {
		once.Do(func() { close(swept) })
		return nil
	})

	m.Set([]string{"10.0.0.5"})
	if !cm.InMaintenance("10.0.0.5:143") || cm.InMaintenance("10.0.0.6:143") {
		t.Fatal("the proxy's connection manager does not honor the shared maintenance set")
	}
	select {
	case <-swept: // the drain was started and swept the server's sessions
	case <-time.After(5 * time.Second):
		t.Fatal("the session drain was not started for the proxy")
	}
}
