package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
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

// The servers whose sessions stage uploads report them.
var (
	_ uploadSessionSource = (*imap.IMAPServer)(nil)
	_ uploadSessionSource = (*lmtp.LMTPServerBackend)(nil)
	_ uploadSessionSource = (*adminapi.Server)(nil)
)

type fakeServer struct{}

func (fakeServer) ReloadConfig(config.ServerConfig) error { return nil }

type fakeUploadServer struct {
	fakeServer
	open, started int64
}

func (f fakeUploadServer) UploadSessions() (int64, int64) { return f.open, f.started }

// The node's upload sessions are those of every server that has them; a proxy server has
// none.
func TestUploadSessionsSumsTheServersThatHaveThem(t *testing.T) {
	deps := &serverDependencies{}
	deps.registerServer("imap", fakeUploadServer{open: 2, started: 10})
	deps.registerServer("lmtp", fakeUploadServer{open: 1, started: 4})
	deps.registerServer("imap-proxy", fakeServer{})

	open, started := deps.uploadSessions()
	if open != 3 || started != 14 {
		t.Fatalf("upload sessions = %d open, %d started; want 3 open, 14 started", open, started)
	}
}

// The node reports at once, then every interval: under its instance id, with the current
// counts, and with one Since for the life of the process (sora-admin tells a restart by
// it). A failed report does not stop the next, and the reports end with ctx.
func TestRunSessionsReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var open, started atomic.Int64
	var mu sync.Mutex
	var reports []db.InstanceSessions
	const failing = 2
	failures := failing
	report := func(_ context.Context, s db.InstanceSessions) error {
		mu.Lock()
		defer mu.Unlock()
		reports = append(reports, s)
		if failures > 0 {
			failures--
			return errors.New("database unavailable")
		}
		return nil
	}
	reported := func() []db.InstanceSessions {
		mu.Lock()
		defer mu.Unlock()
		return append([]db.InstanceSessions(nil), reports...)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSessionsReport(ctx, "node-1", 10*time.Millisecond, func() (int64, int64) { return open.Load(), started.Load() }, report)
	}()

	eventually(t, func() bool { return len(reported()) >= 1 }, "the first report")
	if first := reported()[0]; first.Open != 0 || first.Started != 0 {
		t.Fatalf("first report = %+v, want nothing open or started", first)
	}
	open.Store(3)
	started.Store(5)
	eventually(t, func() bool {
		r := reported()
		return len(r) > failing+1 && r[len(r)-1].Open == 3 && r[len(r)-1].Started == 5
	}, "a report of the new counts after the failed ones")

	for _, r := range reported() {
		if r.InstanceID != "node-1" || !r.Since.Equal(reported()[0].Since) || r.Since.IsZero() {
			t.Fatalf("report %+v: want instance node-1 and one Since throughout", r)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("still reporting after ctx was cancelled")
	}
}

// Only a node with an uploader stages uploads, and the report needs a database: either
// missing, nothing reports. The database stand-in is unconnected and panics if touched.
func TestStartSessionsReport_OnlyWithUploaderAndDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startSessionsReport(ctx, &serverDependencies{resilientDB: &resilient.ResilientDatabase{}, instanceID: "proxy-1"})
	startSessionsReport(ctx, &serverDependencies{uploadWorker: &uploader.UploadWorker{}, instanceID: "backend-1"})
	time.Sleep(50 * time.Millisecond) // a report that should not have started would have panicked by now
}
