package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
	// Not knowing the list is not an empty list: the proxies dial nothing until it loads.
	if m.Loaded() {
		t.Fatal("loaded although the initial load failed")
	}
	calls := list.callCount()
	eventually(t, func() bool { return list.callCount() >= calls+3 }, "polls retrying the initial load")
	if m.Loaded() {
		t.Fatal("loaded although every load failed")
	}

	list.set([]string{"10.0.0.5"}, nil)
	eventually(t, func() bool { return m.Contains("10.0.0.5:143") }, "maintenance on to be polled")
	if !m.Loaded() {
		t.Fatal("not loaded after a successful poll")
	}

	list.set(nil, errors.New("database unavailable"))
	calls = list.callCount()
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

// The servers whose sessions the node must let finish report them.
var (
	_ drainSessionSource = (*imap.IMAPServer)(nil)
	_ drainSessionSource = (*lmtp.LMTPServerBackend)(nil)
	_ drainSessionSource = (*adminapi.Server)(nil)
	_ drainSessionSource = (*pop3.POP3Server)(nil)
)

type fakeServer struct{}

func (fakeServer) ReloadConfig(config.ServerConfig) error { return nil }

type fakeUploadServer struct {
	fakeServer
	open int64
}

func (f fakeUploadServer) DrainSessions() int64 { return f.open }

// The node's drain sessions are those of every server that has them; a proxy server has
// none.
func TestDrainSessionsSumsTheServersThatHaveThem(t *testing.T) {
	deps := &serverDependencies{}
	deps.registerServer("imap", fakeUploadServer{open: 2})
	deps.registerServer("lmtp", fakeUploadServer{open: 1})
	deps.registerServer("imap-proxy", fakeServer{})

	if open := deps.drainSessions(); open != 3 {
		t.Fatalf("drain sessions = %d open, want 3", open)
	}
}

// fakeReporting is what a sessionsReporter talks to: the node's maintenance as the
// database answers it, its session count, and the reports it writes.
type fakeReporting struct {
	mu         sync.Mutex
	since      *time.Time // the maintenance the node is in, past refuse_after
	refusalErr error
	reportErr  error
	open       int64
	reports    []db.InstanceSessions

	gate            *server.MaintenanceGate
	countedRefusing []bool // whether the gate refused at each count
}

// reporter returns the node's reporter (newSessionsReporter) talking to f.
func (f *fakeReporting) reporter() *sessionsReporter {
	r := newSessionsReporter("node-1", func(context.Context) (*time.Time, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.since, f.refusalErr
	}, func() int64 {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.countedRefusing = append(f.countedRefusing, f.gate.Refusing())
		return f.open
	}, func(_ context.Context, s db.InstanceSessions) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reports = append(f.reports, s)
		return f.reportErr
	})
	f.gate = r.gate
	return r
}

func (f *fakeReporting) set(fn func(f *fakeReporting)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeReporting) last(t *testing.T) db.InstanceSessions {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		t.Fatal("no report written")
	}
	return f.reports[len(f.reports)-1]
}

// A node refuses new sessions until it knows it is not in maintenance: a process that
// starts while its node is in maintenance must not let a session in before its first look
// (an earlier process's report of none open would still read as current). The first look
// lets them in.
func TestSessionsReporter_RefusesUntilItKnows(t *testing.T) {
	f := &fakeReporting{refusalErr: errors.New("database unavailable")}
	r := f.reporter()
	gate := r.gate
	if !gate.Refusing() {
		t.Fatal("a new reporter's gate admits sessions before any look")
	}

	r.tick(context.Background(), time.Second)
	if !gate.Refusing() {
		t.Fatal("accepting sessions before the node could look up its maintenance")
	}
	if got := f.last(t); got.RefusingSince != nil {
		t.Fatalf("report %+v claims a maintenance the node could not look up", got)
	}

	f.set(func(f *fakeReporting) { f.refusalErr = nil })
	r.tick(context.Background(), time.Second)
	if gate.Refusing() {
		t.Fatal("still refusing sessions once the node knows it is not in maintenance")
	}
}

// The node refuses BEFORE it counts, and reports the maintenance it refuses for with that
// count: a report of refusing and none open then holds for every later moment.
func TestSessionsReporter_RefusesBeforeItCounts(t *testing.T) {
	began := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	f := &fakeReporting{open: 2}
	r := f.reporter()
	gate := r.gate
	r.tick(context.Background(), time.Second)
	if gate.Refusing() {
		t.Fatal("refusing sessions out of maintenance")
	}

	f.set(func(f *fakeReporting) { f.since = &began })
	r.tick(context.Background(), time.Second)
	if !gate.Refusing() {
		t.Fatal("not refusing sessions in maintenance")
	}
	if len(f.countedRefusing) != 2 || !f.countedRefusing[1] {
		t.Fatalf("counted with the gate refusing = %v, want the gate set before the count", f.countedRefusing)
	}
	got := f.last(t)
	if got.InstanceID != "node-1" || got.Open != 2 || got.RefusingSince == nil || !got.RefusingSince.Equal(began) {
		t.Fatalf("report = %+v, want node-1, 2 open, refusing since %v", got, began)
	}
	if v := testutil.ToFloat64(metrics.BackendMaintenanceRefusing); v != 1 {
		t.Fatalf("refusing gauge = %v, want 1", v)
	}

	f.set(func(f *fakeReporting) { f.since = nil })
	r.tick(context.Background(), time.Second)
	if gate.Refusing() || f.last(t).RefusingSince != nil {
		t.Fatalf("after maintenance ended: refusing=%v, report %+v; want accepting", gate.Refusing(), f.last(t))
	}
	if v := testutil.ToFloat64(metrics.BackendMaintenanceRefusing); v != 0 {
		t.Fatalf("refusing gauge = %v, want 0", v)
	}
}

// A lookup that fails keeps what the node knew: the gate as it was, and the report naming
// the same maintenance (the gate has refused for it throughout).
func TestSessionsReporter_FailedLookupKeepsTheLastState(t *testing.T) {
	began := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	f := &fakeReporting{since: &began}
	r := f.reporter()
	gate := r.gate
	r.tick(context.Background(), time.Second)

	f.set(func(f *fakeReporting) { f.since, f.refusalErr = nil, errors.New("database unavailable") })
	r.tick(context.Background(), time.Second)
	if !gate.Refusing() {
		t.Fatal("a failed lookup let sessions in")
	}
	if got := f.last(t); got.RefusingSince == nil || !got.RefusingSince.Equal(began) {
		t.Fatalf("report after a failed lookup = %+v, want still refusing since %v", got, began)
	}
}

// The node reports at once, then every interval. A failed report does not stop the next,
// and the reports end with ctx.
func TestSessionsReporter_Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := &fakeReporting{reportErr: errors.New("database unavailable")}
	r := f.reporter()
	reported := func() []db.InstanceSessions {
		f.mu.Lock()
		defer f.mu.Unlock()
		return append([]db.InstanceSessions(nil), f.reports...)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx, 10*time.Millisecond)
	}()

	eventually(t, func() bool { return len(reported()) >= 2 }, "reports after a failed one")
	f.set(func(f *fakeReporting) { f.reportErr, f.open = nil, 3 })
	eventually(t, func() bool {
		r := reported()
		return r[len(r)-1].Open == 3
	}, "a report of the new count")

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

	for _, deps := range []*serverDependencies{
		{resilientDB: &resilient.ResilientDatabase{}, instanceID: "proxy-1"},
		{uploadWorker: &uploader.UploadWorker{}, instanceID: "backend-1"},
	} {
		startSessionsReport(ctx, deps)
		if deps.maintenanceGate != nil {
			t.Fatalf("%s: a node that does not report its sessions got a maintenance gate", deps.instanceID)
		}
	}
	time.Sleep(50 * time.Millisecond) // a report that should not have started would have panicked by now
}
