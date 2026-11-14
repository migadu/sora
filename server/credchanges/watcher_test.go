package credchanges

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// steps records, across every fake, what the watcher did in which order.
type steps struct {
	mu  sync.Mutex
	got []string
}

func (s *steps) add(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, fmt.Sprintf(format, args...))
}

func (s *steps) take() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	got := s.got
	s.got = nil
	return got
}

type fakeAuthCache struct{ s *steps }

func (f *fakeAuthCache) InvalidateAccounts(_ context.Context, ids []int64) error {
	f.s.add("auth-cache %v", ids)
	return nil
}

type fakeLoginCache struct {
	s    *steps
	name string
}

func (f *fakeLoginCache) InvalidateAccounts(ids []int64) {
	f.s.add("%s %v", f.name, ids)
}

type fakeSessions struct {
	s    *steps
	name string
	open map[int64]int
}

func (f *fakeSessions) EndLocalSessions(accountID int64) int {
	n := f.open[accountID]
	delete(f.open, accountID)
	f.s.add("%s end %d (%d open)", f.name, accountID, n)
	return n
}

// fakeTable answers the poll as credential_changes would.
type fakeTable struct {
	mu     sync.Mutex
	since  []time.Time
	answer db.CredentialChanges
	err    error
	prunes []time.Time
}

func (f *fakeTable) load(_ context.Context, since time.Time) (db.CredentialChanges, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.since = append(f.since, since)
	if f.err != nil {
		return db.CredentialChanges{}, f.err
	}
	return f.answer, nil
}

func (f *fakeTable) prune(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prunes = append(f.prunes, before)
	return 0, nil
}

func (f *fakeTable) lastSince() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.since[len(f.since)-1]
}

func (f *fakeTable) set(answer db.CredentialChanges, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer, f.err = answer, err
}

func newTestWatcher(table *fakeTable, sinks Sinks, lookback time.Duration) *Watcher {
	return New(table.load, table.prune, sinks, lookback)
}

// A change reaches every login cache on the node, the persistent one first, and only
// an account taken out of service has its sessions ended.
func TestRefreshAppliesToEveryCacheOfTheNode(t *testing.T) {
	s := &steps{}
	readAt := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	table := &fakeTable{answer: db.CredentialChanges{ReadAt: readAt, Accounts: []int64{1, 2}, Removed: []int64{2}}}
	imapSessions := &fakeSessions{s: s, name: "imap", open: map[int64]int{1: 1, 2: 3}}
	pop3Sessions := &fakeSessions{s: s, name: "pop3", open: map[int64]int{}}
	w := newTestWatcher(table, Sinks{
		AuthCache: &fakeAuthCache{s: s},
		LoginCaches: func() []LoginCache {
			return []LoginCache{&fakeLoginCache{s: s, name: "imap-proxy"}, &fakeLoginCache{s: s, name: "pop3"}}
		},
		Sessions: func() []SessionEnder { return []SessionEnder{imapSessions, pop3Sessions} },
	}, 0)

	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	want := []string{
		"auth-cache [1 2]", // first: a login missing an in-memory cache falls back to it
		"imap-proxy [1 2]",
		"pop3 [1 2]",
		"imap end 2 (3 open)",
		"pop3 end 2 (0 open)",
	}
	if got := s.take(); !slices.Equal(got, want) {
		t.Errorf("Refresh did\n  %q\nwant\n  %q", got, want)
	}
	if imapSessions.open[1] != 1 {
		t.Error("a password change ended the account's sessions")
	}
}

// Every read goes back a window before the previous one, so that a change committed
// after a read but stamped before it is not missed, and a failed read is followed by
// one from where the last good read was, however long the database was away. A change
// is applied again at every read while inside the window: that drops what a login racing
// the first application, or reading a lagging replica, put back.
func TestRefreshRereadsAWindowAndResumesAfterAFailure(t *testing.T) {
	s := &steps{}
	first := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	table := &fakeTable{answer: db.CredentialChanges{ReadAt: first, Accounts: []int64{7}}}
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}}, time.Hour)

	before := time.Now()
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if got := table.lastSince(); got.After(before.Add(-time.Hour)) || got.Before(before.Add(-time.Hour-time.Minute)) {
		t.Errorf("first read starts at %v, want the lookback (1h) before now (%v)", got, before)
	}

	second := first.Add(PollInterval)
	table.set(db.CredentialChanges{ReadAt: second, Accounts: []int64{7}}, nil)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh: %v", err)
	}
	if got, want := table.lastSince(), first.Add(-rereadWindow); !got.Equal(want) {
		t.Errorf("second read starts at %v, want %v (the first read less the window)", got, want)
	}
	if got := s.take(); !slices.Equal(got, []string{"auth-cache [7]", "auth-cache [7]"}) {
		t.Errorf("a change inside the window is applied at every read: %q", got)
	}

	table.set(db.CredentialChanges{}, errors.New("database unavailable"))
	for range 3 {
		if err := w.Refresh(context.Background()); err == nil {
			t.Fatal("Refresh hid the failed read")
		}
	}
	if got := s.take(); len(got) != 0 {
		t.Errorf("a failed read applied %q", got)
	}

	table.set(db.CredentialChanges{ReadAt: second.Add(10 * time.Minute)}, nil)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh after the failures: %v", err)
	}
	if got, want := table.lastSince(), second.Add(-rereadWindow); !got.Equal(want) {
		t.Errorf("read after the outage starts at %v, want %v (the last good read less the window)", got, want)
	}
}

// Without a persistent cache there is nothing a restart could have kept, so the first
// read looks back only the window; with one it covers the cache's whole max age.
func TestFirstReadLooksBackAtLeastTheWindow(t *testing.T) {
	s := &steps{}
	table := &fakeTable{answer: db.CredentialChanges{ReadAt: time.Now()}}
	w := newTestWatcher(table, Sinks{LoginCaches: func() []LoginCache { return []LoginCache{&fakeLoginCache{s: s}} }}, 0)
	before := time.Now()
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := table.lastSince(); got.After(before.Add(-rereadWindow)) {
		t.Errorf("first read starts at %v, want at least the window before %v", got, before)
	}
}

// A node with nothing to apply a change to reads nothing.
func TestRefreshWithoutSinksReadsNothing(t *testing.T) {
	table := &fakeTable{}
	w := newTestWatcher(table, Sinks{
		LoginCaches: func() []LoginCache { return nil },
		Sessions:    func() []SessionEnder { return nil },
	}, 0)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(table.since) != 0 {
		t.Errorf("read the table %d times with nothing to apply it to", len(table.since))
	}
}

// Rows older than the retention are pruned at the first read and then about hourly,
// by the database clock.
func TestRefreshPrunesHourly(t *testing.T) {
	s := &steps{}
	t0 := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	table := &fakeTable{}
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}}, 0)

	for _, at := range []time.Time{t0, t0.Add(30 * time.Minute), t0.Add(time.Hour), t0.Add(90 * time.Minute)} {
		table.set(db.CredentialChanges{ReadAt: at}, nil)
		if err := w.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []time.Time{t0.Add(-Retention), t0.Add(time.Hour - Retention)}
	if !slices.EqualFunc(table.prunes, want, time.Time.Equal) {
		t.Errorf("pruned before %v, want %v", table.prunes, want)
	}
}
