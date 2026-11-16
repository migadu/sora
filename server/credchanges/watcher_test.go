package credchanges

import (
	"context"
	"errors"
	"fmt"
	"github.com/migadu/sora/db"
	"slices"
	"sync"
	"testing"
	"time"
)

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

type fakeAuthCache struct {
	s   *steps
	err error
}

func (f *fakeAuthCache) InvalidateAccounts(_ context.Context, ids []int64) error {
	f.s.add("auth-cache %v", ids)
	return f.err
}

type fakeLoginCache struct {
	s    *steps
	name string
}

func (f *fakeLoginCache) InvalidateAccounts(ids []int64) { f.s.add("%s %v", f.name, ids) }

type fakeSessions struct {
	s    *steps
	name string
	open map[int64]int
}

func (f *fakeSessions) EndLocalSessions(id int64) int {
	n := f.open[id]
	delete(f.open, id)
	f.s.add("%s end %d (%d open)", f.name, id, n)
	return n
}

type fakeTable struct {
	mu       sync.Mutex
	since    []int64
	answer   db.CredentialChanges
	err      error
	pruneErr error
	prunes   []time.Time
}

func (f *fakeTable) load(_ context.Context, cursor int64) (db.CredentialChanges, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.since = append(f.since, cursor)
	return f.answer, f.err
}
func (f *fakeTable) prune(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prunes = append(f.prunes, before)
	return 0, f.pruneErr
}
func (f *fakeTable) lastSince() int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.since[len(f.since)-1]
}
func (f *fakeTable) set(answer db.CredentialChanges, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer, f.err = answer, err
}
func lifecycle(s Sinks) Sinks {
	if s.Suspend == nil {
		s.Suspend = func() {}
	}
	if s.Synchronized == nil {
		s.Synchronized = func(context.Context) error { return nil }
	}
	if s.Reset == nil {
		s.Reset = func(context.Context) error { return nil }
	}
	return s
}
func newTestWatcher(table *fakeTable, s Sinks, lookback time.Duration) *Watcher {
	return New(table.load, table.prune, lifecycle(s), lookback)
}
func boundary(at time.Time, cursor int64, ids ...int64) db.CredentialChanges {
	return db.CredentialChanges{ReadAt: at, NextCursor: cursor, Accounts: ids}
}

func TestRefreshAppliesToEveryCacheOfTheNode(t *testing.T) {
	s := &steps{}
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	answer := boundary(at, 10, 1, 2)
	answer.Removed = []int64{2}
	table := &fakeTable{answer: answer}
	sessions := &fakeSessions{s: s, name: "imap", open: map[int64]int{1: 1, 2: 3}}
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}, LoginCaches: func() []LoginCache { return []LoginCache{&fakeLoginCache{s, "proxy"}, &fakeLoginCache{s, "backend"}} }, Sessions: func() []SessionEnder { return []SessionEnder{sessions} }, Suspend: func() { s.add("suspend") }, Synchronized: func(context.Context) error { s.add("resume"); return nil }}, 0)
	if got := s.take(); !slices.Equal(got, []string{"suspend"}) {
		t.Fatalf("startup=%v", got)
	}
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"auth-cache [1 2]", "proxy [1 2]", "backend [1 2]", "imap end 2 (3 open)", "resume"}
	if got := s.take(); !slices.Equal(got, want) {
		t.Fatalf("got%v want%v", got, want)
	}
	if sessions.open[1] != 1 {
		t.Fatal("password change ended an in-service account")
	}
	if w.cursor != 10 {
		t.Fatalf("ack=%d", w.cursor)
	}
}

func TestRefreshAcknowledgesSafeCursorOnlyAfterSuccessfulRetry(t *testing.T) {
	ctx := context.Background()
	s := &steps{}
	at := time.Now()
	table := &fakeTable{answer: boundary(at, 10, 7)}
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}}, time.Hour)
	if err := w.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if table.lastSince() != 0 {
		t.Fatalf("startup cursor=%d, want0 irrespective of lookback", table.lastSince())
	}
	table.set(boundary(at.Add(time.Second), 10, 8), nil)
	if err := w.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if table.lastSince() != 10 || w.cursor != 10 {
		t.Fatal("a pinned safe xmin must still apply other visible changes")
	}
	table.set(db.CredentialChanges{}, errors.New("primary unavailable"))
	for range 3 {
		if err := w.Refresh(ctx); err == nil {
			t.Fatal("hidden load failure")
		}
	}
	table.set(boundary(at.Add(10*time.Minute), 20, 9), nil)
	if err := w.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if table.lastSince() != 10 || w.cursor != 20 {
		t.Fatalf("retry cursor=%d ack=%d", table.lastSince(), w.cursor)
	}
	if got := s.take(); !slices.Equal(got, []string{"auth-cache [7]", "auth-cache [8]", "auth-cache [9]"}) {
		t.Fatal(got)
	}
}

func TestPersistentSinkFailureStillAppliesOthersAndDoesNotAcknowledge(t *testing.T) {
	ctx := context.Background()
	s := &steps{}
	at := time.Now()
	bad := errors.New("sqlite unavailable")
	cache := &fakeAuthCache{s: s, err: bad}
	answer := boundary(at, 20, 1)
	answer.Removed = []int64{1}
	table := &fakeTable{answer: answer}
	syncs := 0
	suspends := 0
	w := newTestWatcher(table, Sinks{AuthCache: cache, LoginCaches: func() []LoginCache { return []LoginCache{&fakeLoginCache{s, "lookup"}} }, Sessions: func() []SessionEnder { return []SessionEnder{&fakeSessions{s, "session", map[int64]int{1: 1}}} }, Suspend: func() { suspends++ }, Synchronized: func(context.Context) error { syncs++; return nil }}, 0)
	if err := w.Refresh(ctx); !errors.Is(err, bad) {
		t.Fatalf("error=%v", err)
	}
	if w.cursor != 0 || !w.appliedAt.IsZero() || !w.lastPrune.IsZero() || syncs != 0 || suspends != 2 {
		t.Fatal("failed application advanced or resumed")
	}
	if got := s.take(); !slices.Equal(got, []string{"auth-cache [1]", "lookup [1]", "session end 1 (1 open)"}) {
		t.Fatal(got)
	}
	cache.err = nil
	if err := w.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if table.lastSince() != 0 || w.cursor != 20 || syncs != 1 {
		t.Fatal("failed batch was not retried before acknowledgement")
	}
}

func TestResumeAndPruneFailuresPreserveCheckpoint(t *testing.T) {
	for _, stage := range []string{"resume"} {
		t.Run(stage, func(t *testing.T) {
			at := time.Now()
			s := &steps{}
			bad := errors.New(stage)
			table := &fakeTable{answer: boundary(at, 30, 1)}
			resErr := error(nil)
			if stage == "prune" {
				table.pruneErr = bad
			} else {
				resErr = bad
			}
			suspended := false
			w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}, Suspend: func() { suspended = true }, Synchronized: func(context.Context) error {
				if resErr != nil {
					return resErr
				}
				suspended = false
				return nil
			}}, 0)
			if err := w.Refresh(context.Background()); !errors.Is(err, bad) {
				t.Fatalf("error=%v", err)
			}
			if w.cursor != 0 || !w.lastPrune.IsZero() || !suspended {
				t.Fatal("failed checkpoint was accepted")
			}
			table.pruneErr = nil
			resErr = nil
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if table.lastSince() != 0 || w.cursor != 30 || suspended {
				t.Fatal("retry did not resume only after success")
			}
		})
	}
}

func TestRetentionClockAndCursorDiscontinuitiesRequireReset(t *testing.T) {
	at := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		when   time.Time
		cursor int64
	}{
		{"retention gap", at.Add(Retention), 20}, {"clock backwards", at.Add(-time.Second), 20}, {"cursor backwards", at.Add(time.Second), 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &steps{}
			table := &fakeTable{answer: boundary(at, 10, 1)}
			resetErr := error(nil)
			resets := 0
			syncs := 0
			w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}, Reset: func(context.Context) error { resets++; return resetErr }, Synchronized: func(context.Context) error { syncs++; return nil }}, 0)
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			table.set(boundary(tc.when, tc.cursor, 2), nil)
			bad := errors.New("full reset failed")
			resetErr = bad
			if err := w.Refresh(context.Background()); !errors.Is(err, bad) {
				t.Fatalf("error=%v", err)
			}
			if w.cursor != 10 || !w.appliedAt.Equal(at) || syncs != 1 || resets != 1 {
				t.Fatal("incomplete full reset advanced checkpoint")
			}
			resetErr = nil
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if w.cursor != tc.cursor || !w.appliedAt.Equal(tc.when) || resets != 2 || syncs != 2 {
				t.Fatal("reset must complete before resume/new boundary")
			}
		})
	}
}

func TestStartupAndEmptyFeedResumeOnlyOnSuccess(t *testing.T) {
	table := &fakeTable{answer: boundary(time.Now(), 40)}
	s := &steps{}
	suspended := false
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}, Suspend: func() { suspended = true }, Synchronized: func(context.Context) error { suspended = false; return nil }}, 0)
	if !suspended {
		t.Fatal("startup trusted cache hits before synchronization")
	}
	table.err = errors.New("down")
	if err := w.Refresh(context.Background()); err == nil || !suspended {
		t.Fatal("failed first refresh trusted cache")
	}
	table.err = nil
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if suspended || w.cursor != 40 {
		t.Fatal("empty successful feed must resume caches and acknowledge")
	}
}

func TestRefreshWithoutSinksReadsNothing(t *testing.T) {
	table := &fakeTable{}
	w := newTestWatcher(table, Sinks{}, 0)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(table.since) != 0 {
		t.Fatal("read without sinks")
	}
}

func TestRefreshPrunesHourlyOnlyAfterSuccess(t *testing.T) {
	s := &steps{}
	at := time.Now()
	table := &fakeTable{}
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}}, 0)
	for i, delta := range []time.Duration{0, 30 * time.Minute, time.Hour, 90 * time.Minute} {
		table.set(boundary(at.Add(delta), int64(10+i)), nil)
		if err := w.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	want := []time.Time{at.Add(-Retention), at.Add(time.Hour - Retention)}
	if !slices.EqualFunc(table.prunes, want, time.Time.Equal) {
		t.Fatalf("prunes=%v", table.prunes)
	}
}

func TestRequiredHooksAndMalformedBoundariesFailClosed(t *testing.T) {
	s := &steps{}
	table := &fakeTable{answer: boundary(time.Now(), 1)}
	w := New(table.load, table.prune, Sinks{AuthCache: &fakeAuthCache{s: s}}, 0)
	if err := w.Refresh(context.Background()); err == nil {
		t.Fatal("missing lifecycle hooks were accepted")
	}
	for _, answer := range []db.CredentialChanges{{NextCursor: 1}, {ReadAt: time.Now(), NextCursor: -1}} {
		table.set(answer, nil)
		w = newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: s}}, 0)
		if err := w.Refresh(context.Background()); err == nil || w.cursor != 0 {
			t.Fatal("invalid boundary was accepted")
		}
	}
}

func TestPruneFailureRetriesCleanupWithoutBlockingDelivery(t *testing.T) {
	at := time.Now()
	steps := &steps{}
	table := &fakeTable{answer: boundary(at, 30, 1), pruneErr: errors.New("cleanup busy")}
	syncs := 0
	w := newTestWatcher(table, Sinks{AuthCache: &fakeAuthCache{s: steps}, Synchronized: func(context.Context) error { syncs++; return nil }}, 0)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.cursor != 30 || !w.lastPrune.IsZero() || syncs != 1 {
		t.Fatal("cleanup failure must not block a successfully applied boundary")
	}
	table.pruneErr = nil
	table.set(boundary(at.Add(time.Second), 35, 2), nil)
	if err := w.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if table.lastSince() != 30 || w.cursor != 35 || len(table.prunes) != 2 || w.lastPrune.IsZero() {
		t.Fatal("cleanup not retried or following event lost")
	}
	if got := steps.take(); !slices.Equal(got, []string{"auth-cache [1]", "auth-cache [2]"}) {
		t.Fatal(got)
	}
}
