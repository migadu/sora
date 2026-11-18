package delivery

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
)

// fakeRedirectRecords is an in-memory redirect_deliveries.
type fakeRedirectRecords struct {
	rows      map[string][]string // delivery hash -> targets
	lookupErr error
	recordErr error
	lookups   int
}

func (f *fakeRedirectRecords) RedirectedTargetsWithRetry(_ context.Context, _ int64, hash string) ([]string, error) {
	f.lookups++
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	return f.rows[hash], nil
}

func (f *fakeRedirectRecords) RecordRedirectDeliveryWithRetry(_ context.Context, _ int64, hash, to string) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	if f.rows == nil {
		f.rows = map[string][]string{}
	}
	f.rows[hash] = append(f.rows[hash], to)
	return nil
}

// fakeHoldQueue records what is held, handed over and aborted.
type fakeHoldQueue struct {
	refuseHold, refuseCommit string
	held, committed, aborted []string
}

func (q *fakeHoldQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	return errors.New("not used")
}

func (q *fakeHoldQueue) Hold(from, to, messageType string, messageBytes []byte) (func() error, func(), error) {
	if to == q.refuseHold {
		return nil, nil, errors.New("queue full")
	}
	q.held = append(q.held, to)
	commit := func() error {
		if to == q.refuseCommit {
			return errors.New("rename failed")
		}
		q.committed = append(q.committed, to)
		return nil
	}
	return commit, func() { q.aborted = append(q.aborted, to) }, nil
}

type fakeDirectRelay struct{ sent []string }

func (r *fakeDirectRelay) SendToExternalRelay(from, to string, messageBytes []byte) error {
	r.sent = append(r.sent, to)
	return nil
}

type captureRedirectLog struct{ lines []string }

func (l *captureRedirectLog) add(level, msg string, kv []any) {
	l.lines = append(l.lines, fmt.Sprintf("%s %s %v", level, msg, kv))
}
func (l *captureRedirectLog) DebugLog(msg string, kv ...any) { l.add("DEBUG", msg, kv) }
func (l *captureRedirectLog) InfoLog(msg string, kv ...any)  { l.add("INFO", msg, kv) }
func (l *captureRedirectLog) WarnLog(msg string, kv ...any)  { l.add("WARN", msg, kv) }

func (l *captureRedirectLog) has(level, msg string) bool {
	return slices.ContainsFunc(l.lines, func(s string) bool { return strings.HasPrefix(s, level+" "+msg) })
}

type redirectHoldFixture struct {
	records *fakeRedirectRecords
	queue   *fakeHoldQueue
	log     *captureRedirectLog
	charged int
	notify  int
}

func newRedirectHoldFixture() *redirectHoldFixture {
	return &redirectHoldFixture{records: &fakeRedirectRecords{}, queue: &fakeHoldQueue{}, log: &captureRedirectLog{}}
}

func (f *redirectHoldFixture) hold(hash string) RedirectHold {
	from, _ := server.NewAddress("sender@example.com")
	owner, _ := server.NewAddress("owner@example.com")
	return RedirectHold{
		Records:      f.records,
		Queue:        f.queue,
		Notify:       func() { f.notify++ },
		Log:          f.log,
		AccountID:    7,
		DeliveryHash: hash,
		From:         &from,
		Owner:        &owner,
		MessageBytes: []byte("Subject: x\r\n\r\nbody\r\n"),
	}
}

func (f *redirectHoldFixture) result(targets ...string) sieveengine.Result {
	return sieveengine.Result{
		Action:         sieveengine.ActionRedirect,
		RedirectTo:     targets,
		RecordRedirect: func(context.Context) error { f.charged++; return nil },
	}
}

// The retry dedup of #1912/#1942, in the one implementation LMTP and the Admin API share
// (#1969): a target an earlier attempt recorded is skipped and counts as held; the
// others are recorded only once handed over, and only those are charged.
func TestRedirectHold_SkipsRecordedTargetsAndRecordsAfterHandOver(t *testing.T) {
	f := newRedirectHoldFixture()
	f.records.rows = map[string][]string{"h1": {"one@example.com"}}

	commit, abort, allHeld := f.hold("h1").Hold(context.Background(), f.result("one@example.com", "two@example.org"))
	defer abort()
	if !allHeld {
		t.Fatal("allHeld = false, want true: a target already queued counts as held")
	}
	if !slices.Equal(f.queue.held, []string{"two@example.org"}) {
		t.Fatalf("held %v, want only the target not yet queued", f.queue.held)
	}
	if !f.log.has("INFO", "sieve redirect already queued by an earlier attempt of this delivery, skipping") {
		t.Errorf("no skip line logged: %v", f.log.lines)
	}
	if got := f.records.rows["h1"]; len(got) != 1 {
		t.Fatalf("recorded before hand-over: %v", got)
	}
	if !commit() {
		t.Fatal("commit = false, want true")
	}
	if !slices.Equal(f.records.rows["h1"], []string{"one@example.com", "two@example.org"}) {
		t.Errorf("records %v, want the handed-over target added", f.records.rows["h1"])
	}
	if f.charged != 1 || f.notify != 1 {
		t.Errorf("charged %d, notified %d, want 1 and 1: only the target handed over", f.charged, f.notify)
	}

	// The retry of the delivery hands over nothing.
	g := newRedirectHoldFixture()
	g.records = f.records
	commit, abort, allHeld = g.hold("h1").Hold(context.Background(), g.result("one@example.com", "two@example.org"))
	defer abort()
	if !allHeld || !commit() || len(g.queue.held) != 0 || g.charged != 0 {
		t.Errorf("retry: allHeld %v held %v charged %d, want everything skipped", allHeld, g.queue.held, g.charged)
	}
}

// Without a delivery hash there is nothing to look up or record; the redirect still goes.
func TestRedirectHold_EmptyDeliveryHash(t *testing.T) {
	f := newRedirectHoldFixture()
	commit, abort, allHeld := f.hold("").Hold(context.Background(), f.result("one@example.com"))
	defer abort()
	if !allHeld || !commit() {
		t.Fatal("redirect without a delivery hash not handed over")
	}
	if f.records.lookups != 0 || len(f.records.rows) != 0 {
		t.Errorf("lookups %d, rows %v, want none for an empty hash", f.records.lookups, f.records.rows)
	}
	if !slices.Equal(f.queue.committed, []string{"one@example.com"}) {
		t.Errorf("committed %v", f.queue.committed)
	}
}

// The failure modes err toward a duplicate, never toward a lost redirect.
func TestRedirectHold_RecordFailuresErrTowardDuplicates(t *testing.T) {
	t.Run("lookup fails", func(t *testing.T) {
		f := newRedirectHoldFixture()
		f.records.rows = map[string][]string{"h1": {"one@example.com"}}
		f.records.lookupErr = errors.New("db down")
		commit, abort, allHeld := f.hold("h1").Hold(context.Background(), f.result("one@example.com"))
		defer abort()
		if !allHeld || !commit() || !slices.Equal(f.queue.committed, []string{"one@example.com"}) {
			t.Errorf("committed %v, want the target queued again when the lookup fails", f.queue.committed)
		}
		if !f.log.has("WARN", "could not check for redirects queued by an earlier attempt, queuing all") {
			t.Errorf("no warning: %v", f.log.lines)
		}
	})
	t.Run("record fails", func(t *testing.T) {
		f := newRedirectHoldFixture()
		f.records.recordErr = errors.New("db down")
		commit, abort, _ := f.hold("h1").Hold(context.Background(), f.result("one@example.com"))
		defer abort()
		if !commit() || f.charged != 1 {
			t.Errorf("a failed record must not fail the hand-over or the charge (charged %d)", f.charged)
		}
		if !f.log.has("WARN", "failed to record a queued redirect, a retry of this delivery would queue it again") {
			t.Errorf("no warning: %v", f.log.lines)
		}
	})
}

// A target the queue refuses is not held; one it fails to hand over is neither recorded
// nor charged; abort drops what is still held.
func TestRedirectHold_QueueFailuresAndAbort(t *testing.T) {
	f := newRedirectHoldFixture()
	f.queue.refuseHold, f.queue.refuseCommit = "bad@example.com", "late@example.com"
	commit, abort, allHeld := f.hold("h1").Hold(context.Background(), f.result("bad@example.com", "late@example.com", "ok@example.com"))
	if allHeld {
		t.Error("allHeld = true with a target the queue refused")
	}
	if commit() {
		t.Error("commit = true with a target that failed to hand over")
	}
	if !slices.Equal(f.records.rows["h1"], []string{"ok@example.com"}) || f.charged != 1 {
		t.Errorf("records %v charged %d, want only ok@example.com", f.records.rows["h1"], f.charged)
	}
	abort()
	if len(f.queue.aborted) != 0 {
		t.Errorf("abort after commit dropped %v", f.queue.aborted)
	}

	g := newRedirectHoldFixture()
	_, abort, _ = g.hold("h1").Hold(context.Background(), g.result("one@example.com"))
	abort()
	if !slices.Equal(g.queue.aborted, []string{"one@example.com"}) || len(g.records.rows) != 0 {
		t.Errorf("abort: aborted %v records %v", g.queue.aborted, g.records.rows)
	}
}

// A direct relay handler cannot hold: commit sends, records and charges, and there is no
// queue worker to wake.
func TestRedirectHold_DirectRelayHandler(t *testing.T) {
	f := newRedirectHoldFixture()
	relay := &fakeDirectRelay{}
	h := f.hold("h1")
	h.Queue, h.Handler = nil, relay
	commit, abort, allHeld := h.Hold(context.Background(), f.result("one@example.com"))
	defer abort()
	if len(relay.sent) != 0 {
		t.Fatal("sent before commit")
	}
	if !allHeld || !commit() || !slices.Equal(relay.sent, []string{"one@example.com"}) {
		t.Fatalf("sent %v", relay.sent)
	}
	if !slices.Equal(f.records.rows["h1"], []string{"one@example.com"}) || f.charged != 1 || f.notify != 0 {
		t.Errorf("records %v charged %d notified %d", f.records.rows["h1"], f.charged, f.notify)
	}
}

// No relay, or no sender to relay from: nothing is held and the message is kept.
func TestRedirectHold_NotPossible(t *testing.T) {
	for name, edit := range map[string]func(*RedirectHold){
		"no relay":  func(h *RedirectHold) { h.Queue, h.Handler = nil, nil },
		"no sender": func(h *RedirectHold) { h.From = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRedirectHoldFixture()
			h := f.hold("h1")
			edit(&h)
			commit, abort, allHeld := h.Hold(context.Background(), f.result("one@example.com"))
			defer abort()
			if allHeld || !commit() || len(f.queue.held) != 0 || f.records.lookups != 0 {
				t.Errorf("allHeld %v held %v lookups %d", allHeld, f.queue.held, f.records.lookups)
			}
		})
	}
}
