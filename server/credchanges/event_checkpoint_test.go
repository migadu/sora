package credchanges

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// Event identities are delivery acknowledgements, including the Resume step.
// A failed attempt must replay the same events; a reset must replay even events
// successfully applied while xmin was pinned.
func TestEventDedupAcknowledgesOnlyCompleteDeliveryAndResets(t *testing.T) {
	for _, failure := range []string{"sink", "resume"} {
		t.Run(failure, func(t *testing.T) {
			at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
			answer := boundary(at, 10, 42)
			answer.Events = []db.CredentialChangeEvent{{ID: 1, AccountID: 42, WriterXID: 11}}
			table := &fakeTable{answer: answer}
			calls := &steps{}
			cache := &fakeAuthCache{s: calls}
			wantErr := errors.New("delivery unavailable")
			var resumeErr error
			if failure == "sink" {
				cache.err = wantErr
			} else {
				resumeErr = wantErr
			}
			resets := 0
			w := newTestWatcher(table, Sinks{
				AuthCache:    cache,
				Synchronized: func(context.Context) error { return resumeErr },
				Reset:        func(context.Context) error { resets++; return nil },
			}, 0)
			if err := w.Refresh(context.Background()); !errors.Is(err, wantErr) {
				t.Fatalf("first delivery = %v", err)
			}
			if w.cursor != 0 || len(w.applied) != 0 {
				t.Fatal("failed delivery acknowledged event")
			}
			cache.err, resumeErr = nil, nil
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := calls.take(); !slices.Equal(got, []string{"auth-cache [42]", "auth-cache [42]"}) {
				t.Fatalf("retry deliveries = %v", got)
			}
			if len(w.applied) != 1 {
				t.Fatal("successful pinned event was not tracked")
			}
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := calls.take(); len(got) != 0 {
				t.Fatalf("acknowledged event replayed: %v", got)
			}
			answer.ReadAt = at.Add(Retention)
			table.answer = answer
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := calls.take(); !slices.Equal(got, []string{"auth-cache [42]"}) || resets != 1 {
				t.Fatalf("reset delivery = %v, resets=%d", got, resets)
			}
			// Once xmin passes the event writer, its acknowledgement is no
			// longer needed, and the feed may legitimately return no rows.
			table.answer = boundary(answer.ReadAt.Add(time.Second), 12)
			if err := w.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(w.applied) != 0 {
				t.Fatal("old event acknowledgement retained")
			}
		})
	}
}
