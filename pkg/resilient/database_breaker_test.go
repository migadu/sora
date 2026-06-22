package resilient

import (
	"context"
	"errors"
	"fmt"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
)

// TestDatabaseBreakerIsSuccessful pins down which errors the database circuit breakers
// treat as "successful" (i.e. NOT a database system failure, so they don't trip the
// breaker). The critical regression guard is that an *imap.Error — returned through the
// FETCH streaming callback when a body is temporarily unavailable from S3 — must NOT be
// counted as a DB failure, otherwise an S3 outage could trip the DB breaker and cascade
// into a database-read outage.
func TestDatabaseBreakerIsSuccessful(t *testing.T) {
	imapUnavailable := &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "Message body temporarily unavailable, please retry"}
	imapServerBug := &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "boom"}

	tests := []struct {
		name      string
		err       error
		wantQuery bool
		wantWrite bool
	}{
		{"nil", nil, true, true},

		// The Fix-3 regression guard: an IMAP protocol error is never a DB system failure.
		{"imap UNAVAILABLE", imapUnavailable, true, true},
		{"imap UNAVAILABLE wrapped", fmt.Errorf("stream failed: %w", imapUnavailable), true, true},
		{"imap SERVERBUG", imapServerBug, true, true},

		// Business-logic errors are expected outcomes, not system failures.
		{"ErrMessageNotAvailable", consts.ErrMessageNotAvailable, true, true},
		{"ErrUserNotFound", consts.ErrUserNotFound, true, true},
		{"ErrMailboxNotFound", consts.ErrMailboxNotFound, true, true},
		{"pgx.ErrNoRows", pgx.ErrNoRows, true, true},
		{"pgx.ErrNoRows wrapped", fmt.Errorf("lookup: %w", pgx.ErrNoRows), true, true},

		// Differences between the two predicates.
		{"ErrDBUniqueViolation", consts.ErrDBUniqueViolation, false, true},
		{"pg deadlock 40P01", &pgconn.PgError{Code: "40P01"}, false, true},
		{"pg serialization 40001", &pgconn.PgError{Code: "40001"}, false, true},

		// Genuine system failures must trip the breaker.
		{"pg unique-violation raw 23505", &pgconn.PgError{Code: "23505"}, false, false},
		{"connection refused", errors.New("dial tcp: connect: connection refused"), false, false},
		{"deadline exceeded", context.DeadlineExceeded, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isQuerySuccessful(tt.err); got != tt.wantQuery {
				t.Errorf("isQuerySuccessful(%v) = %v, want %v", tt.err, got, tt.wantQuery)
			}
			if got := isWriteSuccessful(tt.err); got != tt.wantWrite {
				t.Errorf("isWriteSuccessful(%v) = %v, want %v", tt.err, got, tt.wantWrite)
			}
		})
	}
}
