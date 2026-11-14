package resilient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// TestDatabaseBreakerIsSuccessful pins down which errors the database circuit breakers
// count as failures: only the database failing (unreachable, timing out, out of
// resources, shutting down, internal error). An error the database answered with — a
// rejected request, a not-found, a constraint violation — counts as a success, however
// many arrive: otherwise a few bad Admin API requests open the write breaker and refuse
// every write on the node for 30s. The other regression guard is that an *imap.Error —
// returned through the FETCH streaming callback when a body is temporarily unavailable
// from S3 — must not count either, or an S3 outage would cascade into a database outage.
func TestDatabaseBreakerIsSuccessful(t *testing.T) {
	imapUnavailable := &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "Message body temporarily unavailable, please retry"}
	imapServerBug := &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "boom"}

	tests := []struct {
		name    string
		err     error
		failure bool // counts against the breakers
	}{
		{"nil", nil, false},

		// An IMAP protocol error is never a DB system failure.
		{"imap UNAVAILABLE", imapUnavailable, false},
		{"imap UNAVAILABLE wrapped", fmt.Errorf("stream failed: %w", imapUnavailable), false},
		{"imap SERVERBUG", imapServerBug, false},

		// Expected outcomes of a working database.
		{"ErrMessageNotAvailable", consts.ErrMessageNotAvailable, false},
		{"ErrUserNotFound", consts.ErrUserNotFound, false},
		{"ErrMailboxNotFound", consts.ErrMailboxNotFound, false},
		{"pgx.ErrNoRows", pgx.ErrNoRows, false},
		{"pgx.ErrNoRows wrapped", fmt.Errorf("lookup: %w", pgx.ErrNoRows), false},
		{"search result limit", db.ErrSearchTooManyResults, false},
		{"wrapped search result limit", fmt.Errorf("search: %w", db.ErrSearchTooManyResults), false},
		{"ErrDBUniqueViolation", consts.ErrDBUniqueViolation, false},
		{"pg deadlock 40P01", &pgconn.PgError{Code: "40P01"}, false},
		{"pg serialization 40001", &pgconn.PgError{Code: "40001"}, false},

		// Requests the database layer rejects (issue #386).
		{"ErrCannotDeletePrimaryCredential", db.ErrCannotDeletePrimaryCredential, false},
		{"ErrCannotDeleteLastCredential", db.ErrCannotDeleteLastCredential, false},
		{"ErrAccountAlreadyDeleted", db.ErrAccountAlreadyDeleted, false},
		{"ErrAccountNotDeleted", db.ErrAccountNotDeleted, false},
		{"ErrCrossDomainPrimaryChange", db.ErrCrossDomainPrimaryChange, false},
		{"invalid address", fmt.Errorf("invalid new email address: %w", errors.New("missing @")), false},
		{"unsupported hash type", fmt.Errorf("unsupported hash type: %s", "no-such-hash"), false},
		{"pg unique violation 23505", &pgconn.PgError{Code: "23505"}, false},
		{"pg foreign key violation 23503", &pgconn.PgError{Code: "23503"}, false},
		{"pg value too long 22001", fmt.Errorf("insert: %w", &pgconn.PgError{Code: "22001"}), false},
		{"pg index row too large 54000", &pgconn.PgError{Code: "54000"}, false},

		// The caller giving up says nothing about the database.
		{"caller cancelled", context.Canceled, false},
		{"caller cancelled wrapped", fmt.Errorf("receive message failed: %w", context.Canceled), false},

		// The database failing.
		{"connection refused", dialClosedPort(t), true},
		{"connection reset", fmt.Errorf("receive message failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}), true},
		{"connection lost mid-message", fmt.Errorf("receive message failed: %w", io.ErrUnexpectedEOF), true},
		{"connection closed", fmt.Errorf("conn: %w", pgconn.ErrConnClosed), true},
		{"deadline exceeded", context.DeadlineExceeded, true},
		{"read deadline", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}, true},
		{"pg connection failure 08006", &pgconn.PgError{Code: "08006"}, true},
		{"pgbouncer protocol error 08P01", &pgconn.PgError{Code: "08P01"}, true},
		{"pg too many connections 53300", &pgconn.PgError{Code: "53300"}, true},
		{"pg disk full 53100", &pgconn.PgError{Code: "53100"}, true},
		{"pg statement timeout 57014", &pgconn.PgError{Code: "57014"}, true},
		{"pg admin shutdown 57P01", &pgconn.PgError{Code: "57P01"}, true},
		{"pg cannot connect now 57P03", &pgconn.PgError{Code: "57P03"}, true},
		{"pg io error 58030", &pgconn.PgError{Code: "58030"}, true},
		{"pg internal error XX000", &pgconn.PgError{Code: "XX000"}, true},
		{"pg read-only standby 25006", &pgconn.PgError{Code: "25006"}, true},
		{"pg lock timeout 55P03", errors.Join(db.ErrDBLockTimeout, &pgconn.PgError{Code: "55P03"}), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := !isQuerySuccessful(tt.err); got != tt.failure {
				t.Errorf("query breaker counts %v as a failure: %v, want %v", tt.err, got, tt.failure)
			}
			if got := !isWriteSuccessful(tt.err); got != tt.failure {
				t.Errorf("write breaker counts %v as a failure: %v, want %v", tt.err, got, tt.failure)
			}
		})
	}
}

// dialClosedPort returns the error pgx gives for a database that refuses connections.
func dialClosedPort(t *testing.T) error {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgconn.Connect(ctx, "postgres://postgres@"+addr+"/sora?sslmode=disable")
	if err == nil {
		conn.Close(ctx)
		t.Fatalf("connected to closed port %s", addr)
	}
	var connectErr *pgconn.ConnectError
	if !errors.As(err, &connectErr) {
		t.Fatalf("dial %s: %T %v, want *pgconn.ConnectError", addr, err, err)
	}
	return err
}
