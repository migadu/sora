package imap

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/migadu/go-imap"
)

// sessionEndErrors returns the errors pgx gives on a connection whose server ends the
// session under a statement with the given error, in order: the statement in flight gets
// that error and pgx closes the connection, so the next statement on it gets
// "conn closed" (pgconn.ErrConnClosed).
func sessionEndErrors(t *testing.T, fatal *pgproto3.ErrorResponse) (inFlight, next error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		backend := pgproto3.NewBackend(c, c)
		if _, err := backend.ReceiveStartupMessage(); err != nil {
			return
		}
		backend.Send(&pgproto3.AuthenticationOk{})
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if err := backend.Flush(); err != nil {
			return
		}
		if _, err := backend.Receive(); err != nil {
			return
		}
		backend.Send(fatal)
		_ = backend.Flush()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := pgconn.Connect(ctx, "postgres://test@"+ln.Addr().String()+"/test?sslmode=disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(ctx)
	_, inFlight = conn.Exec(ctx, "SELECT 1").ReadAll()
	_, next = conn.Exec(ctx, "SELECT 1").ReadAll()
	if inFlight == nil || next == nil {
		t.Fatalf("statements across the end of the session: %v, %v; want two errors", inFlight, next)
	}
	return inFlight, next
}

// TestInternalErrorDatabaseConnectionClosedIsUnavailable: a database connection closed
// under a command (PostgreSQL shutting down, a pooler in front of it losing its server
// connection, or a pooled connection the database side or a relay in front of it closed)
// is a subsystem being down. internalError answers NO [UNAVAILABLE], RFC 5530 section 3:
// "Temporary failure because a subsystem is down", not NO [SERVERBUG]: "The server
// encountered a bug in itself or violated one of its own invariants", with the driver's
// error text.
func TestInternalErrorDatabaseConnectionClosedIsUnavailable(t *testing.T) {
	// PostgreSQL shutting down (fast shutdown) or pg_terminate_backend.
	shutdown, next := sessionEndErrors(t, &pgproto3.ErrorResponse{
		Severity:            "FATAL",
		SeverityUnlocalized: "FATAL",
		Code:                "57P01",
		Message:             "terminating connection due to administrator command",
	})
	// PgBouncer in front of PostgreSQL ends its client's session with FATAL 08P01 (its
	// default SQLSTATE) when the server connection under the client fails, as it does
	// when PostgreSQL crashes or is stopped in immediate mode.
	crashed, _ := sessionEndErrors(t, &pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     "08P01",
		Message:  "server conn crashed?",
	})
	for _, tc := range []struct {
		name string
		err  error
		code imap.ResponseCode
	}{
		{"admin shutdown", shutdown, imap.ResponseCodeUnavailable},
		{"conn closed", next, imap.ResponseCodeUnavailable},
		{"pooler server connection crashed", crashed, imap.ResponseCodeUnavailable},
		// PgBouncer while it cannot reach PostgreSQL at all.
		{"pooler cannot log in to the server", &pgconn.PgError{
			Severity: "FATAL",
			Code:     "08P01",
			Message:  "server login has been failing, cached error: connect failed (server_login_retry)",
		}, imap.ResponseCodeUnavailable},
		// lc_messages localizes S; the unlocalized V field still says FATAL.
		{"localized admin shutdown", &pgconn.PgError{
			Severity:            "ВАЖНО",
			SeverityUnlocalized: "FATAL",
			Code:                "57P01",
			Message:             "terminating connection due to administrator command",
		}, imap.ResponseCodeUnavailable},
		// PostgreSQL also uses 08P01 at ERROR for a malformed protocol message: the
		// statement was rejected and the session goes on, so that is not the database
		// being down.
		{"protocol violation in a statement", &pgconn.PgError{
			Severity:            "ERROR",
			SeverityUnlocalized: "ERROR",
			Code:                "08P01",
			Message:             `bind message supplies 1 parameters, but prepared statement "" requires 2`,
		}, imap.ResponseCodeServerBug},
		// A statement the database rejected is not the database being down.
		{"unique violation", &pgconn.PgError{
			Severity: "ERROR",
			Code:     "23505",
			Message:  "duplicate key value violates unique constraint",
		}, imap.ResponseCodeServerBug},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := (&IMAPSession{}).internalError("failed to create default mailboxes: %v", tc.err)
			if response.Type != imap.StatusResponseTypeNo || response.Code != tc.code {
				t.Fatalf("error %q: response=%v, want NO [%s]", tc.err, response, tc.code)
			}
			if tc.code == imap.ResponseCodeUnavailable && strings.Contains(response.Text, tc.err.Error()) {
				t.Fatalf("response exposes the driver error: %s", response.Text)
			}
		})
	}
}
