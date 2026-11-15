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

// databaseShutdownErrors returns the errors pgx gives on a connection whose PostgreSQL
// shuts down under it, in order: the statement in flight gets the server's FATAL 57P01
// (admin_shutdown) and pgx closes the connection, so the next statement on it gets
// "conn closed" (pgconn.ErrConnClosed).
func databaseShutdownErrors(t *testing.T) (inFlight, next error) {
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
		backend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "57P01",
			Message:  "terminating connection due to administrator command",
		})
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
		t.Fatalf("statements across a database shutdown: %v, %v; want two errors", inFlight, next)
	}
	return inFlight, next
}

// TestInternalErrorDatabaseConnectionClosedIsUnavailable: a database connection closed
// under a command (PostgreSQL shutting down, or a pooled connection the database side or
// a relay in front of it closed) is a subsystem being down. internalError answers
// NO [UNAVAILABLE], RFC 5530 section 3: "Temporary failure because a subsystem is down",
// not NO [SERVERBUG]: "The server encountered a bug in itself or violated one of its own
// invariants", with the driver's error text.
func TestInternalErrorDatabaseConnectionClosedIsUnavailable(t *testing.T) {
	inFlight, next := databaseShutdownErrors(t)
	for _, tc := range []struct {
		name string
		err  error
		code imap.ResponseCode
	}{
		{"admin shutdown", inFlight, imap.ResponseCodeUnavailable},
		{"conn closed", next, imap.ResponseCodeUnavailable},
		{"crash shutdown", &pgconn.PgError{
			Severity: "FATAL",
			Code:     "57P02",
			Message:  "terminating connection because of crash of another server process",
		}, imap.ResponseCodeUnavailable},
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
