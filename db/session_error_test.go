package db

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Severity describes session lifetime independently of SQLSTATE. A fatal
// lock-related error must not be mistaken for an ordinary lock timeout.
func TestSessionEndingSeverityPrecedesLockTimeout(t *testing.T) {
	cases := []struct {
		name, severity, unlocalized, code string
		want                              error
	}{
		{"fatal lock code", "FATAL", "", "55P03", ErrConnectionClosed},
		{"panic lock code", "PANIC", "", "55P03", ErrConnectionClosed},
		{"localized fatal lock code", "ВАЖНО", "FATAL", "55P03", ErrConnectionClosed},
		{"ordinary lock timeout", "ERROR", "ERROR", "55P03", ErrDBLockTimeout},
		{"unlocalized severity wins", "FATAL", "ERROR", "55P03", ErrDBLockTimeout},
		{"ordinary protocol error", "ERROR", "ERROR", "08P01", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause := &pgconn.PgError{Severity: tc.severity, SeverityUnlocalized: tc.unlocalized, Code: tc.code, Message: "review error"}
			wrapped := fmt.Errorf("database operation: %w", cause)
			got := ClassifyDBError(wrapped)
			for _, sentinel := range []error{ErrConnectionClosed, ErrDBLockTimeout} {
				if errors.Is(got, sentinel) != (tc.want == sentinel) {
					t.Errorf("ClassifyDBError = %v, sentinel %v, want %v", got, sentinel, tc.want)
				}
			}
			if !errors.Is(got, wrapped) {
				t.Errorf("wrapped error lost: %v", got)
			}
			var pgErr *pgconn.PgError
			if !errors.As(got, &pgErr) || pgErr != cause {
				t.Errorf("structured cause lost: %v", got)
			}
			if tc.want == nil && got != wrapped {
				t.Errorf("ordinary statement error changed: %v", got)
			}
		})
	}
}

// The first statement on a pooled connection the database side already closed fails
// with io.ErrUnexpectedEOF, not pgconn.ErrConnClosed (that is for the statements after
// it). It is the same closed connection, so it must classify the same way, or a login
// right after a database restart answers [SERVERBUG] instead of [UNAVAILABLE].
func TestClosedSocketEOFIsConnectionClosed(t *testing.T) {
	for _, cause := range []error{io.ErrUnexpectedEOF, pgconn.ErrConnClosed} {
		wrapped := fmt.Errorf("database error getting primary email for account ID 1: %w", cause)
		got := ClassifyDBError(wrapped)
		if !errors.Is(got, ErrConnectionClosed) {
			t.Errorf("ClassifyDBError(%v) = %v, want ErrConnectionClosed", wrapped, got)
		}
		if !errors.Is(got, cause) {
			t.Errorf("ClassifyDBError(%v) lost the cause: %v", wrapped, got)
		}
	}
	// io.EOF never reaches us from pgx (pgproto3 turns it into io.ErrUnexpectedEOF), so
	// it is not taken as a closed connection: it can be some other reader's end.
	if got := ClassifyDBError(fmt.Errorf("x: %w", io.EOF)); errors.Is(got, ErrConnectionClosed) {
		t.Errorf("ClassifyDBError(io.EOF) = %v, want it unclassified", got)
	}
}

// A connection attempt that the other end closes reads EOF too, wrapped in a
// pgconn.ConnectError. That is a failure to connect, not a connection that went dead
// in the pool: classifying it as closed would make every read retry it during an
// outage, adding failures to the circuit breaker until it opens.
func TestConnectAttemptEOFIsFailedToConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Read the whole startup message before closing: closing with it unread
			// would answer with a reset rather than the EOF this test is about.
			var length [4]byte
			if _, err := io.ReadFull(c, length[:]); err == nil {
				_, _ = io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint32(length[:]))-4)
			}
			c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, connErr := pgconn.Connect(ctx, "postgres://u@"+ln.Addr().String()+"/d?sslmode=disable")
	var connectErr *pgconn.ConnectError
	if !errors.As(connErr, &connectErr) || !errors.Is(connErr, io.ErrUnexpectedEOF) {
		t.Fatalf("precondition: connect to a closing listener = %v (%T), want a ConnectError wrapping io.ErrUnexpectedEOF", connErr, connErr)
	}
	got := ClassifyDBError(fmt.Errorf("query: %w", connErr))
	if errors.Is(got, ErrConnectionClosed) || !errors.Is(got, ErrFailedToConnect) {
		t.Errorf("ClassifyDBError(%v) = %v, want ErrFailedToConnect, not ErrConnectionClosed", connErr, got)
	}
}
