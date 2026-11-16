package db

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/jackc/pgx/v5"
)

type migrationDropRollbackConn struct {
	net.Conn
	seen chan struct{}
	once sync.Once
}

func (c *migrationDropRollbackConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("ROLLBACK")) {
		c.once.Do(func() { close(c.seen) })
		return len(p), nil // Simulate a connection that stops delivering cleanup.
	}
	return c.Conn.Write(p)
}

func TestMigrationDriverRollbackHasBoundedCleanup(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()
	cfg, err := pgx.ParseConfig(migrationTestConnStr(t))
	if err != nil {
		t.Fatal(err)
	}
	dial := cfg.DialFunc
	seen := make(chan struct{})
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &migrationDropRollbackConn{Conn: c, seen: seen}, nil
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	done := make(chan error, 1)
	go func() {
		done <- (&migrationDriver{conn: conn}).Run(strings.NewReader("BEGIN;\nSELECT 1/0;\nCOMMIT;\n"))
	}()
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		conn.PgConn().Conn().Close()
		<-done
		t.Fatal("migration did not attempt rollback")
	}
	select {
	case err := <-done:
		var migrationErr database.Error
		if !errors.As(err, &migrationErr) || !strings.Contains(migrationErr.Err, "division by zero") {
			t.Fatalf("lost original migration failure: %v", err)
		}
		if !conn.IsClosed() && conn.PgConn().TxStatus() != 'I' {
			t.Fatal("cleanup left an open aborted connection")
		}
	case <-time.After(8 * time.Second):
		conn.PgConn().Conn().Close()
		<-done
		t.Fatal("Run waited indefinitely for an unresponsive rollback")
	}
}
