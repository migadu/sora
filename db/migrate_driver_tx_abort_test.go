package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
)

// When a migration file uses an explicit BEGIN ... COMMIT block and fails mid-way,
// PostgreSQL stops processing the simple-protocol query before COMMIT and leaves the
// session in aborted transaction state (TxStatus == 'E'). migrationDriver.Run must
// roll that failed transaction back so subsequent Version/SetVersion calls on the
// same driver (such as golang-migrate's Version() and Force()) do not fail with
// SQLSTATE 25P02 ("current transaction is aborted").
func TestMigrationDriverRunRollsBackFailedExplicitTransaction(t *testing.T) {
	skipDatabaseTestInShortMode(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, migrationTestConnStr(t))
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer conn.Close(ctx)

	schema := pgx.Identifier{fmt.Sprintf("mig_driver_tx_abort_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	defer func() {
		if conn.PgConn().TxStatus() != 'I' {
			_, _ = conn.Exec(ctx, "ROLLBACK")
		}
		_, _ = conn.Exec(ctx, "RESET search_path")
		_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	}()
	if _, err := conn.Exec(ctx, "SET search_path = "+schema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE TABLE schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)"); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	t.Run("driver Run leaves connection usable for Version and SetVersion", func(t *testing.T) {
		d := &migrationDriver{conn: conn}
		if err := d.SetVersion(1, true); err != nil {
			t.Fatalf("initial SetVersion: %v", err)
		}

		err := d.Run(strings.NewReader("BEGIN;\nSELECT 1/0;\nCOMMIT;\n"))
		var migErr database.Error
		if !errors.As(err, &migErr) {
			t.Fatalf("Run returned %T %v, want database.Error", err, err)
		}
		if got := conn.PgConn().TxStatus(); got != 'I' {
			t.Errorf("conn TxStatus after failed Run = %q, want 'I'", got)
		}

		v, dirty, err := d.Version()
		if err != nil {
			t.Fatalf("Version() after failed explicit-tx Run failed: %v", err)
		}
		if v != 1 || !dirty {
			t.Fatalf("Version() = (%d, %v), want (1, true)", v, dirty)
		}

		if err := d.SetVersion(0, false); err != nil {
			t.Fatalf("SetVersion() after failed explicit-tx Run failed: %v", err)
		}
	})

	t.Run("golang-migrate Version and Force recover after failed explicit-tx migration", func(t *testing.T) {
		// Reset connection state in case the earlier subtest left an aborted tx on main.
		if conn.PgConn().TxStatus() != 'I' {
			_, _ = conn.Exec(ctx, "ROLLBACK")
		}
		if _, err := conn.Exec(ctx, "TRUNCATE schema_migrations"); err != nil {
			t.Fatalf("truncate schema_migrations: %v", err)
		}

		fsys := fstest.MapFS{
			"000001_create_items.up.sql": &fstest.MapFile{
				Data: []byte("CREATE TABLE items (id int NOT NULL);\n"),
			},
			"000002_broken_tx.up.sql": &fstest.MapFile{
				Data: []byte("BEGIN;\nINSERT INTO items VALUES (1);\nSELECT 1/0;\nCOMMIT;\n"),
			},
		}
		src, err := iofs.New(fsys, ".")
		if err != nil {
			t.Fatalf("iofs.New: %v", err)
		}
		m, err := migrate.NewWithInstance("iofs", src, "pgx5", &migrationDriver{conn: conn})
		if err != nil {
			t.Fatalf("migrate.NewWithInstance: %v", err)
		}

		if err := m.Up(); err == nil {
			t.Fatal("m.Up() succeeded, want failure on migration 2")
		}

		v, dirty, err := m.Version()
		if err != nil {
			t.Fatalf("m.Version() after failed explicit-tx Up() failed: %v", err)
		}
		if v != 2 || !dirty {
			t.Fatalf("m.Version() = (%d, %v), want (2, true)", v, dirty)
		}
		var inserted int
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM items").Scan(&inserted); err != nil || inserted != 0 {
			t.Fatalf("failed explicit migration left %d rows, err=%v, want no partial writes", inserted, err)
		}

		if err := m.Force(1); err != nil {
			t.Fatalf("m.Force(1) after failed explicit-tx Up() failed: %v", err)
		}
		v, dirty, err = m.Version()
		if err != nil || dirty || v != 1 {
			t.Fatalf("m.Version() after Force(1) = (%d, %v, %v), want (1, false, nil)", v, dirty, err)
		}
	})
}
