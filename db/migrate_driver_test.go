package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/golang-migrate/migrate/v4/database"
	"github.com/jackc/pgx/v5"
)

// A failed migration must say where in the file it failed, as golang-migrate's pgx/v5
// driver did: PostgreSQL's message and the line its error position points at, not
// "in line 0" with the whole file.
func TestMigrationDriverRunReportsFailingLine(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, migrationTestConnStr(t))
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer conn.Close(ctx)

	d := &migrationDriver{conn: conn}
	err = d.Run(strings.NewReader("SELECT 1;\n\nSELECT no_such_column FROM pg_class;\n"))

	var migErr database.Error
	if !errors.As(err, &migErr) {
		t.Fatalf("Run returned %T %v, want a database.Error", err, err)
	}
	if migErr.Line != 3 {
		t.Errorf("Line = %d, want 3: %v", migErr.Line, err)
	}
	if !strings.Contains(migErr.Err, `column "no_such_column" does not exist`) {
		t.Errorf("Err = %q, want PostgreSQL's message", migErr.Err)
	}
}
