package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// dryRunLookupDB answers the dry run's two lookups through the given functions: the
// account's own mailbox of a name, and whether a message is already in it.
type dryRunLookupDB struct {
	*mockResilientDatabase
	mailboxID func(ctx context.Context) (int64, error)
	exists    func(ctx context.Context, count *int) error
}

func (m *dryRunLookupDB) GetOwnedMailboxIDByNameWithRetry(ctx context.Context, accountID int64, name string) (int64, error) {
	return m.mailboxID(ctx)
}

func (m *dryRunLookupDB) QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row {
	return rowFunc(func(dest ...any) error { return m.exists(ctx, dest[0].(*int)) })
}

type rowFunc func(dest ...any) error

func (f rowFunc) Scan(dest ...any) error { return f(dest...) }

// runCapturingStdout runs f and returns what it printed to stdout, and its error.
func runCapturingStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	ferr := f()
	w.Close()
	os.Stdout = stdout
	return <-out, ferr
}

// TestDryRunStopsOnInterruptAndLookupErrors: `import maildir --dry-run` reports, per
// message, whether the import would store it. Only a mailbox that does not exist yet
// makes a message "would import" without asking; an interrupt (Ctrl-C cancels the
// context) or a failed database lookup leaves the rest of the messages unchecked, so
// the dry run must stop with that error (a non-zero exit) instead of listing them as
// "IMPORT ... new message" under a complete-looking summary.
func TestDryRunStopsOnInterruptAndLookupErrors(t *testing.T) {
	const messages = 5
	errUnavailable := errors.New("simulated database unavailable")
	mailboxExists := func(context.Context) (int64, error) { return 7, nil }
	notImported := func(_ context.Context, count *int) error { *count = 0; return nil }

	run := func(t *testing.T, newDB func(cancel context.CancelFunc) resilientDB) (string, error) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		importer, err := NewImporter(ctx, newCleanupDBMaildir(t, messages), "user@example.com", 1, nil, nil,
			ImporterOptions{DryRun: true, TestMode: true})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = newDB(cancel)
		return runCapturingStdout(t, importer.Run)
	}
	wantStopped := func(t *testing.T, out string, err, want error, maxReported int) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("Run() = %v, want an error wrapping %v", err, want)
		}
		if strings.Contains(out, "Overall Summary") {
			t.Errorf("the stopped dry run printed the overall summary:\n%s", out)
		}
		if n := strings.Count(out, "Action: IMPORT"); n > maxReported {
			t.Errorf("the dry run reported %d messages as IMPORT, want at most %d (the ones it checked):\n%s", n, maxReported, out)
		}
	}

	t.Run("a mailbox that does not exist yet: every message would import", func(t *testing.T) {
		out, err := run(t, func(context.CancelFunc) resilientDB { return newMockResilientDatabase() })
		require.NoError(t, err)
		if !strings.Contains(out, "Would import: 5 messages") {
			t.Errorf("dry run output does not count the 5 messages as would import:\n%s", out)
		}
	})

	t.Run("interrupt between messages", func(t *testing.T) {
		// The interrupt arrives while the first message is checked: it is reported,
		// the four after it are not.
		out, err := run(t, func(cancel context.CancelFunc) resilientDB {
			return &dryRunLookupDB{mockResilientDatabase: newMockResilientDatabase(), mailboxID: mailboxExists,
				exists: func(ctx context.Context, count *int) error { cancel(); return notImported(ctx, count) }}
		})
		wantStopped(t, out, err, context.Canceled, 1)
	})

	t.Run("interrupt during the mailbox lookup", func(t *testing.T) {
		out, err := run(t, func(cancel context.CancelFunc) resilientDB {
			return &dryRunLookupDB{mockResilientDatabase: newMockResilientDatabase(),
				mailboxID: func(ctx context.Context) (int64, error) { cancel(); return 0, ctx.Err() },
				exists:    notImported}
		})
		wantStopped(t, out, err, context.Canceled, 0)
	})

	t.Run("database error on the mailbox lookup", func(t *testing.T) {
		out, err := run(t, func(context.CancelFunc) resilientDB {
			return &dryRunLookupDB{mockResilientDatabase: newMockResilientDatabase(),
				mailboxID: func(context.Context) (int64, error) { return 0, errUnavailable },
				exists:    notImported}
		})
		wantStopped(t, out, err, errUnavailable, 0)
	})

	t.Run("database error on the existence check", func(t *testing.T) {
		out, err := run(t, func(context.CancelFunc) resilientDB {
			return &dryRunLookupDB{mockResilientDatabase: newMockResilientDatabase(), mailboxID: mailboxExists,
				exists: func(context.Context, *int) error { return errUnavailable }}
		})
		wantStopped(t, out, err, errUnavailable, 0)
	})
}
