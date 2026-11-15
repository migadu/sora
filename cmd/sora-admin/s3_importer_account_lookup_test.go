//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
)

// TestS3Importer_AccountLookupErrors is TestImportAccountLookupErrors for `import s3`,
// on PostgreSQL: a run, dry or not, reports a missing account as one, with the hint to
// create it, and a database error (here a closed pool) as a lookup that failed. The
// lookup comes before the scan, so the run needs no S3.
func TestS3Importer_AccountLookupErrors(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	// No account has this address.
	const email = "lookup-s3@example.com"
	modes := []struct {
		name   string
		dryRun bool
	}{
		{"dry run", true},
		{"import", false},
	}
	run := func(t *testing.T, dryRun bool) error {
		t.Helper()
		si, err := NewS3Importer(context.Background(), rdb, nil, S3ImporterOptions{Email: email, DryRun: dryRun, CleanupDB: true})
		if err != nil {
			t.Fatal(err)
		}
		return si.Run()
	}

	for _, mode := range modes {
		t.Run("account missing/"+mode.name, func(t *testing.T) {
			err := run(t, mode.dryRun)
			if !errors.Is(err, consts.ErrUserNotFound) {
				t.Fatalf("error = %v, want an error wrapping %v", err, consts.ErrUserNotFound)
			}
			if msg := err.Error(); !strings.Contains(msg, "account not found") || !strings.Contains(msg, "sora-admin accounts create --email "+email) {
				t.Errorf("error = %q, want it to say the account was not found, with the hint to create it", msg)
			}
		})
	}

	// The database is gone: every lookup fails, whether or not the account exists.
	rdb.Close()
	for _, mode := range modes {
		t.Run("database error/"+mode.name, func(t *testing.T) {
			err := run(t, mode.dryRun)
			if err == nil {
				t.Fatal("the run succeeded on a closed database")
			}
			msg := err.Error()
			if errors.Is(err, consts.ErrUserNotFound) || strings.Contains(msg, "account not found") || strings.Contains(msg, "accounts create") {
				t.Errorf("a failed lookup is reported as a missing account: %q", msg)
			}
			if !strings.Contains(msg, "failed to look up account") {
				t.Errorf("error = %q, want it to say the account lookup failed", msg)
			}
		})
	}
}
