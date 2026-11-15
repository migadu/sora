//go:build integration

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

// TestS3Importer_AccountLookupErrors is TestImportAccountLookupErrors for `import s3`:
// its dry run and its per-object import report a missing account as one, with the hint
// to create it, and a database error (here a closed pool) as a lookup that failed.
func TestS3Importer_AccountLookupErrors(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	// No account has this address.
	const email = "lookup-s3@example.com"
	si, err := NewS3Importer(context.Background(), rdb, nil, S3ImporterOptions{Email: email, Workers: 1, CleanupDB: true})
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()

	obj := S3ObjectInfo{Key: helpers.NewS3Key("example.com", "lookup-s3", strings.Repeat("ab", 32))}
	steps := []struct {
		name string
		run  func() error
	}{
		{"dry run", si.performDryRun},
		{"object import", func() error { return si.importS3Object(obj) }},
	}

	for _, step := range steps {
		t.Run("account missing/"+step.name, func(t *testing.T) {
			err := step.run()
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
	for _, step := range steps {
		t.Run("database error/"+step.name, func(t *testing.T) {
			err := step.run()
			if err == nil {
				t.Fatal("the step succeeded on a closed database")
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
