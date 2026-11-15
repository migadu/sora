package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// accountLookupDB fails every account lookup with err.
type accountLookupDB struct {
	*mockResilientDatabase
	err error
}

func (m *accountLookupDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	return 0, m.err
}

// TestImportAccountLookupErrors: every step of `import maildir` that looks the account
// up passes a missing account (consts.ErrUserNotFound) on as one, and the steps whose
// error is shown to the operator once say so, with the hint to create it (the batch
// inserts' error is the reason recorded for each of the batch's messages). Any other
// error, a database unreachable past the retries or an interrupt (Ctrl-C cancels the
// context), is a lookup that failed, for an account that may well exist: it must not
// say the account was not found nor tell the operator to create it.
func TestImportAccountLookupErrors(t *testing.T) {
	const email = "user@example.com"
	errUnavailable := errors.New("simulated database unavailable")

	steps := []struct {
		name string
		hint bool // shown to the operator once: a missing account comes with the hint to create it
		run  func(t *testing.T, i *Importer) error
	}{
		{"subscriptions", true, func(_ *testing.T, i *Importer) error { return i.processSubscriptions() }},
		{"sieve script", true, func(_ *testing.T, i *Importer) error { return i.importSieveScript() }},
		{"dry run", true, func(t *testing.T, i *Importer) error {
			_, err := runCapturingStdout(t, i.performDryRun)
			return err
		}},
		{"batch insert", false, func(_ *testing.T, i *Importer) error {
			_, err := i.insertBatchToDB(nil)
			return err
		}},
		{"batch insert in one transaction", false, func(_ *testing.T, i *Importer) error {
			_, err := i.insertBatchToDBWithTransaction(nil)
			return err
		}},
	}
	lookups := []struct {
		name    string
		err     error // what the lookup returns
		want    error // what the step's error must wrap
		missing bool
	}{
		{"account missing", consts.ErrUserNotFound, consts.ErrUserNotFound, true},
		{"database error", fmt.Errorf("database error fetching account ID: %w", errUnavailable), errUnavailable, false},
		{"interrupt", fmt.Errorf("retry cancelled by context: %w", context.Canceled), context.Canceled, false},
	}

	newImporter := func(t *testing.T, lookupErr error) *Importer {
		t.Helper()
		maildirPath := newCleanupDBMaildir(t, 1)
		require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "subscriptions"), []byte("Sent\nArchive\n"), 0644))
		sievePath := filepath.Join(t.TempDir(), "filter.sieve")
		require.NoError(t, os.WriteFile(sievePath, []byte("keep;\n"), 0644))
		importer, err := NewImporter(context.Background(), maildirPath, email, 1, nil, nil,
			ImporterOptions{TestMode: true, SievePath: sievePath})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = &accountLookupDB{mockResilientDatabase: newMockResilientDatabase(), err: lookupErr}
		return importer
	}

	for _, lookup := range lookups {
		for _, step := range steps {
			t.Run(lookup.name+"/"+step.name, func(t *testing.T) {
				err := step.run(t, newImporter(t, lookup.err))
				if !errors.Is(err, lookup.want) {
					t.Fatalf("error = %v, want an error wrapping %v", err, lookup.want)
				}
				msg := err.Error()
				hint := "sora-admin accounts create --email " + email
				if lookup.missing {
					if step.hint && (!strings.Contains(msg, "account not found") || !strings.Contains(msg, hint)) {
						t.Errorf("error = %q, want it to say the account was not found, with the hint to create it (%q)", msg, hint)
					}
					return
				}
				if strings.Contains(msg, "account not found") || strings.Contains(msg, "accounts create") {
					t.Errorf("a failed lookup is reported as a missing account: %q", msg)
				}
				if !strings.Contains(msg, "failed to look up account") {
					t.Errorf("error = %q, want it to say the account lookup failed", msg)
				}
			})
		}
	}
}
