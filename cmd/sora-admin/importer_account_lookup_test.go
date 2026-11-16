package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
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

// countingStorage stands in for S3: every upload lands, and is counted.
type countingStorage struct {
	puts atomic.Int64
}

func (s *countingStorage) Put(key string, reader io.Reader, size int64) error {
	s.puts.Add(1)
	return nil
}
func (s *countingStorage) Get(key string) (io.ReadCloser, error)   { return nil, os.ErrNotExist }
func (s *countingStorage) Exists(key string) (bool, string, error) { return false, "", nil }
func (s *countingStorage) Delete(key string) error                 { return nil }
func (s *countingStorage) Copy(sourcePath, destPath string) error  { return nil }
func (s *countingStorage) EnableEncryption(encryptionKey string) error {
	return nil
}

// newAccountLookupMaildir builds a maildir of n messages with a Dovecot subscriptions
// file, and a Sieve script beside it, so that every step of an import that needs the
// account has something to do. It returns the maildir and the script's path.
func newAccountLookupMaildir(t *testing.T, n int) (maildirPath, sievePath string) {
	t.Helper()
	maildirPath = newCleanupDBMaildir(t, n)
	require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "subscriptions"), []byte("Sent\nArchive\n"), 0644))
	sievePath = filepath.Join(t.TempDir(), "filter.sieve")
	require.NoError(t, os.WriteFile(sievePath, []byte("keep;\n"), 0644))
	return maildirPath, sievePath
}

// TestImportAccountLookupErrors: `import maildir` looks the account up before it scans
// the maildir or uploads anything (#1403). A missing account (consts.ErrUserNotFound)
// stops the run there, with the hint to create the account, in a dry run and a real
// import alike: an import that went on would upload every message to S3 and then fail
// each one at its insert, and never say why. Any other error, a database unreachable
// past the retries or an interrupt (Ctrl-C cancels the context), is a lookup that
// failed, for an account that may well exist: it stops the run as well, and must not
// say the account was not found nor tell the operator to create it.
func TestImportAccountLookupErrors(t *testing.T) {
	const email = "user@example.com"
	errUnavailable := errors.New("simulated database unavailable")

	modes := []struct {
		name string
		opts ImporterOptions
	}{
		{"import", ImporterOptions{}},
		{"batch transaction", ImporterOptions{BatchTransactionMode: true}},
		{"dry run", ImporterOptions{DryRun: true}},
		{"dovecot, sieve script and preserved UIDs", ImporterOptions{Dovecot: true, PreserveUIDs: true}},
	}
	lookups := []struct {
		name    string
		err     error // what the lookup returns
		want    error // what the run's error must wrap
		missing bool
	}{
		{"account missing", consts.ErrUserNotFound, consts.ErrUserNotFound, true},
		{"database error", fmt.Errorf("database error fetching account ID: %w", errUnavailable), errUnavailable, false},
		{"interrupt", fmt.Errorf("retry cancelled by context: %w", context.Canceled), context.Canceled, false},
	}

	for _, lookup := range lookups {
		for _, mode := range modes {
			t.Run(lookup.name+"/"+mode.name, func(t *testing.T) {
				maildirPath, sievePath := newAccountLookupMaildir(t, 2)
				opts := mode.opts
				if opts.Dovecot {
					opts.SievePath = sievePath
				}
				s3 := &countingStorage{}
				importer, err := NewImporter(context.Background(), maildirPath, email, 1, nil, s3, opts)
				require.NoError(t, err)
				t.Cleanup(func() { importer.Close() })
				importer.rdb = &accountLookupDB{mockResilientDatabase: newMockResilientDatabase(), err: lookup.err}

				var runErr error
				if opts.DryRun {
					_, runErr = runCapturingStdout(t, importer.Run)
				} else {
					runErr = importer.Run()
				}

				require.Error(t, runErr, "a run whose account lookup failed reported success")
				if !errors.Is(runErr, lookup.want) {
					t.Errorf("error = %v, want an error wrapping %v", runErr, lookup.want)
				}
				msg := runErr.Error()
				hint := "sora-admin accounts create --email " + email
				if lookup.missing {
					if !strings.Contains(msg, "account not found") || !strings.Contains(msg, hint) {
						t.Errorf("error = %q, want it to say the account was not found, with the hint to create it (%q)", msg, hint)
					}
				} else {
					if strings.Contains(msg, "account not found") || strings.Contains(msg, "accounts create") {
						t.Errorf("a failed lookup is reported as a missing account: %q", msg)
					}
					if !strings.Contains(msg, "failed to look up account") {
						t.Errorf("error = %q, want it to say the account lookup failed", msg)
					}
				}

				assert.Zero(t, s3.puts.Load(), "messages were uploaded to S3 for an account the import could not look up")
				assert.Zero(t, importer.failedMessages, "the messages were counted as failed one by one")
				assert.Empty(t, recordedFailedPaths(importer), "the messages were listed as failed one by one")
				imported, pending := uploadedCounts(t, maildirPath)
				assert.Zero(t, imported+pending, "the maildir was scanned for an account the import could not look up")
			})
		}
	}
}

// lookupCountingDB counts the account lookups of an import that succeeds, and stores
// the Sieve script it is given.
type lookupCountingDB struct {
	resilientDB
	lookups atomic.Int64
}

func (m *lookupCountingDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	m.lookups.Add(1)
	return m.resilientDB.GetAccountIDByAddressWithRetry(ctx, address)
}

func (m *lookupCountingDB) GetScriptByNameWithRetry(ctx context.Context, name string, accountID int64) (*db.SieveScript, error) {
	return nil, consts.ErrDBNotFound
}

func (m *lookupCountingDB) CreateScriptWithRetry(ctx context.Context, accountID int64, name, content string) (*db.SieveScript, error) {
	return &db.SieveScript{ID: 1, AccountID: accountID, Name: name, Script: content}, nil
}

// TestImportLooksUpTheAccountOnce: the account an import is for does not change during
// the run, so it is looked up once (#1403), not again by orphan recovery, the Dovecot
// subscriptions, the Sieve script, the UIDVALIDITY sync and every batch's insert.
func TestImportLooksUpTheAccountOnce(t *testing.T) {
	const messages = 3
	for _, batchTx := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch transaction %v", batchTx), func(t *testing.T) {
			maildirPath, sievePath := newAccountLookupMaildir(t, messages)
			var inner resilientDB = newMockResilientDatabase()
			if batchTx {
				inner = &scriptedBatchTxDB{mockResilientDatabase: newMockResilientDatabase()}
			}
			rdb := &lookupCountingDB{resilientDB: inner}
			importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
				BatchSize:            1, // one batch per message
				BatchTransactionMode: batchTx,
				Dovecot:              true,
				PreserveUIDs:         true,
				SievePath:            sievePath,
			})

			require.NoError(t, importer.Run())
			assert.Equal(t, int64(messages), importer.importedMessages)
			assert.Equal(t, int64(1), rdb.lookups.Load(), "the account was looked up more than once")
		})
	}
}
