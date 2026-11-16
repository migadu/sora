package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s3LookupDB is s3ImportTestDB with its account lookups counted, and failing with err
// when it is set.
type s3LookupDB struct {
	*s3ImportTestDB
	err     error
	lookups atomic.Int64
}

func (m *s3LookupDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	m.lookups.Add(1)
	if m.err != nil {
		return 0, m.err
	}
	return m.s3ImportTestDB.GetAccountIDByAddressWithRetry(ctx, address)
}

// TestS3ImportLooksUpTheAccountBeforeTheScan is TestImportAccountLookupErrors for
// `import s3` (#1403): the account is looked up before the bucket is listed. A missing
// account (consts.ErrUserNotFound) stops the run there, with the hint to create the
// account, in a dry run and a real import alike: an import that went on would list the
// account's whole prefix and then fail every object on a lookup of its own, and end
// as if it had succeeded. Any other error is a lookup that failed, for an account that
// may well exist: it stops the run as well, and does not tell the operator to create it.
func TestS3ImportLooksUpTheAccountBeforeTheScan(t *testing.T) {
	const objects = 3
	modes := []struct {
		name   string
		dryRun bool
	}{
		{"import", false},
		{"dry run", true},
	}
	lookups := []struct {
		name    string
		err     error // what the lookup returns
		want    error // what the run's error must wrap
		missing bool
	}{
		{"account missing", consts.ErrUserNotFound, consts.ErrUserNotFound, true},
		{"database error", errors.New("simulated database unavailable"), nil, false},
		{"interrupt", fmt.Errorf("retry cancelled by context: %w", context.Canceled), context.Canceled, false},
	}

	for _, lookup := range lookups {
		want := lookup.want
		if want == nil {
			want = lookup.err
		}
		for _, mode := range modes {
			t.Run(lookup.name+"/"+mode.name, func(t *testing.T) {
				t.Setenv("TMPDIR", t.TempDir())
				bucket, s3storage := newS3ImportTestBucket(t, objects, 1000)
				si, err := NewS3Importer(context.Background(), nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail,
					DryRun: mode.dryRun, Workers: 1, BatchSize: 1000, CleanupDB: true, InstanceID: "test-instance"})
				require.NoError(t, err)
				mock := &s3ImportTestDB{exists: notImportedYet}
				si.rdb = &s3LookupDB{s3ImportTestDB: mock, err: lookup.err}

				_, runErr := runS3Import(t, si)

				require.Error(t, runErr, "a run whose account lookup failed reported success")
				if !errors.Is(runErr, want) {
					t.Errorf("error = %v, want an error wrapping %v", runErr, want)
				}
				msg := runErr.Error()
				hint := "sora-admin accounts create --email " + s3ImportTestEmail
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

				bucket.mu.Lock()
				lists, gets := bucket.lists, bucket.gets
				bucket.mu.Unlock()
				assert.Zero(t, lists, "the bucket was listed for an account the import could not look up")
				assert.Zero(t, gets, "objects were read for an account the import could not look up")
				assert.Zero(t, atomic.LoadInt64(&si.failedMessages), "the objects were counted as failed one by one")
				assert.Empty(t, mock.inserted, "messages were stored for an account the import could not look up")
			})
		}
	}
}

// TestS3ImportLooksUpTheAccountOnce: the account an `import s3` run is for does not
// change during the run, so it is looked up once (#1403), not again for every object.
func TestS3ImportLooksUpTheAccountOnce(t *testing.T) {
	const objects = 3
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dry run %v", dryRun), func(t *testing.T) {
			t.Setenv("TMPDIR", t.TempDir())
			_, s3storage := newS3ImportTestBucket(t, objects, 1000)
			si, err := NewS3Importer(context.Background(), nil, s3storage, S3ImporterOptions{Email: s3ImportTestEmail,
				DryRun: dryRun, Workers: 2, BatchSize: 1000, CleanupDB: true, InstanceID: "test-instance"})
			require.NoError(t, err)
			mock := &s3ImportTestDB{exists: notImportedYet}
			rdb := &s3LookupDB{s3ImportTestDB: mock}
			si.rdb = rdb

			_, err = runS3Import(t, si)
			require.NoError(t, err)
			if !dryRun {
				assert.Len(t, mock.inserted, objects)
			}
			assert.Equal(t, int64(1), rdb.lookups.Load(), "the account was looked up more than once")
		})
	}
}
