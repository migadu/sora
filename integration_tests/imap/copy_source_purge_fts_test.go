//go:build integration

package imap

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

// TestCrossAccountCopyStaysSearchableAfterSourcePurge: a message COPYed into another
// account's shared mailbox must stay searchable by body there after the account it was
// copied from is purged (#909). The copy's search row is written without text or vector,
// for the FTS worker to fill from the source account's row; the purge may run before or
// after the worker does.
func TestCrossAccountCopyStaysSearchableAfterSourcePurge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, tc := range []struct {
		name        string
		workerFirst bool
	}{
		{"purge before the worker", false},
		{"worker before the purge", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			srv, source, fake := common.SetupIMAPServerWithRealS3(t)
			defer srv.Close()
			rdb := srv.ResilientDB
			ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, srv, source.Email, "lrswi")
			sourceID, err := rdb.GetAccountIDByAddressWithRetry(ctx, source.Email)
			require.NoError(t, err)

			const needle = "zebrapurgeneedle"
			c, err := imapclient.DialInsecure(srv.Address, nil)
			require.NoError(t, err)
			defer c.Close()
			require.NoError(t, c.Login(source.Email, source.Password).Wait())
			// A unique subject makes a body of its own: an empty vector left by the other
			// subtest would be copied onto a new delivery of the same body.
			appendTo(t, c, "INBOX", fmt.Sprintf("purge source %d", time.Now().UnixNano()), needle)
			require.NoError(t, srv.FlushFTSQueue())
			_, err = c.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			found, err := c.UIDSearch(&imap.SearchCriteria{Body: []string{needle}}, nil).Wait()
			require.NoError(t, err)
			require.Len(t, found.AllUIDs(), 1, "precondition: the source is searchable by body")
			_, err = c.Copy(imap.SeqSetNum(1), shared).Wait()
			require.NoError(t, err)
			require.NoError(t, c.Logout().Wait())

			var waiting bool
			require.NoError(t, rdb.QueryRowWithRetry(ctx, `
				SELECT v.text_body IS NULL AND v.text_body_tsv IS NULL
				FROM messages m JOIN messages_fts_v2 v ON v.content_hash = m.content_hash AND v.account_id = m.account_id
				WHERE m.account_id = $1 AND m.expunged_at IS NULL`, ownerID).Scan(&waiting))
			require.True(t, waiting, "precondition: the copy's search row waits for the worker")

			if tc.workerFirst {
				require.NoError(t, srv.FlushFTSQueue())
			}
			purgedID, _, err := rdb.RequestAccountPurgeWithRetry(ctx, source.Email)
			require.NoError(t, err)
			require.Equal(t, sourceID, purgedID)
			s3, err := storage.New(fake.Endpoint(), "test-access-key", "test-secret-key", "test-bucket", false, false, 10*time.Second)
			require.NoError(t, err)
			_, err = cleaner.PurgeAccount(ctx, rdb, resilient.NewResilientS3Storage(s3), sourceID)
			require.NoError(t, err)
			var sourceAccounts, sourceRows int
			require.NoError(t, rdb.QueryRowWithRetry(ctx, `
				SELECT (SELECT count(*) FROM accounts WHERE id = $1), (SELECT count(*) FROM messages_fts_v2 WHERE account_id = $1)`,
				sourceID).Scan(&sourceAccounts, &sourceRows))
			require.Zero(t, sourceAccounts, "the source account is purged")
			require.Zero(t, sourceRows, "with its search rows")
			require.NoError(t, srv.FlushFTSQueue())

			oc, err := imapclient.DialInsecure(srv.Address, nil)
			require.NoError(t, err)
			defer oc.Close()
			require.NoError(t, oc.Login(ownerEmail, "owner-pass-123").Wait())
			_, err = oc.Select(shared, nil).Wait()
			require.NoError(t, err)
			require.Contains(t, string(fetchFullBody(t, oc, 1)), needle, "the copy's body is still readable")
			found, err = oc.UIDSearch(&imap.SearchCriteria{Body: []string{needle}}, nil).Wait()
			require.NoError(t, err)
			require.Len(t, found.AllUIDs(), 1, "the copy is still searchable by body")
		})
	}
}
