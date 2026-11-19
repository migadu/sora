//go:build integration

package imap_test

import (
	"bytes"
	"context"
	"maps"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const recoveryArchive = "Recovered"

type moveRecoveryFixture struct {
	ctx       context.Context
	server    *common.TestServer
	client    *imapclient.Client
	fake      *common.FakeS3
	s3        *storage.S3Storage
	accountID int64
	inboxID   int64
	pendingID int64
	uid       imap.UID
	hash      string
	key       string
	path      string
	body      []byte
}

func newMoveRecoveryFixture(t *testing.T) *moveRecoveryFixture {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	fake, s3 := common.NewFakeS3Storage(t)
	server, account := common.SetupIMAPServerForUploadRaceWithS3(t, s3)
	t.Cleanup(server.Close)
	c := loginSelectInbox(t, server.Address, account.Email, account.Password)
	t.Cleanup(func() { c.Logout() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	f := &moveRecoveryFixture{ctx: ctx, server: server, client: c, fake: fake, s3: s3}
	var err error
	f.accountID, err = server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	require.NoError(t, c.Create(recoveryArchive, nil).Wait())
	f.uid = appendMessage(t, c, "Subject: MOVE upload recovery\r\n\r\nThis body survived the MOVE.\r\n")
	var domain, localpart string
	pool := server.ResilientDB.GetDatabase().GetWritePool()
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT m.mailbox_id, p.id, m.content_hash, m.s3_domain, m.s3_localpart FROM messages m
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		JOIN pending_uploads p ON p.account_id = m.account_id AND p.content_hash = m.content_hash
		WHERE m.account_id = $1 AND mb.name = 'INBOX' AND m.uid = $2 AND m.expunged_at IS NULL`,
		f.accountID, f.uid).Scan(&f.inboxID, &f.pendingID, &f.hash, &domain, &localpart))
	f.key = helpers.NewS3Key(domain, localpart, f.hash)
	f.path = uploader.StagingFilePath(server.UploadPath, f.hash, f.accountID)
	f.body, err = os.ReadFile(f.path)
	require.NoError(t, err)
	return f
}

func TestIMAP_MoveRecoversUploadFromS3(t *testing.T) {
	f := newMoveRecoveryFixture(t)
	// A previous PUT stored the exact staged bytes before the upload was finalized.
	require.NoError(t, f.s3.PutContext(f.ctx, f.key, bytes.NewReader(f.body), int64(len(f.body))))
	require.Contains(t, f.fake.Keys(f.key), f.key)
	move, err := f.client.Move(imap.UIDSetNum(f.uid), recoveryArchive).Wait()
	require.NoError(t, err)
	require.NoError(t, os.Remove(f.path))
	f.checkRecovery(t, move)
}

func TestIMAP_UploaderPutsDuringMoveAndRecoversOnNextPass(t *testing.T) {
	f := newMoveRecoveryFixture(t)
	pool := f.server.ResilientDB.GetDatabase().GetWritePool()

	// The source expunge updates INBOX statistics after MOVE has locked the source
	// message and inserted the destination. Hold just this fixture's stats row.
	hold, err := pool.Begin(f.ctx)
	require.NoError(t, err)
	var firstPass sync.WaitGroup
	defer firstPass.Wait()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	defer hold.Rollback(context.Background())
	var holderPID int
	require.NoError(t, hold.QueryRow(ctx, `
		SELECT pg_backend_pid() FROM mailbox_stats WHERE mailbox_id = $1 FOR UPDATE`, f.inboxID).Scan(&holderPID))

	// Match the direct blocker and the statement so unrelated backend waits cannot
	// satisfy either half of the lock chain.
	blockedPID := func(blocker int, statement string) int {
		t.Helper()
		var pid int
		require.EventuallyWithT(t, func(check *assert.CollectT) {
			require.NoError(check, pool.QueryRow(ctx, `
				SELECT pid FROM pg_stat_activity WHERE datname = current_database() AND state = 'active'
				  AND $1 = ANY(pg_blocking_pids(pid)) AND query ILIKE $2`, blocker, statement).Scan(&pid))
		}, 5*time.Second, 10*time.Millisecond, "waiting for %q blocked by PID %d", statement, blocker)
		return pid
	}
	cmd := f.client.Move(imap.UIDSetNum(f.uid), recoveryArchive)
	movePID := blockedPID(holderPID, "%SET expunged_at = NOW()%")
	require.Empty(t, f.fake.Keys(f.key), "the first pass must start with no stored object")
	var firstErr error
	firstPass.Go(func() { firstErr = f.server.DrainUploads(ctx) })
	blockedPID(movePID, "%SET uploaded = TRUE%")
	require.Contains(t, f.fake.Keys(f.key), f.key, "the uploader must complete its PUT while MOVE is still open")

	require.NoError(t, hold.Rollback(ctx))
	move, err := cmd.Wait()
	require.NoError(t, err)
	firstPass.Wait()
	require.NoError(t, firstErr)
	var sourceUploaded bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT uploaded FROM messages WHERE mailbox_id = $1 AND uid = $2 AND expunged_at IS NOT NULL`,
		f.inboxID, f.uid).Scan(&sourceUploaded))
	require.True(t, sourceUploaded, "the first pass must mark the expunged source uploaded")

	// Advance only the retry timestamp. The first pass must have released its lease
	// and removed the staged file itself before recovery starts.
	tag, err := pool.Exec(ctx, `
		UPDATE pending_uploads SET last_attempt = now() - interval '1 day'
		WHERE id = $1 AND attempts = 0 AND last_attempt IS NOT NULL AND lease_until IS NULL AND lease_owner IS NULL`, f.pendingID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "the first pass must leave the original pending row available for retry")
	f.checkRecovery(t, move)
}

func (f *moveRecoveryFixture) checkRecovery(t *testing.T, move *imapclient.MoveData) {
	t.Helper()
	require.NotNil(t, move)
	destUID, ok := maps.Collect(move.UIDMapping.All())[f.uid]
	require.True(t, ok, "MOVE must return the destination UID for source UID %d", f.uid)
	inbox, err := f.client.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.Zero(t, inbox.NumMessages, "MOVE must remove the original message from INBOX")
	_, err = os.Stat(f.path)
	require.ErrorIs(t, err, os.ErrNotExist, "the second pass must start without the staging file")

	// Read the same live destination and its account/hash queue entry on both sides of the pass.
	pool := f.server.ResilientDB.GetDatabase().GetWritePool()
	state := func() (uploaded, pending bool) {
		t.Helper()
		require.NoError(t, pool.QueryRow(f.ctx, `
			SELECT m.uploaded, EXISTS (
				SELECT 1 FROM pending_uploads p WHERE p.account_id = m.account_id AND p.content_hash = m.content_hash)
			FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE m.account_id = $1 AND mb.name = $2 AND m.uid = $3 AND m.content_hash = $4
			  AND m.expunged_at IS NULL`, f.accountID, recoveryArchive, destUID, f.hash).Scan(&uploaded, &pending))
		return uploaded, pending
	}
	uploaded, pending := state()
	require.False(t, uploaded, "MOVE destination should be waiting for its upload")
	require.True(t, pending, "MOVE must retain the pending upload")

	f.fake.FailPuts(true)
	heads := f.fake.HeadCount(f.key)
	f.server.WaitForUploads(t)
	require.Greater(t, f.fake.HeadCount(f.key), heads, "the uploader must confirm the moved message's object")
	uploaded, pending = state()
	require.True(t, uploaded, "the uploader must mark the MOVE destination uploaded")
	require.False(t, pending, "the completed upload must leave the queue")

	_, err = f.client.Select(recoveryArchive, nil).Wait()
	require.NoError(t, err)
	gets := f.fake.GetCount()
	require.Equal(t, f.body, fetchBodySection(t, f.client, destUID, &imap.FetchItemBodySection{Peek: true}))
	require.Greater(t, f.fake.GetCount(), gets, "FETCH must read the recovered bytes from S3")
}
