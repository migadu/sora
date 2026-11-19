//go:build integration

package imap_test

import (
	"bytes"
	"context"
	"maps"
	"os"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/uploader"
	"github.com/stretchr/testify/require"
)

func TestIMAP_MoveRecoversUploadFromS3(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	fake, s3 := common.NewFakeS3Storage(t)
	server, account := common.SetupIMAPServerForUploadRaceWithS3(t, s3)
	defer server.Close()
	c := loginSelectInbox(t, server.Address, account.Email, account.Password)
	defer c.Logout()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rdb := server.ResilientDB
	pool := rdb.GetDatabase().GetWritePool()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	const archive = "Recovered"
	require.NoError(t, c.Create(archive, nil).Wait())
	uid := appendMessage(t, c, "Subject: MOVE upload recovery\r\n\r\nThis body survived the MOVE.\r\n")
	var hash, domain, localpart string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT m.content_hash, m.s3_domain, m.s3_localpart FROM messages m
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		WHERE m.account_id = $1 AND mb.name = 'INBOX' AND m.uid = $2 AND m.expunged_at IS NULL`,
		accountID, uid).Scan(&hash, &domain, &localpart))

	// A previous PUT stored the exact staged bytes before the upload was finalized.
	path := uploader.StagingFilePath(server.UploadPath, hash, accountID)
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	key := helpers.NewS3Key(domain, localpart, hash)
	require.NoError(t, s3.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
	require.Contains(t, fake.Keys(key), key)

	move, err := c.Move(imap.UIDSetNum(uid), archive).Wait()
	require.NoError(t, err)
	require.NotNil(t, move)
	destUID, ok := maps.Collect(move.UIDMapping.All())[uid]
	require.True(t, ok, "MOVE must return the destination UID for source UID %d", uid)
	inbox, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.Zero(t, inbox.NumMessages, "MOVE must remove the original message from INBOX")
	require.NoError(t, os.Remove(path))
	require.NoFileExists(t, path)

	// Read the same live destination and its account/hash queue entry on both sides of the pass.
	state := func() (uploaded, pending bool) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT m.uploaded, EXISTS (
				SELECT 1 FROM pending_uploads p WHERE p.account_id = m.account_id AND p.content_hash = m.content_hash)
			FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE m.account_id = $1 AND mb.name = $2 AND m.uid = $3 AND m.content_hash = $4
			  AND m.expunged_at IS NULL`, accountID, archive, destUID, hash).Scan(&uploaded, &pending))
		return uploaded, pending
	}
	uploaded, pending := state()
	require.False(t, uploaded, "MOVE destination should be waiting for its upload")
	require.True(t, pending, "MOVE must retain the pending upload")

	fake.FailPuts(true)
	heads := fake.HeadCount(key)
	server.WaitForUploads(t)
	require.Greater(t, fake.HeadCount(key), heads, "the uploader must confirm the moved message's object")
	uploaded, pending = state()
	require.True(t, uploaded, "the uploader must mark the MOVE destination uploaded")
	require.False(t, pending, "the completed upload must leave the queue")

	_, err = c.Select(archive, nil).Wait()
	require.NoError(t, err)
	gets := fake.GetCount()
	require.Equal(t, body, fetchBodySection(t, c, destUID, &imap.FetchItemBodySection{Peek: true}))
	require.Greater(t, fake.GetCount(), gets, "FETCH must read the recovered bytes from S3")
}
