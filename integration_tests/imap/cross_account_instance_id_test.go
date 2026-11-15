//go:build integration

package imap

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCrossAccountCopyMove_QueuesOwnerUploadUnderInstanceID: a cross-account COPY or MOVE
// of a body still staged on this node re-stages the upload under the destination owner.
// That pending_uploads row must carry the node's upload instance id, the key its uploader
// leases (WHERE instance_id = $1), not the mail hostname: the two differ whenever
// [uploader] instance_id is set, and a row under the hostname is leased by no uploader, so
// the owner's copy of the body never reaches S3 (#1190). The default test setups use
// "localhost" for both, which is why this needs its own server.
func TestCrossAccountCopyMove_QueuesOwnerUploadUnderInstanceID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, command := range []string{"COPY", "MOVE"} {
		t.Run(command, func(t *testing.T) {
			run := crossAccountCommands[command]
			ctx := context.Background()

			const mailHostname = "mail-copy-identity.example.com"
			leaseKey := fmt.Sprintf("node-copy-identity-%d", time.Now().UnixNano())

			rdb := common.SetupTestDatabase(t)
			contributor := common.CreateTestAccount(t, rdb)
			fake, s3storage := common.NewFakeS3Storage(t)
			uploadWorker := common.NewSyncUploaderWithS3(t, rdb, fake, leaseKey)

			address := common.GetRandomAddress(t)
			srv, err := serverImap.New(ctx, "test-copy-identity", mailHostname, address, s3storage, rdb, uploadWorker, nil,
				serverImap.IMAPServerOptions{
					InstanceID:   leaseKey,
					InsecureAuth: true,
					Config: &config.Config{
						SharedMailboxes: config.SharedMailboxesConfig{
							Enabled:         true,
							NamespacePrefix: "Shared/",
							AllowUserCreate: true,
							DefaultRights:   "lrswipkxtea",
						},
					},
				})
			require.NoError(t, err)
			go func() {
				if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
					t.Logf("IMAP server stopped: %v", err)
				}
			}()
			t.Cleanup(srv.Close)
			time.Sleep(100 * time.Millisecond)
			server := &common.TestServer{Address: address, Server: srv, ResilientDB: rdb}

			ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")

			cc, err := imapclient.DialInsecure(address, nil)
			require.NoError(t, err)
			defer cc.Logout()
			require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

			fake.FailPuts(true) // the body stays staged on this node
			marker := "instance id marker " + command
			appendTo(t, cc, "INBOX", "Instance id", marker)
			require.Equal(t, 0, fake.ObjectCount(), "the upload must still be pending")

			_, err = cc.Select("INBOX", nil).Wait()
			require.NoError(t, err)
			require.NoError(t, run(cc, shared), "%s of a staged body into the owner's mailbox", command)

			var ownerMessageID int64
			var hash, instanceID string
			err = rdb.QueryRowWithRetry(ctx, `
				SELECT m.id, m.content_hash, pu.instance_id
				FROM messages m
				JOIN mailboxes mb ON m.mailbox_id = mb.id
				JOIN pending_uploads pu ON pu.content_hash = m.content_hash AND pu.account_id = m.account_id
				WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
			`, ownerID, shared).Scan(&ownerMessageID, &hash, &instanceID)
			require.NoError(t, err, "the owner's copy must have a pending upload")
			assert.Equal(t, leaseKey, instanceID,
				"the owner's pending upload must be queued under the upload instance id, not the mail hostname %q", mailHostname)

			// End to end: once S3 accepts writes, this node's uploader uploads the owner's copy.
			fake.FailPuts(false)
			deadline := time.Now().Add(5 * time.Second)
			var uploaded bool
			for {
				drainCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				require.NoError(t, uploadWorker.DrainSync(drainCtx))
				cancel()
				require.NoError(t, rdb.QueryRowWithRetry(ctx,
					`SELECT uploaded FROM messages WHERE id = $1`, ownerMessageID).Scan(&uploaded))
				if uploaded || time.Now().After(deadline) {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			require.True(t, uploaded, "this node's uploader never uploaded the owner's copy")
			ownerParts := strings.SplitN(ownerEmail, "@", 2)
			assert.NotEmpty(t, fake.Keys(helpers.NewS3Key(ownerParts[1], ownerParts[0], hash)),
				"the body must be in S3 under the owner's key")
			ownerFetchesMarker(t, server, ownerEmail, shared, marker)
		})
	}
}
