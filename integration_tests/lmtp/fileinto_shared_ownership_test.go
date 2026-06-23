//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchFullBodyIMAP fetches BODY[] for the given sequence number over an IMAP client.
func fetchFullBodyIMAP(t *testing.T, c *imapclient.Client, seq uint32) []byte {
	t.Helper()
	cmd := c.Fetch(imap.SeqSetNum(seq), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{Part: []int{}}},
	})
	var body []byte
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if b, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				_, _ = io.Copy(buf, b.Literal)
				body = buf.Bytes()
			}
		}
	}
	_ = cmd.Close()
	return body
}

// TestLMTP_FileintoSharedMailbox_OwnerAttributionEndToEnd verifies B2 ownership for the
// SIEVE fileinto delivery path with a real (in-memory) S3, mirroring the IMAP APPEND/
// COPY/MOVE end-to-end tests: a message LMTP-delivered to a contributor whose active
// SIEVE files it into another account's shared mailbox must be attributed to the
// mailbox OWNER (account_id + S3 path), have its body uploaded to the owner's S3 path
// and retrievable from S3 by the owner, and survive a purge of the contributor.
func TestLMTP_FileintoSharedMailbox_OwnerAttributionEndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// IMAP server (real S3) provides rdb + fake S3 + the contributor account, and is
	// used to create the owner's shared mailbox and to FETCH the delivered message.
	imapSrv, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	// Owner B (same domain) creates the shared mailbox via IMAP (sets is_shared).
	domain := strings.Split(contributor.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	_, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     ownerEmail,
		Password:  ownerPassword,
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	require.NoError(t, err)

	shared := fmt.Sprintf("Shared/B2LMTP-%d", common.GetTimestamp())
	oc, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, ownerPassword).Wait())
	require.NoError(t, oc.Create(shared, nil).Wait())
	_ = oc.Logout()

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	require.NoError(t, err)
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	// Contributor needs the 'i' (insert) right for fileinto to honor the target.
	require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, contributor.Email, shared, "lri"))

	// Contributor's active SIEVE files all incoming mail into the shared mailbox.
	sieve := fmt.Sprintf("require [\"fileinto\"];\r\nfileinto \"%s\";\r\n", shared)
	_, err = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", contributorID)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())`, contributorID, "fileinto-shared", sieve, true)
	require.NoError(t, err)

	// LMTP server sharing rdb + the same FakeS3 (real sync uploader, no cache).
	lmtpAddr := common.StartLMTPServerWithS3(t, rdb, fake)

	// Deliver to the contributor; SIEVE files it into the owner's shared mailbox.
	marker := fmt.Sprintf("B2-LMTP-fileinto-%d", common.GetTimestamp())
	deliverLMTP(t, lmtpAddr, contributor.Email, marker)

	// Attribution: the delivered row must belong to the OWNER, not the recipient.
	var accID int64
	var dom, loc string
	err = rdb.QueryRowWithRetry(ctx, `
		SELECT m.account_id, m.s3_domain, m.s3_localpart
		FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
		ORDER BY m.uid DESC LIMIT 1
	`, ownerID, shared).Scan(&accID, &dom, &loc)
	require.NoError(t, err, "delivered message must exist in the shared mailbox")
	assert.Equal(t, ownerID, accID, "fileinto must attribute to the mailbox owner, not the recipient")
	assert.Equal(t, strings.Split(ownerEmail, "@")[1], dom, "s3_domain must be the owner's")
	assert.Equal(t, strings.Split(ownerEmail, "@")[0], loc, "s3_localpart must be the owner's")

	// The body must be uploaded to the owner's S3 path and retrievable by the owner.
	oc2, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc2.Login(ownerEmail, ownerPassword).Wait())
	defer oc2.Logout()
	mbox, err := oc2.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "owner sees the fileinto'd message")
	assert.Contains(t, string(fetchFullBodyIMAP(t, oc2, 1)), marker, "owner FETCHes the body from S3")

	// Purge the contributor: the fileinto'd message + its S3 body must survive.
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, rdb.GetDatabase().HardDeleteAccounts(ctx, tx, []int64{contributorID}))
	require.NoError(t, tx.Commit(ctx))

	mbox, err = oc2.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "fileinto'd message survives contributor purge")
	assert.Contains(t, string(fetchFullBodyIMAP(t, oc2, 1)), marker, "owner still FETCHes body from S3 after purge")
}
