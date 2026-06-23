//go:build integration

package delivery_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger adapts testing.T to delivery.Logger.
type testLogger struct{ t *testing.T }

func (l testLogger) Log(format string, args ...any) { l.t.Logf("[delivery] "+format, args...) }

func fetchBodyIMAP(t *testing.T, c *imapclient.Client, seq uint32) []byte {
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

// TestDelivery_SaveMessageToMailbox_OwnerAttributionEndToEnd covers the B2 invariant for
// the shared delivery engine's fileinto path (server/delivery/delivery.go
// SaveMessageToMailbox, reached in production via SIEVE `fileinto :copy`): a message
// filed into another account's shared mailbox must be attributed to the mailbox OWNER
// (account_id + S3 path), uploaded to the owner's S3 path and retrievable from S3, and
// must survive a purge of the contributor.
func TestDelivery_SaveMessageToMailbox_OwnerAttributionEndToEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	// Owner B (same domain) creates the shared mailbox via IMAP (sets is_shared).
	domain := strings.Split(contributor.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	_, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: ownerEmail, Password: ownerPassword, HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)

	shared := fmt.Sprintf("Shared/B2DELIV-%d", common.GetTimestamp())
	oc, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, ownerPassword).Wait())
	require.NoError(t, oc.Create(shared, nil).Wait())
	_ = oc.Logout()

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	require.NoError(t, err)
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)
	require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, contributor.Email, shared, "lri"))

	// Build a delivery context backed by the same FakeS3 (distinct uploader instance).
	up := common.NewSyncUploaderWithS3(t, rdb, fake, "delivery-host")
	contribAddr, err := server.NewAddress(contributor.Email)
	require.NoError(t, err)
	dctx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          rdb,
		Uploader:     up,
		Hostname:     "delivery-host",
		MetricsLabel: "http_delivery",
		Logger:       testLogger{t},
	}

	marker := fmt.Sprintf("B2-delivery-fileinto-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + contributor.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")
	entity, err := message.Read(bytes.NewReader(msgBytes))
	require.NoError(t, err)
	plaintext, _ := helpers.ExtractPlaintextBody(entity)
	if plaintext == nil {
		empty := ""
		plaintext = &empty
	}

	recipient := delivery.RecipientInfo{
		AccountID: contributorID,
		Address:   &contribAddr,
		ToAddress: &contribAddr,
	}

	// Stage the file under the recipient first, exactly as DeliverMessage does
	// (StoreLocally before SIEVE) — SaveMessageToMailbox then hardlinks it to the
	// owner's staging path for the cross-account upload.
	contentHash := helpers.HashContent(msgBytes)
	_, err = up.StoreLocally(contentHash, contributorID, msgBytes)
	require.NoError(t, err)

	// File into the owner's shared mailbox via the B2-fixed delivery path.
	require.NoError(t, dctx.SaveMessageToMailbox(ctx, recipient, shared, msgBytes, entity, plaintext, nil))
	// SaveMessageToMailbox stages + inserts + queues the owner pending_upload; the
	// caller (DeliverMessage) is what flushes the upload, so emulate that here.
	up.NotifyUploadQueued()

	// Attribution: row owned by the OWNER, not the recipient.
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
	assert.Equal(t, strings.Split(ownerEmail, "@")[1], dom)
	assert.Equal(t, strings.Split(ownerEmail, "@")[0], loc)

	// Body uploaded to the owner's S3 path and retrievable by the owner.
	oc2, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc2.Login(ownerEmail, ownerPassword).Wait())
	defer oc2.Logout()
	mbox, err := oc2.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchBodyIMAP(t, oc2, 1)), marker, "owner FETCHes the body from S3")

	// Purge survival.
	tx, err := rdb.BeginTxWithRetry(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	require.NoError(t, rdb.GetDatabase().HardDeleteAccounts(ctx, tx, []int64{contributorID}))
	require.NoError(t, tx.Commit(ctx))

	mbox, err = oc2.Select(shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "fileinto'd message survives contributor purge")
	assert.Contains(t, string(fetchBodyIMAP(t, oc2, 1)), marker, "owner still FETCHes body from S3 after purge")
}

// TestDelivery_DeliverMessage_InlineSaveToInbox probes the DeliveryContext.DeliverMessage
// inline save path (used by the Admin API /deliver endpoint). It delivers a plain message
// with no active SIEVE script, which must land in the recipient's INBOX.
//
// KNOWN-FAILING GAP (intentionally left red so it gets fixed): DeliverMessage builds its
// InsertMessageOptions with MailboxID: 0 and a comment "Will be set by InsertMessage based
// on mailboxName", but db.InsertMessage no longer resolves the mailbox name -> ID. It uses
// options.MailboxID (=0) directly, so the UID bump `UPDATE mailboxes ... WHERE id = 0`
// matches no rows and the insert fails with "failed to update highest UID: no rows in
// result set". The Admin API /deliver endpoint is therefore broken for every delivery
// (no integration test exercised it — the others call InsertMessageWithRetry with a real
// MailboxID). Fix: have DeliverMessage resolve mailboxName -> MailboxID (GetMailboxByName,
// honoring shared-mailbox ownership + the 'i' right) before InsertMessageWithRetry, the
// same way SaveMessageToMailbox does.
func TestDelivery_DeliverMessage_InlineSaveToInbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, recipientAcct, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	recipientID, err := rdb.GetAccountIDByAddressWithRetry(ctx, recipientAcct.Email)
	require.NoError(t, err)

	up := common.NewSyncUploaderWithS3(t, rdb, fake, "delivery-host")
	addr, err := server.NewAddress(recipientAcct.Email)
	require.NoError(t, err)
	dctx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          rdb,
		Uploader:     up,
		Hostname:     "delivery-host",
		MetricsLabel: "http_delivery",
		Logger:       testLogger{t},
	}
	dctx.SieveExecutor = &delivery.StandardSieveExecutor{
		DeliveryCtx:    dctx,
		VacationOracle: &delivery.VacationOracle{RDB: rdb},
	}

	marker := fmt.Sprintf("B2-deliver-inbox-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + recipientAcct.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

	result, err := dctx.DeliverMessage(delivery.RecipientInfo{
		AccountID: recipientID,
		Address:   &addr,
		ToAddress: &addr,
	}, msgBytes)
	require.NoError(t, err, "DeliverMessage inline save must succeed (result=%+v)", result)
	require.True(t, result.Success)
	assert.Equal(t, "INBOX", result.MailboxName)

	// Retrieve from S3 via IMAP.
	c, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, c.Login(recipientAcct.Email, recipientAcct.Password).Wait())
	defer c.Logout()
	// Allow the async/sync uploader a brief settle window (sync should be immediate).
	time.Sleep(100 * time.Millisecond)
	mbox, err := c.Select("INBOX", nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages, "message must land in INBOX")
	assert.Contains(t, string(fetchBodyIMAP(t, c, 1)), marker)
}

// countLiveInMailbox returns the number of non-expunged messages in (ownerID, name).
func countLiveInMailbox(t *testing.T, rdb interface {
	QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row
}, ownerID int64, name string) int {
	t.Helper()
	var n int
	err := rdb.QueryRowWithRetry(context.Background(), `
		SELECT COUNT(*) FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = $2 AND m.expunged_at IS NULL
	`, ownerID, name).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestDelivery_DeliverMessage_FileintoSharedMailbox_RequiresInsertRight asserts that a
// DeliveryContext.DeliverMessage targeting another account's shared mailbox honors the
// RFC 4314 'i' (insert) right: with only 'lr' the message must fall back to the
// recipient's INBOX, not be written into the shared mailbox. (Driven here via
// TargetMailbox — the Admin API /deliver mechanism; a plain SIEVE `fileinto` target
// reaches the same DeliverMessage resolution.)
//
// Regression guard for a fixed gap: DeliverMessage's inline resolution attributes to the
// mailbox owner (B2) AND — like SaveMessageToMailbox and the LMTP path — now calls
// CheckMailboxPermission for the 'i' right before writing, falling back to INBOX on
// denial. Without that check a recipient with mere lookup/read access (or an Admin API
// caller delivering "as" that recipient) could inject mail into a shared mailbox they
// cannot insert into.
func TestDelivery_DeliverMessage_FileintoSharedMailbox_RequiresInsertRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	domain := strings.Split(contributor.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	_, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: ownerEmail, Password: ownerPassword, HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)

	shared := fmt.Sprintf("Shared/B2NOINS-%d", common.GetTimestamp())
	oc, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, oc.Login(ownerEmail, ownerPassword).Wait())
	require.NoError(t, oc.Create(shared, nil).Wait())
	_ = oc.Logout()

	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	require.NoError(t, err)
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	// Grant ONLY lookup+read (no 'i'): delivery into the shared mailbox must be denied.
	require.NoError(t, rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, contributor.Email, shared, "lr"))

	up := common.NewSyncUploaderWithS3(t, rdb, fake, "delivery-host")
	addr, err := server.NewAddress(contributor.Email)
	require.NoError(t, err)
	dctx := &delivery.DeliveryContext{
		Ctx: ctx, RDB: rdb, Uploader: up, Hostname: "delivery-host",
		MetricsLabel: "http_delivery", Logger: testLogger{t},
	}

	marker := fmt.Sprintf("B2-deliver-noinsert-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + contributor.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

	// Drive delivery straight at the shared mailbox via TargetMailbox — the Admin API
	// /deliver mechanism, and the same DeliverMessage resolution a plain SIEVE fileinto
	// target reaches. The contributor lacks the 'i' right, so it must be denied and fall
	// back to INBOX (as SaveMessageToMailbox and the LMTP path do).
	_, err = dctx.DeliverMessage(delivery.RecipientInfo{
		AccountID:     contributorID,
		Address:       &addr,
		ToAddress:     &addr,
		TargetMailbox: shared,
	}, msgBytes)
	require.NoError(t, err)

	// Insert right was NOT granted: the message must NOT be in the shared mailbox, and
	// must have fallen back to the contributor's own INBOX.
	assert.Equal(t, 0, countLiveInMailbox(t, rdb, ownerID, shared),
		"fileinto without 'i' right must not write into the shared mailbox")
	assert.Equal(t, 1, countLiveInMailbox(t, rdb, contributorID, "INBOX"),
		"denied fileinto must fall back to the recipient's INBOX")
}
