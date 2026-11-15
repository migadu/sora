//go:build integration

package delivery_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/uploader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ownerStagingFixture is a contributor who may insert into a shared mailbox another
// account owns, and a delivery context whose upload worker is never started, so nothing
// uploads or removes a staged file behind the test's back.
type ownerStagingFixture struct {
	dctx          *delivery.DeliveryContext
	up            *uploader.UploadWorker
	recipient     delivery.RecipientInfo
	ownerID       int64
	contributorID int64
	shared        string
}

func newOwnerStagingFixture(t *testing.T, label string) ownerStagingFixture {
	t.Helper()
	imapSrv, contributor := common.SetupIMAPServer(t)
	t.Cleanup(imapSrv.Close)
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	domain := strings.Split(contributor.Email, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	_, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: ownerEmail, Password: ownerPassword, HashType: "bcrypt", IsPrimary: true,
	})
	require.NoError(t, err)
	shared := fmt.Sprintf("Shared/%s-%d", label, common.GetTimestamp())
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

	instanceID := "owner-staging-" + label // no other test's worker leases the rows
	up, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 3, time.Second, 0, instanceID, rdb, nil, nil, nil)
	require.NoError(t, err)
	addr, err := server.NewAddress(contributor.Email)
	require.NoError(t, err)
	return ownerStagingFixture{
		dctx: &delivery.DeliveryContext{
			Ctx:          ctx,
			RDB:          rdb,
			Uploader:     up,
			Hostname:     "delivery-host",
			InstanceID:   instanceID,
			MetricsLabel: "http_delivery",
			Logger:       testLogger{t},
		},
		up:            up,
		recipient:     delivery.RecipientInfo{AccountID: contributorID, Address: &addr, ToAddress: &addr},
		ownerID:       ownerID,
		contributorID: contributorID,
		shared:        shared,
	}
}

// TestDelivery_SaveMessageToMailbox_CrossAccountRecipientFileGone: the owner's pending
// upload reads only the owner's staging file. When the recipient's staged file is gone by
// the time a delivery files the message into a shared mailbox (its upload finished and
// removed it after the delivery found it staged), the owner's file is staged from the
// bytes the delivery holds; it used to be skipped with a log line, and the owner's
// message was stored with a body its upload could not find (issue #1192).
func TestDelivery_SaveMessageToMailbox_CrossAccountRecipientFileGone(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newOwnerStagingFixture(t, "OwnerStageGone")
	ctx := context.Background()

	msgBytes := []byte("From: sender@example.com\r\nTo: " + f.recipient.Address.FullAddress() +
		"\r\nSubject: recipient file gone\r\nMessage-ID: <owner-stage-gone-" + fmt.Sprint(common.GetTimestamp()) +
		"@example.com>\r\n\r\nbody\r\n")
	entity, err := message.Read(bytes.NewReader(msgBytes))
	require.NoError(t, err)
	plaintext := ""
	contentHash := helpers.HashContent(msgBytes)
	bodyStructure, err := helpers.SafeBodyStructure(msgBytes)
	require.NoError(t, err)

	// Nothing is staged under the recipient: its upload already took the file.
	require.NoError(t, f.dctx.SaveMessageToMailbox(ctx, f.recipient, f.shared, msgBytes, entity, &plaintext, nil, contentHash, &bodyStructure))

	require.Equal(t, 1, countLiveInMailbox(t, f.dctx.RDB, f.ownerID, f.shared))
	got, err := os.ReadFile(f.up.FilePath(contentHash, f.ownerID))
	require.NoError(t, err, "the owner's message is stored, so its body must be staged for the owner's upload")
	assert.Equal(t, msgBytes, got)
}

// TestDelivery_DeliverMessage_CrossAccountOwnerStagingFails: a delivery whose body cannot
// be staged for the owner of the shared mailbox it targets fails (the Admin API answers
// it as transient) and stores nothing there; it used to store the owner's message with
// a pending upload that had no file to read (issue #1192).
func TestDelivery_DeliverMessage_CrossAccountOwnerStagingFails(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores the directory permissions this test relies on")
	}
	f := newOwnerStagingFixture(t, "OwnerStageFails")

	// The owner's staging directory takes no new file, so neither a hard link nor a copy
	// can stage the body there.
	ownerDir := filepath.Dir(f.up.FilePath(strings.Repeat("0", 64), f.ownerID))
	require.NoError(t, os.MkdirAll(ownerDir, 0o555))
	require.NoError(t, os.Chmod(ownerDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(ownerDir, 0o755) })

	marker := fmt.Sprintf("owner-stage-fails-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + f.recipient.Address.FullAddress() +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

	recipient := f.recipient
	recipient.TargetMailbox = f.shared
	result, err := f.dctx.DeliverMessage(recipient, msgBytes)
	require.Error(t, err, "a body not staged for the owner must fail the delivery")
	assert.False(t, result.Success)
	assert.Equal(t, 0, countLiveInMailbox(t, f.dctx.RDB, f.ownerID, f.shared),
		"no message may be stored for the owner without a body staged for the owner's upload")
}
