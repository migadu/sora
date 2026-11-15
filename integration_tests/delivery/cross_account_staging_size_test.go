//go:build integration

package delivery_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
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

// TestDelivery_SaveMessageToMailbox_CrossAccountStagingCounts: filing a delivery into a
// shared mailbox another account owns stages the body a second time, under the owner,
// for the owner's pending upload. That upload subtracts the body's size when it removes
// the file, so the staging must count against max_staging_size too (issue #1174).
func TestDelivery_SaveMessageToMailbox_CrossAccountStagingCounts(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, contributor, _ := common.SetupIMAPServerWithRealS3(t)
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
	shared := fmt.Sprintf("Shared/StagingLimit-%d", common.GetTimestamp())
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

	// A worker that is never started: nothing uploads, and nothing re-bases the count.
	const limit = 1 << 20
	up, err := uploader.NewWithS3Interface(t.TempDir(), 10, 1, 3, time.Second, limit, "staging-limit-1174", rdb, nil, nil, nil)
	require.NoError(t, err)
	contribAddr, err := server.NewAddress(contributor.Email)
	require.NoError(t, err)
	dctx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          rdb,
		Uploader:     up,
		Hostname:     "delivery-host",
		InstanceID:   "staging-limit-1174", // no other test's worker leases the row
		MetricsLabel: "http_delivery",
		Logger:       testLogger{t},
	}

	msgBytes := []byte("From: sender@example.com\r\nTo: " + contributor.Email +
		"\r\nSubject: staging limit\r\nMessage-ID: <staging-limit-" + fmt.Sprint(common.GetTimestamp()) +
		"@example.com>\r\n\r\nbody\r\n")
	entity, err := message.Read(bytes.NewReader(msgBytes))
	require.NoError(t, err)
	plaintext := ""
	contentHash := helpers.HashContent(msgBytes)
	bodyStructure, err := helpers.SafeBodyStructure(msgBytes)
	require.NoError(t, err)

	// Staged under the recipient first, as DeliverMessage does before Sieve.
	_, err = up.StoreLocally(contentHash, contributorID, msgBytes)
	require.NoError(t, err)
	require.NoError(t, dctx.SaveMessageToMailbox(ctx, delivery.RecipientInfo{
		AccountID: contributorID, Address: &contribAddr, ToAddress: &contribAddr,
	}, shared, msgBytes, entity, &plaintext, nil, contentHash, &bodyStructure))

	_, err = os.Stat(up.FilePath(contentHash, ownerID))
	require.NoError(t, err, "the body must be staged for the owner's upload")
	staged := int64(2 * len(msgBytes)) // the recipient's file and the owner's
	assert.True(t, up.IsStagingLimitExceeded(limit-staged+1),
		"with the recipient's and the owner's staging of the %d byte body counted, %d more bytes exceed the %d byte limit",
		len(msgBytes), limit-staged+1, limit)
	assert.False(t, up.IsStagingLimitExceeded(limit-staged))
}
