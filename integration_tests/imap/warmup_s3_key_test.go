//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

// TestIMAP_CacheWarmup_BodyStoredUnderEarlierPrimaryAddress: the login cache warmup
// fetches each body by the S3 key its message row was stored under, as FETCH does
// (#291). The key holds the address that was primary when the message was stored;
// the warmup used to build it from the current primary address, so after the address
// changed it asked S3 for objects that do not exist and cached nothing.
func TestIMAP_CacheWarmup_BodyStoredUnderEarlierPrimaryAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	fake, s3storage := common.NewFakeS3Storage(t)
	instanceID := fmt.Sprintf("warmup-s3-key-%d", time.Now().UnixNano())
	uploadWorker := common.NewSyncUploaderWithS3(t, rdb, fake, instanceID)

	// The uploader keeps no cache, so only the warmup can put a body into this one.
	c, err := cache.New(t.TempDir(), 100*1024*1024, 10*1024*1024, 5*time.Minute, time.Hour, rdb)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	address := common.GetRandomAddress(t)
	srv, err := serverImap.New(ctx, "test-warmup-s3-key", "localhost", address, s3storage, rdb, uploadWorker, c,
		serverImap.IMAPServerOptions{
			InstanceID:         instanceID,
			InsecureAuth:       true,
			EnableWarmup:       true,
			WarmupMessageCount: 10,
			WarmupMailboxes:    []string{"INBOX"},
			WarmupAsync:        false, // the login answers once the warmup is done
			WarmupInterval:     "1ms", // every login warms
		})
	require.NoError(t, err)
	go func() {
		if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("IMAP server stopped: %v", err)
		}
	}()
	t.Cleanup(srv.Close)
	time.Sleep(100 * time.Millisecond)

	// A message stored while the account's first address is primary.
	c1 := dialAndLogin(t, address, account.Email, account.Password)
	appendMessage(t, c1, "From: sender@example.com\r\n"+
		"To: "+account.Email+"\r\n"+
		"Subject: Stored under the first address\r\n"+
		"Date: "+time.Now().Format(time.RFC1123Z)+"\r\n"+
		"\r\n"+
		"Body uploaded before the primary address changed.\r\n")

	localPart, domain, _ := strings.Cut(account.Email, "@")
	keys := fake.Keys(domain + "/" + localPart + "/")
	require.Len(t, keys, 1, "the appended body must be uploaded under the first address")
	contentHash := path.Base(keys[0])

	// The account takes a new primary address in the same domain.
	accountID, err := rdb.GetActiveAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	renamed := fmt.Sprintf("renamed-%d@%s", time.Now().UnixNano(), domain)
	require.NoError(t, rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID: accountID, NewEmail: renamed, NewPassword: account.Password, NewHashType: "bcrypt", IsPrimary: true,
	}))

	cached, err := c.Exists(contentHash)
	require.NoError(t, err)
	require.False(t, cached, "nothing may have cached the body before the warmup")

	dialAndLogin(t, address, renamed, account.Password)

	cached, err = c.Exists(contentHash)
	require.NoError(t, err)
	require.True(t, cached, "the warmup after the address change did not cache the body stored as %s", keys[0])
}
