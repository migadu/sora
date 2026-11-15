//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/stretchr/testify/require"
)

// TestIMAP_CacheWarmup_SkipsBodiesNotUploadedYet: the login cache warmup does not ask
// S3 for a body whose upload is still pending (#986). Such a body is not in S3 yet, so
// the GET answers NoSuchKey and warms nothing; with warmup_message_count 1 the pending
// newest message also took the place of the uploaded one, which then went unwarmed
// for the whole warmup interval.
func TestIMAP_CacheWarmup_SkipsBodiesNotUploadedYet(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	fake, s3storage := common.NewFakeS3Storage(t)
	instanceID := fmt.Sprintf("warmup-pending-%d", time.Now().UnixNano())
	uploadWorker := common.NewSyncUploaderWithS3(t, rdb, fake, instanceID)

	// The uploader keeps no cache, so only the warmup can put a body into this one.
	c, err := cache.New(t.TempDir(), 100*1024*1024, 10*1024*1024, 5*time.Minute, time.Hour, rdb)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	address := common.GetRandomAddress(t)
	srv, err := serverImap.New(ctx, "test-warmup-pending", "localhost", address, s3storage, rdb, uploadWorker, c,
		serverImap.IMAPServerOptions{
			InstanceID:         instanceID,
			InsecureAuth:       true,
			EnableWarmup:       true,
			WarmupMessageCount: 1,
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

	localPart, domain, _ := strings.Cut(account.Email, "@")
	prefix := domain + "/" + localPart + "/"
	header := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n"

	c1 := dialAndLogin(t, address, account.Email, account.Password)
	appendMessage(t, c1, header+"Subject: Uploaded\r\n\r\nA body that is in S3.\r\n")
	uploadedKeys := fake.Keys(prefix)
	require.Len(t, uploadedKeys, 1, "the first body must be uploaded")
	uploadedKey := uploadedKeys[0]

	// The newest message's upload stalls: its body stays staged and is not in S3.
	fake.FailPuts(true)
	appendMessage(t, c1, header+"Subject: Pending\r\n\r\nA body whose upload has not completed.\r\n")
	require.Equal(t, uploadedKeys, fake.Keys(prefix), "the second body must still be pending")

	cached, err := c.Exists(path.Base(uploadedKey))
	require.NoError(t, err)
	require.False(t, cached, "nothing may have cached the uploaded body before the warmup")

	var mu sync.Mutex
	var fetched []string
	fake.OnGet(func(key string) {
		mu.Lock()
		defer mu.Unlock()
		fetched = append(fetched, key)
	})
	t.Cleanup(func() { fake.OnGet(nil) })

	dialAndLogin(t, address, account.Email, account.Password)

	mu.Lock()
	defer mu.Unlock()
	for _, k := range fetched {
		require.Equal(t, uploadedKey, k, "the warmup asked S3 for a body that is not uploaded yet")
	}
	cached, err = c.Exists(path.Base(uploadedKey))
	require.NoError(t, err)
	require.True(t, cached, "the warmup did not cache the newest uploaded body")
}
