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

// TestIMAP_CacheWarmup_SkipsBodiesTheCacheRefuses: the login cache warmup does not
// download a body the cache would refuse for its size (#694). It used to GET every
// recent body from S3, read it into memory and only then learn from Put that the
// body was above max_object_size, at every warmup interval.
func TestIMAP_CacheWarmup_SkipsBodiesTheCacheRefuses(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	fake, s3storage := common.NewFakeS3Storage(t)
	instanceID := fmt.Sprintf("warmup-too-large-%d", time.Now().UnixNano())
	uploadWorker := common.NewSyncUploaderWithS3(t, rdb, fake, instanceID)

	// max_object_size 2 KiB; the capacity leaves each shard far more than that.
	const maxObjectSize = 2048
	c, err := cache.New(t.TempDir(), 100*1024*1024, maxObjectSize, 5*time.Minute, time.Hour, rdb)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })

	address := common.GetRandomAddress(t)
	srv, err := serverImap.New(ctx, "test-warmup-too-large", "localhost", address, s3storage, rdb, uploadWorker, c,
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

	localPart, domain, _ := strings.Cut(account.Email, "@")
	prefix := domain + "/" + localPart + "/"
	header := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n"

	c1 := dialAndLogin(t, address, account.Email, account.Password)
	appendMessage(t, c1, header+"Subject: Small\r\n\r\nA body the cache takes.\r\n")
	smallKeys := fake.Keys(prefix)
	require.Len(t, smallKeys, 1, "the small body must be uploaded")
	smallKey := smallKeys[0]

	appendMessage(t, c1, header+"Subject: Large\r\n\r\n"+strings.Repeat("x", 4*maxObjectSize)+"\r\n")
	var largeKey string
	for _, k := range fake.Keys(prefix) {
		if k != smallKey {
			largeKey = k
		}
	}
	require.NotEmpty(t, largeKey, "the large body must be uploaded")

	cached, err := c.Exists(path.Base(smallKey))
	require.NoError(t, err)
	require.False(t, cached, "nothing may have cached the small body before the warmup")

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
	cached, err = c.Exists(path.Base(smallKey))
	require.NoError(t, err)
	require.True(t, cached, "the warmup did not cache the small body")
	for _, k := range fetched {
		require.NotContains(t, k, largeKey, "the warmup downloaded a body above max_object_size")
	}
}
