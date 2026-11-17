//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

// TestUploaderResolveFencesQuarantinedAndReconciledBody proves `uploader resolve`
// acquires the shared S3 body lock (and checks s3_body_delete_intents) before
// trusting S3 HEAD or finalizing CompleteS3Upload. Without that fence, an S3 HEAD
// sees 200 OK on a quarantined object right before reconciliation deletes the
// orphan-only key and clears s3_body_delete_intents, causing CompleteS3Upload to
// mark the message uploaded=TRUE and drop pending_uploads against a deleted S3 key.
func TestUploaderResolveFencesQuarantinedAndReconciledBody(t *testing.T) {
	ctx := context.Background()
	rdb := openAdminTestDatabase(t)
	t.Cleanup(func() { rdb.Close() })
	endpoint := adminTestDBConfig(t).Write

	var (
		mu             sync.Mutex
		objects        = make(map[string][]byte)
		failNextDelete bool
		onHead         func(key string)
	)
	const bucket = "resolve-fence-test"
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/" + bucket + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			objects[key] = data
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			mu.Lock()
			data, ok := objects[key]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
		case http.MethodHead:
			mu.Lock()
			_, ok := objects[key]
			hook := onHead
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if hook != nil {
				hook(key)
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			mu.Lock()
			if failNextDelete {
				failNextDelete = false
				mu.Unlock()
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			delete(objects, key)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(s3Srv.Close)

	s3Host := strings.TrimPrefix(s3Srv.URL, "http://")
	s3Client, err := storage.New(s3Host, "test", "test", bucket, false, false, 10*time.Second)
	require.NoError(t, err)

	spoolDir := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	cfgContent := fmt.Sprintf(`[database.write]
hosts = [%q]
port = %q
user = %q
password = %q
name = %q

[s3]
endpoint = %q
disable_tls = true
bucket = %q
access_key = "test"
secret_key = "test"
body_deletion_protocol = "global-hash-v1"

[uploader]
path = %q
`, endpoint.Hosts[0], fmt.Sprint(endpoint.Port), endpoint.User, endpoint.Password, endpoint.Name,
		s3Host, bucket, spoolDir)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))
	var cfg AdminConfig
	require.NoError(t, loadAdminConfig(cfgPath, &cfg))

	stamp := time.Now().UnixNano()
	local := fmt.Sprintf("resolve-fence-%d", stamp)
	domain := "example.com"
	email := local + "@" + domain
	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: email, Password: "password123", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	body := []byte(fmt.Sprintf("Subject: fence %d\r\n\r\nfenced body %d", stamp, stamp))
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	require.NoError(t, s3Client.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))

	// Create an old expunged row and fail its S3 DELETE uncertainly so PostgreSQL holds
	// a real durable s3_body_delete_intents fence while the old S3 object is still present.
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	oldMsgID, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     inbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      domain,
		S3Localpart:   local,
		ContentHash:   hash,
		MessageID:     fmt.Sprintf("<old-%d@example.com>", stamp),
		InternalDate:  time.Now().Add(-3 * time.Hour),
		Size:          int64(len(body)),
		PlaintextBody: "fenced body",
		BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: cfg.InstanceID(), ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET uploaded = TRUE, expunged_at = now() - interval '2 hours' WHERE id = $1`, oldMsgID)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `DELETE FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash)
	require.NoError(t, err)

	mu.Lock()
	failNextDelete = true
	mu.Unlock()
	candidate := db.UserScopedObjectForCleanup{AccountID: accountID, ContentHash: hash, S3Domain: domain, S3Localpart: local}
	_, err = rdb.ExecuteWithS3BodyCleanup(ctx, []db.UserScopedObjectForCleanup{candidate}, time.Hour, func(c context.Context, objs []db.UserScopedObjectForCleanup) (db.S3BodyCleanupResult, error) {
		require.Len(t, objs, 1)
		if delErr := s3Client.DeleteContext(c, key); delErr != nil {
			return db.S3BodyCleanupResult{}, delErr
		}
		return db.S3BodyCleanupResult{Gone: objs}, nil
	})
	require.Error(t, err)
	t.Cleanup(func() {
		_, _ = rdb.ExecWithRetry(context.Background(), `DELETE FROM s3_body_delete_intents WHERE content_hash = $1`, hash)
		_, _ = rdb.ExecWithRetry(context.Background(), `DELETE FROM pending_uploads WHERE account_id = $1`, accountID)
	})

	intents, err := rdb.ListS3BodyDeleteIntents(ctx)
	require.NoError(t, err)
	var intentOpID string
	for _, in := range intents {
		if in.ContentHash == hash {
			intentOpID = in.OperationID
			break
		}
	}
	require.NotEmpty(t, intentOpID, "uncertain cleanup must leave a durable s3_body_delete_intents fence")

	// Deliver a new copy while hash is quarantined: InsertMessage stages uploaded=FALSE + pending_uploads.
	newMsgID, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     inbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      domain,
		S3Localpart:   local,
		ContentHash:   hash,
		MessageID:     fmt.Sprintf("<new-%d@example.com>", stamp),
		InternalDate:  time.Now(),
		Size:          int64(len(body)),
		PlaintextBody: "fenced body",
		BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: cfg.InstanceID(), ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
	require.NoError(t, err)
	stagedPath := uploader.StagingFilePath(cfg.Uploader.Path, hash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(stagedPath), 0o755))
	require.NoError(t, os.WriteFile(stagedPath, body, 0o644))
	_, err = rdb.ExecWithRetry(ctx, `UPDATE pending_uploads SET attempts = $3 WHERE account_id = $1 AND content_hash = $2`,
		accountID, hash, cfg.Uploader.MaxAttempts)
	require.NoError(t, err)

	headObserved := make(chan struct{})
	releaseHead := make(chan struct{})
	var headOnce, releaseOnce sync.Once
	unblockHead := func() { releaseOnce.Do(func() { close(releaseHead) }) }
	defer unblockHead()

	mu.Lock()
	onHead = func(k string) {
		if k == key {
			headOnce.Do(func() {
				close(headObserved)
				<-releaseHead
			})
		}
	}
	mu.Unlock()

	resolveDone := make(chan error, 1)
	go func() {
		resolveDone <- resolveFailedUploads(ctx, cfg, false, 100)
	}()

	select {
	case <-headObserved:
		// Unfenced resolve probed S3 HEAD despite the active deletion fence.
		// Complete reconciliation (which deletes the S3 key and clears the intent)
		// before letting the stale 200 OK HEAD return to CompleteS3Upload.
		require.NoError(t, reconcileBodyDeletion(ctx, rdb, s3Client, hash, intentOpID, true))
		unblockHead()
		require.NoError(t, <-resolveDone)
	case resolveErr := <-resolveDone:
		require.NoError(t, resolveErr)
		mu.Lock()
		onHead = nil
		mu.Unlock()
		require.NoError(t, reconcileBodyDeletion(ctx, rdb, s3Client, hash, intentOpID, true))
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for resolveFailedUploads")
	}

	mu.Lock()
	_, stillInS3 := objects[key]
	mu.Unlock()
	require.False(t, stillInS3, "reconciliation must have deleted the quarantined orphan-only S3 key")

	var newUploaded bool
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT uploaded FROM messages WHERE id = $1`, newMsgID).Scan(&newUploaded))
	require.False(t, newUploaded, "uploader resolve marked message uploaded=TRUE against an S3 object deleted by reconciliation")

	var pendingCount int
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&pendingCount))
	require.Equal(t, 1, pendingCount, "pending_uploads row must remain so the staged body can be uploaded")

	// Once reconciliation has cleared the fence, running resolve again sees 404 in S3
	// and re-arms the intact staged upload from the local spool.
	mu.Lock()
	onHead = nil
	mu.Unlock()
	require.NoError(t, resolveFailedUploads(ctx, cfg, false, 100))
	var attempts int
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT attempts FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&attempts))
	require.Zero(t, attempts, "post-reconciliation resolve should re-arm the staged upload")
}

// TestUploaderResolveRefusesStaleHeadAfterHolderLoss proves `uploader resolve` holds
// a shared S3 body advisory lock across S3 HEAD and carries S3BodyClaimContext into
// CompleteS3UploadWithRetry, refusing to mark uploaded=TRUE if the holder session dies
// and the S3 object is deleted before completion commits.
func TestUploaderResolveRefusesStaleHeadAfterHolderLoss(t *testing.T) {
	ctx := context.Background()
	rdb := openAdminTestDatabase(t)
	t.Cleanup(func() { rdb.Close() })
	endpoint := adminTestDBConfig(t).Write
	pool := rdb.GetOperationalDatabase().GetWritePool()

	var (
		mu      sync.Mutex
		objects = make(map[string][]byte)
		onHead  func(key string)
	)
	const bucket = "resolve-holder-loss-test"
	s3Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/" + bucket + "/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodHead:
			mu.Lock()
			_, ok := objects[key]
			hook := onHead
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if hook != nil {
				hook(key)
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(s3Srv.Close)

	spoolDir := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	cfgContent := fmt.Sprintf(`[database.write]
hosts = [%q]
port = %q
user = %q
password = %q
name = %q

[s3]
endpoint = %q
disable_tls = true
bucket = %q
access_key = "test"
secret_key = "test"

[uploader]
path = %q
`, endpoint.Hosts[0], fmt.Sprint(endpoint.Port), endpoint.User, endpoint.Password, endpoint.Name,
		strings.TrimPrefix(s3Srv.URL, "http://"), bucket, spoolDir)
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfgContent), 0o600))
	var cfg AdminConfig
	require.NoError(t, loadAdminConfig(cfgPath, &cfg))

	stamp := time.Now().UnixNano()
	local := fmt.Sprintf("resolve-holder-%d", stamp)
	domain := "example.com"
	email := local + "@" + domain
	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: email, Password: "password123", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	body := []byte(fmt.Sprintf("Subject: holder %d\r\n\r\nholder body %d", stamp, stamp))
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	mu.Lock()
	objects[key] = body
	mu.Unlock()

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	msgID, _, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     inbox.ID,
		MailboxName:   "INBOX",
		S3Domain:      domain,
		S3Localpart:   local,
		ContentHash:   hash,
		MessageID:     fmt.Sprintf("<holder-%d@example.com>", stamp),
		InternalDate:  time.Now(),
		Size:          int64(len(body)),
		PlaintextBody: "holder body",
		BodyStructure: &bs,
	}, db.PendingUpload{InstanceID: cfg.InstanceID(), ContentHash: hash, Size: int64(len(body)), AccountID: accountID})
	require.NoError(t, err)
	stagedPath := uploader.StagingFilePath(cfg.Uploader.Path, hash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(stagedPath), 0o755))
	require.NoError(t, os.WriteFile(stagedPath, body, 0o644))
	_, err = rdb.ExecWithRetry(ctx, `UPDATE pending_uploads SET attempts = $3 WHERE account_id = $1 AND content_hash = $2`,
		accountID, hash, cfg.Uploader.MaxAttempts)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = rdb.ExecWithRetry(context.Background(), `DELETE FROM pending_uploads WHERE account_id = $1`, accountID)
	})

	lockID := uint64(db.GetS3ObjectLockID(accountID, hash))
	var hadShareLock atomic.Bool
	mu.Lock()
	onHead = func(k string) {
		if k != key {
			return
		}
		var outerPID int
		scanErr := pool.QueryRow(ctx,
			`SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ShareLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`,
			int64(lockID>>32), int64(lockID&0xffffffff),
		).Scan(&outerPID)
		if scanErr == nil && outerPID != 0 {
			hadShareLock.Store(true)
			var killed bool
			_ = pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, outerPID).Scan(&killed)
		}
		mu.Lock()
		delete(objects, key)
		mu.Unlock()
	}
	mu.Unlock()

	require.NoError(t, resolveFailedUploads(ctx, cfg, false, 100))

	require.True(t, hadShareLock.Load(), "uploader resolve probed S3 HEAD without holding shared S3 body advisory lock")
	var uploaded bool
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT uploaded FROM messages WHERE id = $1`, msgID).Scan(&uploaded))
	require.False(t, uploaded, "uploader resolve marked message uploaded=TRUE after losing its S3 body lock holder")
}

// TestDomainPurgePausedPreservesCrossDomainAliases proves `accounts purge-domain`
// refuses upfront while [s3] body_deletion_protocol is unset/"paused", without
// deleting cross-domain aliases in @<domain>.
func TestDomainPurgePausedPreservesCrossDomainAliases(t *testing.T) {
	ctx := context.Background()
	rdb := setupPurgeTestDatabase(t)
	defer rdb.Close()
	s3Storage := createPurgeTestS3Storage(t)

	pausedCfg := createPurgeTestConfig(t)
	pausedCfg.S3.BodyDeletionProtocol = ""

	stamp := time.Now().UnixNano()
	domain := fmt.Sprintf("paused-domain-%d.example.com", stamp)
	owner := fmt.Sprintf("owner-%d@example.org", stamp)
	alias := "alias@" + domain

	createPurgeTestAccount(t, rdb, owner, "password123")
	ownerID, err := rdb.GetAccountIDByEmailWithRetry(ctx, owner)
	require.NoError(t, err)
	require.NoError(t, rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
		AccountID:   ownerID,
		NewEmail:    alias,
		NewPassword: "password123",
		NewHashType: "bcrypt",
	}))

	err = purgeDomainWithStorage(ctx, pausedCfg, rdb, domain, s3Storage)
	require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)

	var aliasRows int
	require.NoError(t, rdb.QueryRowWithRetry(ctx, `SELECT count(*) FROM credentials WHERE LOWER(address) = LOWER($1)`, alias).Scan(&aliasRows))
	require.Equal(t, 1, aliasRows, "purgeDomainWithStorage deleted cross-domain alias %s while body_deletion_protocol was paused", alias)
}
