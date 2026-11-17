//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HEAD may already have observed absence while an immutable uploader finishes
// its PUT and SQL publication before the response reaches fix-missing.
func TestVerifyFixMissingDoesNotUndoUploadDuringHead(t *testing.T) {
	f := newRekeyFixture(t)
	account, domain, local := f.account("verify-head-overlap")
	body := f.body("head-overlap")
	hash := helpers.HashContent(body)
	key := helpers.NewS3Key(domain, local, hash)
	row := f.insert(account, "INBOX", domain, local, hash, body, "<head-overlap-"+f.nonce+"@example.org>")
	mem, _ := newMemS3(t)
	headStarted, releaseHead := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseHead) }) }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/"+key) {
			close(headStarted)
			select {
			case <-releaseHead:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNotFound) // absence observed before the PUT
			return
		}
		mem.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { release(); srv.Close() })
	s3, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test", "test", verifyTestBucket, false, false, 10*time.Second)
	require.NoError(t, err)
	type outcome struct {
		count int64
		err   error
	}
	done := make(chan outcome, 1)
	go func() { n, err := fixMissingObject(f.ctx, f.rdb, s3, account, key); done <- outcome{n, err} }()
	select {
	case <-headStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("fix-missing did not reach HEAD")
	}
	var pending int64
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('head-overlap',$1,$2,$3) RETURNING id`, hash, len(body), account).Scan(&pending))
	gate, err := f.rdb.PassS3WriteGateWithRetry(f.ctx, pending, account, hash, "head-overlap", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, db.S3WriteBusy, gate, "repair must exclude a newly admitted uploader until commit")
	if gate == db.S3WriteOpen {
		// Old shared repair admits and finalizes this PUT before its stale HEAD returns.
		require.NoError(t, s3.PutContext(f.ctx, key, bytes.NewReader(body), int64(len(body))))
		require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(f.ctx, pending, "head-overlap", hash, account, []string{key}))
	}
	release()
	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.Zero(t, got.count, "a completed upload must not be marked missing")
	case <-time.After(10 * time.Second):
		t.Fatal("fix-missing did not finish")
	}
	if gate == db.S3WriteBusy {
		gate, err = f.rdb.PassS3WriteGateWithRetry(f.ctx, pending, account, hash, "head-overlap", time.Minute)
		require.NoError(t, err)
		require.Equal(t, db.S3WriteOpen, gate, "repair commit must release its exclusive holder")
		require.NoError(t, s3.PutContext(f.ctx, key, bytes.NewReader(body), int64(len(body))))
		require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(f.ctx, pending, "head-overlap", hash, account, []string{key}))
	}
	var uploaded bool
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, "SELECT uploaded FROM messages WHERE id=$1", row).Scan(&uploaded))
	require.True(t, uploaded, "completed upload was clobbered after the stale HEAD")
}

func TestVerifyFixMissingSameHolderControls(t *testing.T) {
	for _, mode := range []string{"missing", "present", "other_account_pending", "quarantined", "canceled", "holder_lost"} {
		t.Run(mode, func(t *testing.T) {
			f := newRekeyFixture(t)
			account, domain, local := f.account("verify-holder-" + mode)
			body := f.body(mode)
			hash := helpers.HashContent(body)
			key := helpers.NewS3Key(domain, local, hash)
			obj := db.ContentObject{S3Domain: domain, S3Localpart: local, ContentHash: hash}
			row := f.insert(account, "INBOX", domain, local, hash, body, "<holder-"+f.nonce+"@example.org>")
			mem, _ := newMemS3(t)
			if mode == "present" {
				mem.put(key)
			}
			if mode == "other_account_pending" {
				other, _, _ := f.account("verify-other-pending")
				f.exec(`INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('other-pending',$1,$2,$3)`, hash, len(body), other)
			}
			if mode == "quarantined" {
				f.exec(`INSERT INTO s3_body_delete_intents(content_hash,operation_id,object_keys,retire_snapshot) VALUES($1,'11111111-1111-4111-8111-111111111111',$2,'[]')`, hash, []string{key})
				t.Cleanup(func() { f.exec(`DELETE FROM s3_body_delete_intents WHERE content_hash=$1`, hash) })
			}
			killResult := make(chan error, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "holder_lost" && r.Method == http.MethodHead {
					lockID := uint64(db.GetS3ObjectLockID(0, hash))
					var pid int
					err := f.rdb.QueryRowWithRetry(f.ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`, int64(lockID>>32), int64(lockID&0xffffffff)).Scan(&pid)
					if err == nil {
						var killed bool
						err = f.rdb.QueryRowWithRetry(f.ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed)
						if err == nil && !killed {
							err = fmt.Errorf("fixture holder was not terminated")
						}
					}
					killResult <- err
				}
				mem.ServeHTTP(w, r)
			}))
			defer srv.Close()
			s3, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test", "test", verifyTestBucket, false, false, 5*time.Second)
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			checked := false
			count, err := f.rdb.GetOperationalDatabase().MarkMessagesAsNotUploadedIfAbsent(ctx, obj, func(guarded context.Context) (bool, error) {
				checked = true
				exists, _, err := s3.ExistsContext(guarded, key)
				return exists, err
			})
			if mode == "quarantined" || mode == "canceled" || mode == "holder_lost" {
				require.Error(t, err)
				require.Zero(t, count)
			} else {
				require.NoError(t, err)
			}
			if mode == "holder_lost" {
				require.NoError(t, <-killResult)
			}
			if mode == "other_account_pending" || mode == "quarantined" || mode == "canceled" {
				require.False(t, checked)
			}
			var uploaded bool
			require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT uploaded FROM messages WHERE id=$1`, row).Scan(&uploaded))
			if mode == "missing" {
				require.Equal(t, int64(1), count)
				require.False(t, uploaded)
			} else {
				require.Zero(t, count)
				require.True(t, uploaded, "refusal or existing/pending body must preserve the row")
			}
		})
	}
}
