//go:build integration

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
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
	t.Cleanup(srv.Close)
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
	require.Equal(t, db.S3WriteOpen, gate, "shared repair must currently allow this real uploader interleave")
	require.NoError(t, s3.PutContext(f.ctx, key, bytes.NewReader(body), int64(len(body))))
	require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(f.ctx, pending, "head-overlap", hash, account, []string{key}))
	close(releaseHead)
	select {
	case got := <-done:
		require.NoError(t, got.err)
		require.Zero(t, got.count, "a completed upload must not be marked missing")
	case <-time.After(10 * time.Second):
		t.Fatal("fix-missing did not finish")
	}
	var uploaded bool
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, "SELECT uploaded FROM messages WHERE id=$1", row).Scan(&uploaded))
	require.True(t, uploaded, "completed upload was clobbered after the stale HEAD")
}
