//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

func TestRekeyDeleteHolderLossQuarantinesNewClaim(t *testing.T) {
	f := newRekeyFixture(t)
	ctx := context.Background()
	a, domain, local := f.account("delete-owner")
	body := f.body("delete-holder")
	hash := sha256Hex(body)
	key := helpers.NewS3Key(domain, local, hash)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	present := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, r.Body)
			mu.Lock()
			present = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			close(entered)
			<-release
			mu.Lock()
			present = false
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer func() { unblock(); srv.Close() }()
	st, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test", "secret", "bucket", false, false, 10*time.Second)
	require.NoError(t, err)
	require.NoError(t, st.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
	r := &rekeyRun{rdb: f.rdb, store: st, accountID: a, opts: rekeyOptions{BodyDeletionProtocol: "global-hash-v1"}, report: &rekeyReport{}}
	done := make(chan struct{})
	go func() {
		r.deleteOldObject(ctx, db.ContentObject{S3Domain: domain, S3Localpart: local, ContentHash: hash})
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("real rekey DELETE did not reach storage")
	}
	id := uint64(db.GetS3ObjectLockID(a, hash))
	pool := f.rdb.GetOperationalDatabase().GetWritePool()
	var pid int
	require.NoError(t, pool.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`, int64(id>>32), int64(id&0xffffffff)).Scan(&pid))
	var killed bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&killed))
	require.True(t, killed)
	b, _, _ := f.account("new-claim")
	mb, err := f.rdb.GetMailboxByNameWithRetry(ctx, b, "INBOX")
	require.NoError(t, err)
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	_, _, err = f.rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{AccountID: b, MailboxID: mb.ID, MailboxName: mb.Name, S3Domain: domain, S3Localpart: local, ContentHash: hash, MessageID: fmt.Sprintf("<new-%d@example.org>", time.Now().UnixNano()), BodyStructure: &bs, Size: int64(len(body))}, db.PendingUpload{AccountID: b, ContentHash: hash, InstanceID: "new-claim", Size: int64(len(body))})
	require.NoError(t, err)
	var pending int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT id FROM pending_uploads WHERE account_id=$1 AND content_hash=$2`, b, hash).Scan(&pending))
	gate, err := f.rdb.PassS3WriteGateWithRetry(ctx, pending, b, hash, "new-claim", time.Minute)
	require.NoError(t, err)
	if gate == db.S3WriteOpen {
		require.NoError(t, st.PutContext(ctx, key, bytes.NewReader(body), int64(len(body))))
		require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(ctx, pending, "new-claim", hash, b, []string{key}))
	}
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("rekey deletion did not finish")
	}
	var uploaded bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT uploaded FROM messages WHERE account_id=$1 AND content_hash=$2`, b, hash).Scan(&uploaded))
	mu.Lock()
	exists := present
	mu.Unlock()
	require.False(t, uploaded && !exists, "rekey's accepted DELETE removed a new committed body after PG holder loss")
	require.Equal(t, db.S3WriteBusy, gate)
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&n))
	require.Equal(t, 1, n, "unknown rekey DELETE lost its durable fence")
	require.NotEmpty(t, append(r.report.OldLeft, r.report.Failed...), "uncertain deletion was reported as an unqualified success")
}
