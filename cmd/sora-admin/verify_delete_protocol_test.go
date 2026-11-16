//go:build integration

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/require"
)

// The storage request deliberately ignores client cancellation. Losing a PG
// connection cannot retract a DELETE already accepted by another service.
func TestVerifyOrphanDeleteFencesLateCrossAccountClaim(t *testing.T) {
	for _, loseHolder := range []bool{false, true} {
		name := "live_holder"
		if loseHolder {
			name = "lost_holder"
		}
		t.Run(name, func(t *testing.T) {
			f := newRekeyFixture(t)
			mem, _ := newMemS3(t)
			owner, domain, local := f.account("verify-holder")
			other, _, _ := f.account("verify-claimer")
			body := f.body("late-claim")
			hash := helpers.HashContent(body)
			key := helpers.NewS3Key(domain, local, hash)
			mem.put(key)
			// A separate live key supplies a valid staging-row shape. Creating
			// uploaded=false metadata is not permission to publish body claims.
			templateBody := f.body("staging-template")
			template := f.insert(owner, "INBOX", domain, local, helpers.HashContent(templateBody), templateBody, "<template-"+f.nonce+"@example.com>")
			mailbox, err := f.rdb.GetMailboxByNameWithRetry(f.ctx, other, "INBOX")
			require.NoError(t, err)
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					enteredOnce.Do(func() { close(entered) })
					<-release
				}
				mem.ServeHTTP(w, r)
			}))
			defer func() { unblock(); srv.Close() }()
			store, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test-access", "test-secret", verifyTestBucket, false, false, 10*time.Second)
			require.NoError(t, err)
			otherNode, err := newAdminDatabase(f.ctx, adminTestDBConfig(t))
			require.NoError(t, err)
			defer otherNode.Close()
			type outcome struct {
				deleted bool
				err     error
			}
			done := make(chan outcome, 1)
			go func() {
				deleted, err := deleteOrphanedObject(f.ctx, f.rdb, store, owner, key)
				done <- outcome{deleted, err}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("orphan DELETE did not start")
			}
			if loseHolder {
				id := uint64(db.GetS3ObjectLockID(owner, hash))
				var pid int
				require.NoError(t, otherNode.QueryRowWithRetry(f.ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND granted AND mode='ExclusiveLock' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND classid=$1::bigint::oid AND objid=$2::bigint::oid AND objsubid=1`, int64(id>>32), int64(id&0xffffffff)).Scan(&pid))
				var terminated bool
				require.NoError(t, otherNode.QueryRowWithRetry(f.ctx, `SELECT pg_terminate_backend($1)`, pid).Scan(&terminated))
				require.True(t, terminated)
			}
			var rowID, pendingID int64
			require.NoError(t, otherNode.QueryRowWithRetry(f.ctx, `INSERT INTO messages(account_id,mailbox_id,uid,mailbox_path,content_hash,s3_domain,s3_localpart,message_id,internal_date,sent_date,size,body_structure,recipients_json,created_modseq,uploaded) SELECT $1,$2,16777215,'INBOX',$3,$4,$5,$6,internal_date,sent_date,size,body_structure,recipients_json,nextval('messages_modseq'),false FROM messages WHERE id=$7 RETURNING id`, other, mailbox.ID, hash, domain, local, "<late-"+f.nonce+"@example.com>", template).Scan(&rowID))
			require.NoError(t, otherNode.QueryRowWithRetry(f.ctx, `INSERT INTO pending_uploads(instance_id,content_hash,size,account_id) VALUES('verify-claim',$1,$2,$3) RETURNING id`, hash, len(body), other).Scan(&pendingID))
			gate, err := otherNode.PassS3WriteGateWithRetry(f.ctx, pendingID, other, hash, "verify-claim", time.Minute)
			require.NoError(t, err)
			if gate == db.S3WriteOpen {
				require.NoError(t, store.PutContext(f.ctx, key, bytes.NewReader(body), int64(len(body))))
				require.NoError(t, otherNode.CompleteLeasedS3UploadWithRetry(f.ctx, pendingID, "verify-claim", hash, other, []string{key}))
			}
			unblock()
			var result outcome
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("orphan DELETE did not settle")
			}
			var uploaded bool
			require.NoError(t, otherNode.QueryRowWithRetry(f.ctx, `SELECT uploaded FROM messages WHERE id=$1`, rowID).Scan(&uploaded))
			require.False(t, uploaded && !mem.has(key), "verifier removed a newly committed live body")
			require.Equal(t, db.S3WriteBusy, gate)
			if loseHolder {
				require.Error(t, result.err)
				require.False(t, result.deleted)
			} else {
				require.NoError(t, result.err)
				require.True(t, result.deleted)
			}
			if loseHolder {
				_, err = otherNode.ExecWithRetry(f.ctx, `UPDATE s3_body_delete_intents SET created_at=now()-interval '100 years' WHERE content_hash=$1`, hash)
				require.NoError(t, err)
				gate, err = otherNode.PassS3WriteGateWithRetry(f.ctx, pendingID, other, hash, "after-delete", time.Nanosecond)
				require.NoError(t, err)
				require.Equal(t, db.S3WriteBusy, gate, "storage uncertainty must not expire")
			}
		})
	}
}

func TestVerifyOrphanDeleteKnownRefusalReleasesOnlyItsFence(t *testing.T) {
	f := newRekeyFixture(t)
	owner, domain, local := f.account("verify-refusal")
	hash := helpers.HashContent(f.body("refused"))
	key := helpers.NewS3Key(domain, local, hash)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	store, err := storage.New(strings.TrimPrefix(srv.URL, "http://"), "test-access", "test-secret", verifyTestBucket, false, false, time.Second)
	require.NoError(t, err)
	deleted, err := deleteOrphanedObject(context.Background(), f.rdb, store, owner, key)
	require.Error(t, err)
	require.False(t, deleted)
	var count int
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT count(*) FROM s3_body_delete_intents WHERE content_hash=$1`, hash).Scan(&count))
	require.Zero(t, count, "an explicit first-attempt refusal can release its own durable intent")
}
