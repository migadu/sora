//go:build integration

package main

import (
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pausingDeleteStore holds its first Delete until release is closed, so a test can act
// while that delete is in flight.
type pausingDeleteStore struct {
	*testutils.FileBasedS3Mock
	deleting chan struct{}
	release  chan struct{}
}

func (s *pausingDeleteStore) Delete(key string) error {
	close(s.deleting)
	<-s.release
	return s.FileBasedS3Mock.Delete(key)
}

// TestRekeyOldObjectDeleteKeepsOutAnotherAccountsUpload: rows of another account can point
// at the same S3 object (a row's key is the address its account had when the row was
// written, and addresses move between accounts). Here that account's delivery of the body
// (a row under the old key, its upload pending) commits after the reference check, while the
// DELETE is in flight. Its upload must wait for the delete, as an upload of the same account
// does; written before it, the DELETE removes the body under a live row marked uploaded
// (#557).
func TestRekeyOldObjectDeleteKeepsOutAnotherAccountsUpload(t *testing.T) {
	f := newRekeyFixture(t)
	accountID, domain, local := f.account("deleter")
	otherID, _, _ := f.account("claimer")
	body := f.body("claimed")
	oldHash := sha256Hex(body)
	oldKey := helpers.NewS3Key(domain, local, oldHash)
	f.put(oldKey, body)

	store := &pausingDeleteStore{FileBasedS3Mock: f.store, deleting: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-store.release:
		default:
			close(store.release)
		}
	})
	r := &rekeyRun{rdb: f.rdb, store: store, accountID: accountID, opts: rekeyOptions{DeleteOldObjects: true, BodyDeletionProtocol: "global-hash-v1", BatchSize: 10, Jobs: 1},
		report: &rekeyReport{}, written: map[db.ContentObject]bool{}}
	deleted := make(chan struct{})
	go func() {
		defer close(deleted)
		r.deleteOldObject(f.ctx, db.ContentObject{S3Domain: domain, S3Localpart: local, ContentHash: oldHash})
	}()
	select {
	case <-store.deleting:
	case <-time.After(10 * time.Second):
		close(store.release)
		t.Fatal("the old object's DELETE did not start")
	}

	// Stage a not-uploaded reference while DELETE is in flight. This raw fixture
	// does not claim existing remote bytes; uploaded admission uses the guarded APIs.
	mb, err := f.rdb.GetMailboxByNameWithRetry(f.ctx, otherID, "INBOX")
	require.NoError(t, err)
	var row int64
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `WITH next AS(UPDATE mailboxes SET highest_uid=highest_uid+1 WHERE id=$2 RETURNING highest_uid), ins AS(INSERT INTO messages(account_id,mailbox_id,uid,content_hash,sent_date,internal_date,size,uploaded,s3_domain,s3_localpart,message_id,body_structure,recipients_json,created_modseq) SELECT $1,$2,highest_uid,$3,now(),now(),$4,false,$5,$6,$7,'body','[]',nextval('messages_modseq') FROM next RETURNING id,mailbox_id), state AS(INSERT INTO message_state(message_id,mailbox_id,flags) SELECT id,mailbox_id,0 FROM ins) SELECT id FROM ins`, otherID, mb.ID, oldHash, len(body), domain, local, "claimed-"+f.nonce).Scan(&row))
	var pendingID int64
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx,
		`INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('other-node', $1, $2, $3) RETURNING id`,
		oldHash, len(body), otherID).Scan(&pendingID))

	// What server/uploader does: write and finalize once the gate opens; a busy gate defers
	// the upload to a later round.
	upload := func() db.S3WriteGate {
		gate, err := f.rdb.PassS3WriteGateWithRetry(f.ctx, pendingID, otherID, oldHash, "other-node", time.Minute)
		require.NoError(t, err)
		if gate == db.S3WriteOpen {
			f.put(oldKey, body)
			require.NoError(t, f.rdb.CompleteLeasedS3UploadWithRetry(f.ctx, pendingID, "other-node", oldHash, otherID, []string{oldKey}))
		}
		return gate
	}
	gate := upload()
	close(store.release)
	<-deleted
	assert.Equal(t, db.S3WriteBusy, gate, "another account's upload of the body opened while its delete was in flight")
	if gate != db.S3WriteOpen {
		require.Equal(t, db.S3WriteOpen, upload(), "the deferred upload must run once the delete is over")
	}

	_, ok := f.stored(oldKey)
	assert.True(t, ok, "the DELETE removed the body another account had just uploaded")
	var uploaded bool
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT uploaded FROM messages WHERE id = $1`, row).Scan(&uploaded))
	assert.True(t, uploaded)
}
