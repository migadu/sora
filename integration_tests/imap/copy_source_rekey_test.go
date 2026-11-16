//go:build integration

package imap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sourceRekeyFixture is a cross-account COPY of a body that sora-admin import rekey is
// about to rename: the contributor's message is stored as older maildir importers stored
// it, under the SHA-256 digest of its bytes, and the owner of the shared mailbox it is
// copied into has no object for the body under either digest.
type sourceRekeyFixture struct {
	server        *common.TestServer
	fake          *common.FakeS3
	s3            *storage.S3Storage
	cc            *imapclient.Client // the contributor, INBOX selected
	contributorID int64
	ownerID       int64
	ownerEmail    string
	shared        string
	body          []byte
	legacy        db.ContentObject // the contributor's object under the SHA-256 digest
	canonical     db.ContentObject // the same bytes under the BLAKE3 digest
	marker        string
}

func newSourceRekeyFixture(t *testing.T) *sourceRekeyFixture {
	t.Helper()
	server, contributor, fake := common.SetupIMAPServerWithRealS3(t)
	t.Cleanup(server.Close)
	ctx := context.Background()
	rdb := server.ResilientDB

	ownerEmail, ownerID, shared := createOwnerWithSharedMailbox(t, server, contributor.Email, "lrswi")
	contributorID, err := rdb.GetAccountIDByAddressWithRetry(ctx, contributor.Email)
	require.NoError(t, err)

	cc, err := imapclient.DialInsecure(server.Address, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Logout() })
	require.NoError(t, cc.Login(contributor.Email, contributor.Password).Wait())

	const marker = "source rekeyed during copy marker"
	appendTo(t, cc, "INBOX", "Source rekeyed during copy", marker)
	var canonical db.ContentObject
	require.NoError(t, rdb.QueryRowWithRetry(ctx,
		`SELECT s3_domain, s3_localpart, content_hash FROM messages WHERE account_id = $1 AND uploaded AND expunged_at IS NULL`,
		contributorID).Scan(&canonical.S3Domain, &canonical.S3Localpart, &canonical.ContentHash))

	s3storage, err := storage.New(fake.Endpoint(), "test-access-key", "test-secret-key", "test-bucket", false, false, 10*time.Second)
	require.NoError(t, err)
	rc, err := s3storage.Get(canonical.Key())
	require.NoError(t, err)
	body, err := io.ReadAll(rc)
	_ = rc.Close()
	require.NoError(t, err)
	require.Equal(t, canonical.ContentHash, helpers.HashContent(body), "precondition: the stored body hashes to its key")

	// Store the body as an older import did: the contributor's rows (and FTS row) carry
	// the SHA-256 digest, and only the object under that digest exists.
	sum := sha256.Sum256(body)
	legacy := canonical
	legacy.ContentHash = hex.EncodeToString(sum[:])
	require.NoError(t, s3storage.Put(legacy.Key(), bytes.NewReader(body), int64(len(body))))
	require.NoError(t, s3storage.Delete(canonical.Key()))
	_, err = rdb.ExecWithRetry(ctx, `UPDATE messages SET content_hash = $3 WHERE account_id = $1 AND content_hash = $2`,
		contributorID, canonical.ContentHash, legacy.ContentHash)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, `UPDATE messages_fts_v2 SET content_hash = $3 WHERE account_id = $1 AND content_hash = $2`,
		contributorID, canonical.ContentHash, legacy.ContentHash)
	require.NoError(t, err)

	_, err = cc.Select("INBOX", nil).Wait()
	require.NoError(t, err)

	f := &sourceRekeyFixture{
		server:        server,
		fake:          fake,
		s3:            s3storage,
		cc:            cc,
		contributorID: contributorID,
		ownerID:       ownerID,
		ownerEmail:    ownerEmail,
		shared:        shared,
		body:          body,
		legacy:        legacy,
		canonical:     canonical,
		marker:        marker,
	}
	require.Empty(t, fake.Keys(f.ownerKey(legacy.ContentHash)), "precondition: the owner has no object for the body")
	require.Empty(t, fake.Keys(f.ownerKey(canonical.ContentHash)), "precondition: the owner has no object for the body")
	return f
}

func (f *sourceRekeyFixture) ownerKey(contentHash string) string {
	local, domain, _ := strings.Cut(f.ownerEmail, "@")
	return helpers.NewS3Key(domain, local, contentHash)
}

// startCopy starts a COPY of the contributor's message into the shared mailbox and
// returns the channel its result arrives on.
func (f *sourceRekeyFixture) startCopy() <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := f.cc.Copy(imap.SeqSetNum(1), f.shared).Wait()
		done <- err
	}()
	return done
}

// rekey re-keys the contributor's body as sora-admin import rekey does (moveBody), keeping
// the old object for readers that still hold the old hash: under the S3 object lock of the
// new key, write the BLAKE3 object, then move the contributor's rows to it.
func (f *sourceRekeyFixture) rekey(t *testing.T) {
	t.Helper()
	rdb := f.server.ResilientDB
	err := rdb.ExecuteWithS3ObjectLock(context.Background(), f.canonical.ContentHash, f.contributorID, func(ctx context.Context) error {
		if err := f.s3.Put(f.canonical.Key(), bytes.NewReader(f.body), int64(len(f.body))); err != nil {
			return err
		}
		rows, err := rdb.RekeyContentHashWithRetry(ctx, f.contributorID, f.legacy, f.canonical.ContentHash)
		if err == nil && rows != 1 {
			return fmt.Errorf("re-keyed %d rows, want 1", rows)
		}
		return err
	})
	require.NoError(t, err, "rekey")
}

// checkOwnerCopy checks what a COPY that raced with the rekey left behind
// (checkOwnerResult).
func (f *sourceRekeyFixture) checkOwnerCopy(t *testing.T, copyErr error) {
	t.Helper()
	f.checkOwnerResult(t, "COPY", copyErr, func() error {
		_, err := f.cc.Copy(imap.SeqSetNum(1), f.shared).Wait()
		return err
	})
}

// checkOwnerResult checks what a COPY or MOVE (op) that raced with the rekey left behind.
// Every live row of the owner must be readable: an uploaded row's object exists under its
// key, any other row has an upload pending. The operation may instead be refused as one to
// retry, writing nothing; retry then succeeds. Either way the owner ends up reading the
// body.
func (f *sourceRekeyFixture) checkOwnerResult(t *testing.T, op string, opErr error, retry func() error) {
	t.Helper()
	ctx := context.Background()
	pool := f.server.ResilientDB.GetDatabase().GetWritePool()

	rows, err := pool.Query(ctx, `
		SELECT m.content_hash, m.uploaded, m.s3_domain, m.s3_localpart,
		       EXISTS (SELECT 1 FROM pending_uploads p WHERE p.content_hash = m.content_hash AND p.account_id = m.account_id)
		FROM messages m WHERE m.account_id = $1 AND m.expunged_at IS NULL`, f.ownerID)
	require.NoError(t, err)
	var live int
	for rows.Next() {
		var hash, domain, local string
		var uploaded, pending bool
		require.NoError(t, rows.Scan(&hash, &uploaded, &domain, &local, &pending))
		live++
		key := helpers.NewS3Key(domain, local, hash)
		if uploaded {
			assert.NotEmpty(t, f.fake.Keys(key),
				"%s committed uploaded=true under %s, but no object exists there (provisioned: %v)", op, key, f.fake.Keys(f.ownerKey("")))
		} else {
			assert.True(t, pending, "%s committed a row not uploaded under %s with no pending upload", op, key)
		}
	}
	require.NoError(t, rows.Err())

	if opErr != nil {
		var imapErr *imap.Error
		require.ErrorAs(t, opErr, &imapErr, "%s failed: %v", op, opErr)
		assert.Equal(t, imap.ResponseCodeInUse, imapErr.Code, "a %s refused because its source changed must be retryable: %v", op, opErr)
		require.Zero(t, live, "a refused %s must not leave rows behind", op)
		require.NoError(t, retry(), "%s retried after the rekey", op)
	}

	oc, err := imapclient.DialInsecure(f.server.Address, nil)
	require.NoError(t, err)
	defer oc.Logout()
	require.NoError(t, oc.Login(f.ownerEmail, "owner-pass-123").Wait())
	mbox, err := oc.Select(f.shared, nil).Wait()
	require.NoError(t, err)
	require.Equal(t, uint32(1), mbox.NumMessages)
	assert.Contains(t, string(fetchFullBody(t, oc, 1)), f.marker, "owner FETCHes the body from S3 after the %s", op)
}

// copyBarrier is a transaction holding a lock that a COPY is made to wait for, so a
// concurrent operation can be run at a fixed point of the COPY.
type copyBarrier struct {
	server *common.TestServer
	tx     pgx.Tx
	pid    int
}

func newCopyBarrier(t *testing.T, server *common.TestServer, lockSQL string, args ...any) *copyBarrier {
	t.Helper()
	ctx := context.Background()
	tx, err := server.ResilientDB.GetDatabase().GetWritePool().Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	b := &copyBarrier{server: server, tx: tx}
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&b.pid))
	_, err = tx.Exec(ctx, lockSQL, args...)
	require.NoError(t, err)
	return b
}

// waitBlocked waits until another session waits for the barrier's lock.
func (b *copyBarrier) waitBlocked(t *testing.T) {
	t.Helper()
	pool := b.server.ResilientDB.GetDatabase().GetWritePool()
	require.Eventually(t, func() bool {
		var waiting bool
		_ = pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, b.pid).Scan(&waiting)
		return waiting
	}, 10*time.Second, 10*time.Millisecond, "the COPY never waited for the barrier")
}

func (b *copyBarrier) release(t *testing.T) {
	t.Helper()
	require.NoError(t, b.tx.Rollback(context.Background()))
}

// TestCrossAccountCopyOfSourceRekeyedBeforeInsert re-keys the source body after a
// cross-account COPY made it exist under the owner's key for the old hash and before the
// COPY inserts its rows (#761). The COPY must not commit a row under the new hash, whose
// object under the owner's key nothing wrote.
func TestCrossAccountCopyOfSourceRekeyedBeforeInsert(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newSourceRekeyFixture(t)

	// The COPY stops at its UID allocation: after it read the source and copied the body
	// under the owner's key, before its INSERT reads the source rows again.
	barrier := newCopyBarrier(t, f.server,
		`SELECT 1 FROM mailboxes WHERE account_id = $1 AND name = $2 FOR UPDATE`, f.ownerID, f.shared)
	copyDone := f.startCopy()
	barrier.waitBlocked(t)
	require.NotEmpty(t, f.fake.Keys(f.ownerKey(f.legacy.ContentHash)), "the COPY copied the body under the owner's key for the old hash")

	f.rekey(t)
	barrier.release(t)
	f.checkOwnerCopy(t, <-copyDone)
}

// TestCrossAccountCopyOfSourceRekeyedBeforeObjectCheck re-keys the source body after a
// cross-account COPY read it and before the COPY checks the owner's object, i.e. before
// the copy's transaction first reads the source rows. The COPY makes the object exist for
// the hash it read, so it must not commit a row under the new one.
func TestCrossAccountCopyOfSourceRekeyedBeforeObjectCheck(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	f := newSourceRekeyFixture(t)

	// The cleaner's lock of the owner's object for the old hash stops the COPY before it
	// checks that object.
	barrier := newCopyBarrier(t, f.server, `SELECT pg_advisory_xact_lock($1)`,
		db.GetS3ObjectLockID(f.ownerID, f.legacy.ContentHash))
	copyDone := f.startCopy()
	barrier.waitBlocked(t)

	f.rekey(t)
	barrier.release(t)
	f.checkOwnerCopy(t, <-copyDone)
}
