//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rekeyFixture struct {
	t     *testing.T
	ctx   context.Context
	rdb   *resilient.ResilientDatabase
	store *testutils.FileBasedS3Mock
	nonce string
}

func newRekeyFixture(t *testing.T) *rekeyFixture {
	rdb := openAdminTestDatabase(t)
	t.Cleanup(rdb.Close)
	store, err := testutils.NewFileBasedS3Mock(filepath.Join(t.TempDir(), "s3"))
	require.NoError(t, err)
	old := rekeyOldObjectDelay
	rekeyOldObjectDelay = 0
	t.Cleanup(func() { rekeyOldObjectDelay = old })
	return &rekeyFixture{t: t, ctx: context.Background(), rdb: rdb, store: store, nonce: fmt.Sprint(time.Now().UnixNano())}
}

func (f *rekeyFixture) account(name string) (int64, string, string) {
	localpart := fmt.Sprintf("rekey-%s-%s", name, f.nonce)
	accountID, err := f.rdb.CreateAccountWithRetry(f.ctx, db.CreateAccountRequest{
		Email: localpart + "@example.com", Password: "password", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(f.t, err)
	require.NoError(f.t, f.rdb.CreateDefaultMailboxesWithRetry(f.ctx, accountID))
	return accountID, "example.com", localpart
}

func (f *rekeyFixture) body(name string) []byte {
	return []byte(fmt.Sprintf("From: sender@example.org\r\nSubject: %s\r\nMessage-ID: <%s-%s@example.org>\r\n\r\nbody of %s %s\r\n",
		name, name, f.nonce, name, f.nonce))
}

// insert adds a message row the way `import maildir` does, keyed by hash under the S3 path
// s3Domain/s3Localpart, and returns its row id. It does not store the object.
func (f *rekeyFixture) insert(accountID int64, mailbox, s3Domain, s3Localpart, hash string, body []byte, messageID string) int64 {
	mb, err := f.rdb.GetMailboxByNameWithRetry(f.ctx, accountID, mailbox)
	require.NoError(f.t, err)
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	now := time.Now()
	id, _, err := f.rdb.InsertMessageFromImporterWithRetry(f.ctx, &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mb.ID,
		MailboxName:   mailbox,
		S3Domain:      s3Domain,
		S3Localpart:   s3Localpart,
		ContentHash:   hash,
		MessageID:     messageID,
		InternalDate:  now,
		SentDate:      now,
		Size:          int64(len(body)),
		Subject:       "rekey test",
		PlaintextBody: "searchable text " + f.nonce,
		BodyStructure: &bs,
	})
	require.NoError(f.t, err)
	return id
}

func (f *rekeyFixture) put(key string, content []byte) {
	require.NoError(f.t, f.store.Put(key, bytes.NewReader(content), int64(len(content))))
}

func (f *rekeyFixture) exec(sql string, args ...any) {
	_, err := f.rdb.ExecWithRetry(f.ctx, sql, args...)
	require.NoError(f.t, err)
}

func (f *rekeyFixture) hashOf(messageRowID int64) string {
	var hash string
	require.NoError(f.t, f.rdb.GetOperationalDatabase().GetWritePool().QueryRow(f.ctx,
		"SELECT content_hash FROM messages WHERE id = $1", messageRowID).Scan(&hash))
	return hash
}

// ftsText returns the text_body of the FTS row (hash, account), and whether it exists.
func (f *rekeyFixture) ftsText(hash string, accountID int64) (string, bool) {
	var text *string
	err := f.rdb.GetOperationalDatabase().GetWritePool().QueryRow(f.ctx,
		"SELECT text_body FROM messages_fts_v2 WHERE content_hash = $1 AND account_id = $2", hash, accountID).Scan(&text)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false
	}
	require.NoError(f.t, err)
	if text == nil {
		return "", true
	}
	return *text, true
}

func (f *rekeyFixture) stored(key string) ([]byte, bool) {
	return f.store.GetStoredData(key)
}

// TestRekeyLegacySHA256Imports reproduces mail imported before the importer hashed with
// BLAKE3 (rows and objects keyed by SHA-256) and re-keys it.
func TestRekeyLegacySHA256Imports(t *testing.T) {
	f := newRekeyFixture(t)
	accountA, domain, localA := f.account("a")
	accountB, _, _ := f.account("b")
	key := func(hash string) string { return helpers.NewS3Key(domain, localA, hash) }

	// Legacy: one body in two mailboxes, so two rows on one object.
	legacy := f.body("legacy")
	legacyOld, legacyNew := sha256Hex(legacy), helpers.HashContent(legacy)
	legacyInbox := f.insert(accountA, "INBOX", domain, localA, legacyOld, legacy, "legacy-"+f.nonce)
	legacySent := f.insert(accountA, "Sent", domain, localA, legacyOld, legacy, "legacy-"+f.nonce)
	f.put(key(legacyOld), legacy)

	// Already BLAKE3: untouched.
	current := f.body("current")
	currentHash := helpers.HashContent(current)
	currentRow := f.insert(accountA, "INBOX", domain, localA, currentHash, current, "current-"+f.nonce)
	f.put(key(currentHash), current)

	// Corrupt: the bytes match neither digest of the key. Untouched.
	corruptHash := sha256Hex(f.body("corrupt original"))
	corruptRow := f.insert(accountA, "INBOX", domain, localA, corruptHash, f.body("corrupt original"), "corrupt-"+f.nonce)
	f.put(key(corruptHash), []byte("truncated"))

	// Legacy with an intact copy already under its BLAKE3 key: the copy is reused.
	reused := f.body("reused")
	reusedOld, reusedNew := sha256Hex(reused), helpers.HashContent(reused)
	reusedRow := f.insert(accountA, "INBOX", domain, localA, reusedOld, reused, "reused-"+f.nonce)
	f.put(key(reusedOld), reused)
	f.put(key(reusedNew), reused)

	// Legacy, expunged: re-keyed too, a restore brings it back with its hash.
	expunged := f.body("expunged")
	expungedOld, expungedNew := sha256Hex(expunged), helpers.HashContent(expunged)
	expungedRow := f.insert(accountA, "INBOX", domain, localA, expungedOld, expunged, "expunged-"+f.nonce)
	f.put(key(expungedOld), expunged)
	f.exec("UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE id = $1", expungedRow)

	// Legacy with a pending upload: left for a later run.
	pending := f.body("pending")
	pendingOld := sha256Hex(pending)
	pendingRow := f.insert(accountA, "INBOX", domain, localA, pendingOld, pending, "pending-"+f.nonce)
	f.put(key(pendingOld), pending)
	f.exec("INSERT INTO pending_uploads (instance_id, content_hash, size, account_id) VALUES ('rekey-test', $1, $2, $3)",
		pendingOld, len(pending), accountA)

	// Legacy, also referenced by a row of account B under A's S3 path: A's rows move, the
	// old object stays until B's run.
	shared := f.body("shared")
	sharedOld, sharedNew := sha256Hex(shared), helpers.HashContent(shared)
	sharedRowA := f.insert(accountA, "INBOX", domain, localA, sharedOld, shared, "shared-"+f.nonce)
	sharedRowB := f.insert(accountB, "INBOX", domain, localA, sharedOld, shared, "shared-"+f.nonce)
	f.put(key(sharedOld), shared)

	objectsBefore := f.store.ObjectCount()
	_, ok := f.ftsText(legacyOld, accountA)
	require.True(t, ok, "the import staged an FTS row under the SHA-256 hash")

	// Dry run: classifies, changes nothing.
	report, err := rekeyAccount(f.ctx, f.rdb, f.store, accountA, rekeyOptions{DryRun: true, BatchSize: 2, Jobs: 3})
	require.NoError(t, err)
	assert.Equal(t, 7, report.Checked)
	assert.Equal(t, 1, report.Current)
	assert.Equal(t, 5, report.Legacy)
	assert.Len(t, report.Unrecognised, 1)
	assert.Zero(t, report.Rekeyed)
	assert.Equal(t, legacyOld, f.hashOf(legacyInbox))
	assert.Equal(t, objectsBefore, f.store.ObjectCount())

	report, err = rekeyAccount(f.ctx, f.rdb, f.store, accountA, rekeyOptions{BatchSize: 2, Jobs: 3})
	require.NoError(t, err)
	assert.Equal(t, 5, report.Legacy)
	assert.Equal(t, 4, report.Rekeyed, "legacy, reused, expunged, shared")
	assert.Equal(t, int64(5), report.RowsUpdated)
	assert.Equal(t, 3, report.Written)
	assert.Equal(t, 1, report.Reused)
	assert.Equal(t, 3, report.OldDeleted)
	assert.Equal(t, []string{key(sharedOld)}, report.OldKept)
	assert.Equal(t, []string{key(pendingOld)}, report.Pending)
	assert.Len(t, report.Unrecognised, 1)
	assert.Empty(t, report.Failed)
	assert.Empty(t, report.OldLeft)

	// Rows: moved to BLAKE3, the rest untouched.
	assert.Equal(t, legacyNew, f.hashOf(legacyInbox))
	assert.Equal(t, legacyNew, f.hashOf(legacySent))
	assert.Equal(t, reusedNew, f.hashOf(reusedRow))
	assert.Equal(t, expungedNew, f.hashOf(expungedRow))
	assert.Equal(t, sharedNew, f.hashOf(sharedRowA))
	assert.Equal(t, sharedOld, f.hashOf(sharedRowB), "another account's row is that account's run")
	assert.Equal(t, currentHash, f.hashOf(currentRow))
	assert.Equal(t, corruptHash, f.hashOf(corruptRow))
	assert.Equal(t, pendingOld, f.hashOf(pendingRow))

	// Objects: the body under its BLAKE3 key, the old object gone unless still referenced.
	for _, c := range []struct {
		body     []byte
		old, new string
		oldKept  bool
	}{
		{legacy, legacyOld, legacyNew, false},
		{reused, reusedOld, reusedNew, false},
		{expunged, expungedOld, expungedNew, false},
		{shared, sharedOld, sharedNew, true},
	} {
		got, ok := f.stored(key(c.new))
		if assert.True(t, ok, "%s missing", key(c.new)) {
			assert.Equal(t, c.body, got)
			_, err := verifyS3Content(f.store, key(c.new), c.new)
			assert.NoError(t, err)
		}
		_, ok = f.stored(key(c.old))
		assert.Equal(t, c.oldKept, ok, "old object %s", key(c.old))
	}
	_, ok = f.stored(key(pendingOld))
	assert.True(t, ok)
	_, ok = f.stored(key(corruptHash))
	assert.True(t, ok)

	// Search: A's FTS row moved with A's rows; B's row still needs its own.
	text, ok := f.ftsText(legacyNew, accountA)
	assert.True(t, ok)
	assert.Equal(t, "searchable text "+f.nonce, text)
	_, ok = f.ftsText(legacyOld, accountA)
	assert.False(t, ok, "the old hash's FTS row is gone")
	_, ok = f.ftsText(sharedNew, accountA)
	assert.True(t, ok)
	_, ok = f.ftsText(sharedOld, accountA)
	assert.False(t, ok)
	_, ok = f.ftsText(sharedOld, accountB)
	assert.True(t, ok, "account B's row still references the old hash")

	// Importing the same message again now matches the existing row (the importer's
	// duplicate check is on message_id and content_hash) instead of adding a second copy.
	inbox, err := f.rdb.GetMailboxByNameWithRetry(f.ctx, accountA, "INBOX")
	require.NoError(t, err)
	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	_, _, err = f.rdb.InsertMessageFromImporterWithRetry(f.ctx, &db.InsertMessageOptions{
		AccountID: accountA, MailboxID: inbox.ID, MailboxName: "INBOX", S3Domain: domain, S3Localpart: localA,
		ContentHash: legacyNew, MessageID: "legacy-" + f.nonce, InternalDate: time.Now(), SentDate: time.Now(),
		Size: int64(len(legacy)), BodyStructure: &bs,
	})
	assert.ErrorIs(t, err, consts.ErrDBUniqueViolation)

	// Running again changes nothing: the pending body is still pending, the rest is done.
	report, err = rekeyAccount(f.ctx, f.rdb, f.store, accountA, rekeyOptions{BatchSize: 3, Jobs: 2})
	require.NoError(t, err)
	assert.Equal(t, 1, report.Legacy)
	assert.Zero(t, report.Rekeyed)
	assert.Zero(t, report.Written)
	assert.Equal(t, []string{key(pendingOld)}, report.Pending)

	// Account B's run moves its row onto the object A's run wrote, and the old object,
	// referenced by nothing now, goes.
	report, err = rekeyAccount(f.ctx, f.rdb, f.store, accountB, rekeyOptions{BatchSize: 10, Jobs: 1})
	require.NoError(t, err)
	assert.Equal(t, 1, report.Rekeyed)
	assert.Equal(t, 1, report.Reused)
	assert.Equal(t, 1, report.OldDeleted)
	assert.Equal(t, sharedNew, f.hashOf(sharedRowB))
	_, ok = f.stored(key(sharedOld))
	assert.False(t, ok)
	_, ok = f.ftsText(sharedOld, accountB)
	assert.False(t, ok)
	_, ok = f.ftsText(sharedNew, accountB)
	assert.True(t, ok)
}

// TestRekeyOldObjectWaitsAndRechecks: the old object is deleted only after the delay, and
// only if no row has claimed it meanwhile (here: a row written with the old hash after the
// re-key committed, as a COPY that read its source before the re-key would).
func TestRekeyOldObjectWaitsAndRechecks(t *testing.T) {
	f := newRekeyFixture(t)
	rekeyOldObjectDelay = 300 * time.Millisecond
	accountID, domain, local := f.account("late")
	body := f.body("late")
	oldHash := sha256Hex(body)
	f.insert(accountID, "INBOX", domain, local, oldHash, body, "late-"+f.nonce)
	oldKey := helpers.NewS3Key(domain, local, oldHash)
	f.put(oldKey, body)

	r := &rekeyRun{rdb: f.rdb, store: f.store, accountID: accountID, opts: rekeyOptions{BatchSize: 10, Jobs: 1},
		report: &rekeyReport{}, written: map[db.ContentObject]bool{}}
	obj := db.ContentObject{S3Domain: domain, S3Localpart: local, ContentHash: oldHash}
	r.processObject(f.ctx, obj)
	require.Equal(t, 1, r.report.Rekeyed)

	r.deleteOldObjects(f.ctx, false)
	_, ok := f.stored(oldKey)
	assert.True(t, ok, "deleted before the delay")
	require.Len(t, r.oldObjects, 1)

	f.insert(accountID, "Sent", domain, local, oldHash, body, "late-copy-"+f.nonce)
	r.deleteOldObjects(f.ctx, true)
	_, ok = f.stored(oldKey)
	assert.True(t, ok, "deleted although a row references it")
	assert.Equal(t, []string{oldKey}, r.report.OldKept)
	assert.Zero(t, r.report.OldDeleted)
	assert.False(t, strings.Contains(strings.Join(r.report.OldLeft, ","), oldKey))
}
