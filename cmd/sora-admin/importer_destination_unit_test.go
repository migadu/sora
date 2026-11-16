package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type destinationCheckDB struct {
	*mockResilientDatabase
	identityErr   error
	identityCalls int
	mailboxErr    error
}

func (d *destinationCheckDB) GetDatabaseIdentityWithRetry(ctx context.Context) (string, error) {
	d.identityCalls++
	if d.identityErr != nil {
		return "", d.identityErr
	}
	return d.mockResilientDatabase.GetDatabaseIdentityWithRetry(ctx)
}

func (d *destinationCheckDB) GetOwnedMailboxIDByNameWithRetry(ctx context.Context, accountID int64, name string) (int64, error) {
	if d.mailboxErr != nil {
		return 0, d.mailboxErr
	}
	return d.mockResilientDatabase.GetOwnedMailboxIDByNameWithRetry(ctx, accountID, name)
}

func newDestinationCheckImporter(t *testing.T, rdb *destinationCheckDB) *Importer {
	t.Helper()
	i, err := NewImporter(context.Background(), newCleanupDBMaildir(t, 0), "user@example.com", 1, nil, nil, ImporterOptions{Incremental: true})
	require.NoError(t, err)
	t.Cleanup(func() { i.Close() })
	i.rdb = rdb
	require.NoError(t, i.lookupAccount())
	return i
}

func seedDestinationCheckRow(t *testing.T, i *Importer, uploaded int) {
	t.Helper()
	_, err := i.sqliteDB.Exec(`INSERT INTO messages
		(path, filename, hash, size, mailbox, s3_uploaded, account_id)
		VALUES (?, 'msg:2,S', 'content', 128, 'INBOX', ?, 1)`,
		filepath.Join(i.maildirPath, "cur", "msg:2,S"), uploaded)
	require.NoError(t, err)
}

func TestImporterDestinationIdentityFailureStopsBeforeScan(t *testing.T) {
	failure := errors.New("primary identity unavailable")
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase(), identityErr: failure}
	i := newDestinationCheckImporter(t, rdb)
	require.ErrorIs(t, i.Run(), failure)
	require.Equal(t, 1, rdb.identityCalls)
	require.Zero(t, i.totalMessages)
	require.Zero(t, i.importedMessages)
	require.Zero(t, rdb.getOrCreateCalls)
}

func TestImporterDestinationTrustedHistoryRestoresProjection(t *testing.T) {
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase()}
	i := newDestinationCheckImporter(t, rdb)
	seedDestinationCheckRow(t, i, 0)
	identity, err := rdb.mockResilientDatabase.GetDatabaseIdentityWithRetry(i.ctx)
	require.NoError(t, err)
	_, err = i.sqliteDB.Exec(`INSERT INTO import_completions
		(database_uuid, account_id, hash, mailbox, completed_at)
		VALUES (?, 1, 'content', 'INBOX', CURRENT_TIMESTAMP)`, identity)
	require.NoError(t, err)
	require.NoError(t, i.recoverOrphanedSQLiteState())
	require.NoError(t, i.recoverOrphanedSQLiteState())
	require.Equal(t, 1, rdb.identityCalls, "identity is resolved once per importer")
	require.Zero(t, rdb.getMailboxByNameCalls, "a trusted deletion must not be rechecked")
	var uploaded int
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT s3_uploaded FROM messages`).Scan(&uploaded))
	require.Equal(t, 1, uploaded)
}

func TestImporterDestinationLegacyNumericStampIsUnverified(t *testing.T) {
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase()}
	i := newDestinationCheckImporter(t, rdb)
	seedDestinationCheckRow(t, i, 1)
	require.NoError(t, i.recoverOrphanedSQLiteState())
	require.Equal(t, 1, rdb.getMailboxByNameCalls)
	var uploaded, completed int
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT s3_uploaded FROM messages`).Scan(&uploaded))
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT COUNT(*) FROM import_completions`).Scan(&completed))
	require.Zero(t, uploaded)
	require.Zero(t, completed)
}

func TestImporterDestinationRecoveryFailureDoesNotTrustLegacyMarks(t *testing.T) {
	failure := errors.New("primary mailbox lookup unavailable")
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase(), mailboxErr: failure}
	i := newDestinationCheckImporter(t, rdb)
	seedDestinationCheckRow(t, i, 1)
	require.ErrorIs(t, i.recoverOrphanedSQLiteState(), failure)
	var uploaded, completed int
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT s3_uploaded FROM messages`).Scan(&uploaded))
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT COUNT(*) FROM import_completions`).Scan(&completed))
	require.Equal(t, 1, uploaded, "failed recovery makes no partial projection changes")
	require.Zero(t, completed, "failed recovery cannot establish trusted history")
}

func TestImporterDestinationLedgerFailureRollsBackMark(t *testing.T) {
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase()}
	i := newDestinationCheckImporter(t, rdb)
	require.NoError(t, i.recoverOrphanedSQLiteState())
	seedDestinationCheckRow(t, i, 0)
	_, err := i.sqliteDB.Exec(`CREATE TRIGGER refuse_completion BEFORE INSERT ON import_completions
		BEGIN SELECT RAISE(ABORT, 'completion failure'); END`)
	require.NoError(t, err)
	require.ErrorContains(t, i.markBatchInSQLite([]markedMessage{{hash: "content", mailbox: "INBOX"}}), "completion failure")
	var uploaded, completed int
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT s3_uploaded FROM messages`).Scan(&uploaded))
	require.NoError(t, i.sqliteDB.QueryRow(`SELECT COUNT(*) FROM import_completions`).Scan(&completed))
	require.Zero(t, uploaded)
	require.Zero(t, completed)
}

func TestImporterDestinationLegacyIdentityRequiresEqualBytesAndCompletedCopy(t *testing.T) {
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase()}
	i := newDestinationCheckImporter(t, rdb)
	content := []byte("Subject: old identity\r\n\r\nunchanged body\r\n")
	m := msgInfo{hash: legacyImportHash(content), mailbox: "INBOX"}
	keep, err := i.keepLegacyImportIdentity(m, content)
	require.NoError(t, err)
	require.False(t, keep, "an unimported SHA cache row still transitions to BLAKE3")
	_, err = i.sqliteDB.Exec(`INSERT INTO import_completions
		(database_uuid, account_id, hash, mailbox, completed_at)
		VALUES ('other-destination', 9, ?, 'INBOX', CURRENT_TIMESTAMP)`, m.hash)
	require.NoError(t, err)
	keep, err = i.keepLegacyImportIdentity(m, content)
	require.NoError(t, err)
	require.True(t, keep, "another destination's history preserves the stable byte identity")
	require.False(t, m.imported, "identity retention must not become current-destination completion")
	m.mailbox = "Archive"
	keep, err = i.keepLegacyImportIdentity(m, content)
	require.NoError(t, err)
	require.False(t, keep, "completion belongs to an exact mailbox copy")
	m.mailbox, m.imported = "INBOX", true
	keep, err = i.keepLegacyImportIdentity(m, []byte("different bytes"))
	require.NoError(t, err)
	require.False(t, keep, "even current-destination completion cannot preserve a stale hash after a real content change")
}

func TestImporterDestinationLegacyIdentityLookupFailsClosed(t *testing.T) {
	rdb := &destinationCheckDB{mockResilientDatabase: newMockResilientDatabase()}
	i := newDestinationCheckImporter(t, rdb)
	content := []byte("Subject: old identity\r\n\r\nbody\r\n")
	_, err := i.sqliteDB.Exec(`DROP TABLE import_completions`)
	require.NoError(t, err)
	keep, err := i.keepLegacyImportIdentity(msgInfo{hash: legacyImportHash(content), mailbox: "INBOX"}, content)
	require.ErrorContains(t, err, "read completed legacy identity")
	require.False(t, keep)
}
