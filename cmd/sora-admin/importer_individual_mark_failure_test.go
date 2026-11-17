package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type individualMarkOutcome int

const (
	individualInsertOK individualMarkOutcome = iota
	individualDuplicate
)

type scriptedIndividualDB struct {
	*mockResilientDatabase
	outcomes      map[string]individualMarkOutcome
	forceFallback bool
}

func (d *scriptedIndividualDB) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	if d.forceFallback {
		return nil, nil, nil, consts.ErrDBUniqueViolation
	}
	var ids, uids []int64
	var hashes []string
	var next int64
	for _, opt := range opts {
		if d.outcomes[opt.MessageID] == individualDuplicate {
			continue
		}
		next++
		ids = append(ids, next)
		uids = append(uids, next)
		hashes = append(hashes, opt.ContentHash)
	}
	return ids, uids, hashes, nil
}

func (d *scriptedIndividualDB) InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error) {
	if d.outcomes[opts.MessageID] == individualDuplicate {
		return 0, 0, consts.ErrDBUniqueViolation
	}
	return 1, 1, nil
}

func installSQLiteMarkFailureTrigger(t *testing.T, importer *Importer) {
	t.Helper()
	_, err := importer.sqliteDB.Exec(`
		CREATE TRIGGER abort_individual_mark BEFORE INSERT ON import_completions
		BEGIN
			SELECT RAISE(ABORT, 'simulated sqlite mark failure');
		END`)
	require.NoError(t, err)
}

func expectedCleanupMaildirPaths(maildirPath string) []string {
	return []string{
		filepath.Join(maildirPath, "cur", "1700000001.M1P1.host:2,S"),
		filepath.Join(maildirPath, "cur", "1700000002.M2P1.host:2,S"),
		filepath.Join(maildirPath, "cur", "1700000003.M3P1.host:2,S"),
	}
}

func completionCount(t *testing.T, maildirPath string) int {
	t.Helper()
	importer, err := NewImporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{})
	require.NoError(t, err)
	defer importer.Close()
	var completed int
	require.NoError(t, importer.sqliteDB.QueryRow(`SELECT COUNT(*) FROM import_completions`).Scan(&completed))
	return completed
}

// TestIndividualMarkFailure (#1784): in default individual-transaction mode
// (!BatchTransactionMode), duplicate-skipped messages must not be counted in
// skippedMessages until markBatchInSQLite commits, and a markBatchInSQLite failure
// must record and count every unmarked message (both newly inserted and
// duplicate-skipped) in failedPaths and failedMessages so Run fails and --cleanup-db
// preserves sora-maildir.db.
func TestIndividualMarkFailure(t *testing.T) {
	for _, mode := range []struct {
		name          string
		forceFallback bool
	}{
		{name: "batch insert path", forceFallback: false},
		{name: "individual fallback path", forceFallback: true},
	} {
		t.Run("all-duplicate batch fails Run, records failedPaths, and preserves cache under --cleanup-db/"+mode.name, func(t *testing.T) {
			maildirPath := newCleanupDBMaildir(t, 3)
			rdb := &scriptedIndividualDB{
				mockResilientDatabase: newMockResilientDatabase(),
				forceFallback:         mode.forceFallback,
				outcomes: map[string]individualMarkOutcome{
					"cleanup-1@example.com": individualDuplicate,
					"cleanup-2@example.com": individualDuplicate,
					"cleanup-3@example.com": individualDuplicate,
				},
			}
			importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
				BatchTransactionMode: false,
				CleanupDB:            true,
			})
			installSQLiteMarkFailureTrigger(t, importer)

			err := importer.Run()
			require.Error(t, err)
			assert.Equal(t, "import completed with 3 failed messages", err.Error())
			assert.Equal(t, int64(3), importer.totalMessages)
			assert.Equal(t, int64(3), importer.failedMessages)
			assert.Zero(t, importer.skippedMessages)
			assert.Zero(t, importer.importedMessages)

			assert.ElementsMatch(t, expectedCleanupMaildirPaths(maildirPath), recordedFailedPaths(importer))
			for _, reason := range recordedFailedReasons(importer) {
				assert.True(t, strings.HasPrefix(reason, "failed to update SQLite cache: "), "unexpected reason: %s", reason)
			}

			dbPath := filepath.Join(maildirPath, "sora-maildir.db")
			require.FileExists(t, dbPath, "failed SQLite completion mark must preserve sora-maildir.db under --cleanup-db")

			imported, pending := uploadedCounts(t, maildirPath)
			assert.Equal(t, 0, imported)
			assert.Equal(t, 3, pending)
			assert.Equal(t, 0, completionCount(t, maildirPath))
		})

		t.Run("mixed inserted and duplicate-skipped batch records all unmarked paths without double counting/"+mode.name, func(t *testing.T) {
			maildirPath := newCleanupDBMaildir(t, 3)
			rdb := &scriptedIndividualDB{
				mockResilientDatabase: newMockResilientDatabase(),
				forceFallback:         mode.forceFallback,
				outcomes: map[string]individualMarkOutcome{
					"cleanup-1@example.com": individualDuplicate,
					"cleanup-2@example.com": individualDuplicate,
					"cleanup-3@example.com": individualInsertOK,
				},
			}
			importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
				BatchTransactionMode: false,
			})
			installSQLiteMarkFailureTrigger(t, importer)

			err := importer.Run()
			require.Error(t, err)
			assert.Equal(t, "import completed with 3 failed messages", err.Error())
			assert.Equal(t, int64(3), importer.totalMessages)
			assert.Equal(t, int64(3), importer.failedMessages)
			assert.Zero(t, importer.skippedMessages,
				"duplicate-skipped messages whose SQLite completion mark rolled back must not stay counted in skippedMessages")
			assert.Zero(t, importer.importedMessages)

			assert.ElementsMatch(t, expectedCleanupMaildirPaths(maildirPath), recordedFailedPaths(importer))
			for _, reason := range recordedFailedReasons(importer) {
				assert.True(t, strings.HasPrefix(reason, "failed to update SQLite cache: "), "unexpected reason: %s", reason)
			}

			imported, pending := uploadedCounts(t, maildirPath)
			assert.Equal(t, 0, imported)
			assert.Equal(t, 3, pending)
			assert.Equal(t, 0, completionCount(t, maildirPath))
		})

		t.Run("committed mark records skips and imports once/"+mode.name, func(t *testing.T) {
			maildirPath := newCleanupDBMaildir(t, 3)
			rdb := &scriptedIndividualDB{
				mockResilientDatabase: newMockResilientDatabase(),
				forceFallback:         mode.forceFallback,
				outcomes: map[string]individualMarkOutcome{
					"cleanup-1@example.com": individualDuplicate,
					"cleanup-2@example.com": individualDuplicate,
					"cleanup-3@example.com": individualInsertOK,
				},
			}
			importer := newTestModeImporter(t, maildirPath, rdb, ImporterOptions{
				BatchTransactionMode: false,
			})

			require.NoError(t, importer.Run())
			assert.Equal(t, int64(3), importer.totalMessages)
			assert.Equal(t, int64(1), importer.importedMessages)
			assert.Equal(t, int64(2), importer.skippedMessages)
			assert.Zero(t, importer.failedMessages)
			assert.Empty(t, recordedFailedPaths(importer))

			imported, pending := uploadedCounts(t, maildirPath)
			assert.Equal(t, 3, imported)
			assert.Equal(t, 0, pending)
			assert.Equal(t, 3, completionCount(t, maildirPath))
		})
	}
}
