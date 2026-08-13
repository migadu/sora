package uploader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestCleanupOrphanedFilesResolvesFilesInOneQueryPerAccount pins the cost of the
// cleanup scan. The scan runs every five minutes over the whole staging tree, and
// the tree is at its largest during an S3 outage or a stranded backlog - precisely
// when the database is already carrying the queue. Asking "is this file orphaned?"
// once per file turns every cycle into tens of thousands of retry-wrapped point
// queries for an answer one query can give.
func TestCleanupOrphanedFilesResolvesFilesInOneQueryPerAccount(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	const filesPerAccount = 20
	accounts := []int64{4001, 4002}
	staged := make(map[string]bool) // path -> should survive the scan

	for _, accountID := range accounts {
		for i := 0; i < filesPerAccount; i++ {
			hash := fmt.Sprintf("%064x", accountID*1000+int64(i))
			path := worker.FilePath(hash, accountID)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
			require.NoError(t, os.WriteFile(path, []byte("message body"), 0644))
			old := time.Now().Add(-2 * time.Hour)
			require.NoError(t, os.Chtimes(path, old, old))

			// Half of the files are a backlog waiting on S3, half are true orphans.
			queued := i%2 == 0
			staged[path] = queued
			if queued {
				mockDB.setPendingUpload(accountID, hash)
			}
			mockDB.On("PendingUploadExistsWithRetry", mock.Anything, hash, accountID).
				Return(queued, nil).Maybe()
		}
	}

	require.NoError(t, worker.cleanupOrphanedFiles(context.Background()))

	for path, shouldSurvive := range staged {
		_, err := os.Stat(path)
		if shouldSurvive {
			require.NoError(t, err, "file with a committed pending_uploads row must survive the cleanup scan")
		} else {
			require.True(t, os.IsNotExist(err), "orphaned file must be removed by the cleanup scan")
		}
	}

	if got := mockDB.lookups(); got > len(accounts) {
		t.Fatalf("cleanup issued %d database lookups for %d staged files across %d accounts, want at most %d: "+
			"a point query per file makes every 5-minute cycle scale with the size of the staging tree, "+
			"which peaks exactly when S3 is down and the database is already carrying the backlog",
			got, filesPerAccount*len(accounts), len(accounts), len(accounts))
	}
}

// TestCleanupOrphanedFilesKeepsFilesWhenLookupFails keeps the conservative rule
// intact under batching: a staged file is deleted only on a definite answer that no
// pending_uploads row exists. If the lookup itself fails, every file it covered
// stays on disk - deleting one loses a message the uploader would have retried.
func TestCleanupOrphanedFilesKeepsFilesWhenLookupFails(t *testing.T) {
	uploadDir := t.TempDir()
	mockDB := new(mockUploaderDB)
	mockDB.batchErr = fmt.Errorf("connection refused")

	worker := &UploadWorker{
		rdb:  mockDB,
		path: uploadDir,
	}

	const hash = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"
	const accountID = int64(4003)

	path := worker.FilePath(hash, accountID)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	require.NoError(t, os.WriteFile(path, []byte("message body"), 0644))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))

	mockDB.On("PendingUploadExistsWithRetry", mock.Anything, hash, accountID).
		Return(false, fmt.Errorf("connection refused")).Maybe()

	require.NoError(t, worker.cleanupOrphanedFiles(context.Background()))

	_, err := os.Stat(path)
	require.NoError(t, err, "staged file must survive a failed orphan lookup: an unanswered query is not evidence the message was already uploaded")
}
