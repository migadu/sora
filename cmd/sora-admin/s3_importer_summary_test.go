package main

import (
	"testing"
	"time"
)

// TestS3ImporterSummaryFailsOnFailedObjects: S3Importer.Run ends with printSummary,
// whose result is the command's outcome, so `import s3` must exit non-zero when an
// object failed, as `import maildir` does.
func TestS3ImporterSummaryFailsOnFailedObjects(t *testing.T) {
	si := &S3Importer{startTime: time.Now(), totalObjects: 3, processedObjects: 3, importedMessages: 2}
	if err := si.printSummary(); err != nil {
		t.Fatalf("summary of a run without failures: %v", err)
	}

	si.importedMessages, si.failedMessages = 1, 2
	if err := si.printSummary(); err == nil {
		t.Error("summary of a run with 2 failed objects returned nil, so import s3 exits 0")
	}
}
