package resilient

import (
	"context"

	"github.com/migadu/sora/db"
)

// RestoreMessagesChunkedForTest exposes the chunked restore with an explicit chunk size so
// tests can force chunk boundaries with a handful of messages.
func (rd *ResilientDatabase) RestoreMessagesChunkedForTest(ctx context.Context, params db.RestoreMessagesParams, chunkSize int) (int64, error) {
	return rd.restoreMessagesChunked(ctx, params, chunkSize)
}

// PurgeMailboxChunkedForTest exposes the chunked hard delete with a caller-chosen batch
// size, so a test can force several steps without seeding thousands of messages.
func (rd *ResilientDatabase) PurgeMailboxChunkedForTest(ctx context.Context, mailboxID, accountID int64, batchSize int) error {
	return rd.purgeMailboxChunked(ctx, mailboxID, accountID, batchSize)
}
