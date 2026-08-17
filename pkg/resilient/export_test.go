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
