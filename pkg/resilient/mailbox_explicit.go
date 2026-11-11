package resilient

import (
	"context"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// GetMailboxByNameForRightWithRetry resolves an explicit mailbox operation that
// may use its required ACL right without the lookup right. The caller must still
// check authorization on the returned normal namespace winner.
func (rd *ResilientDatabase) GetMailboxByNameForRightWithRetry(ctx context.Context, accountID int64, name string, right db.ACLRight) (*db.DBMailbox, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMailboxByNameForRight(ctx, accountID, name, right)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrMailboxNotFound)
	if err != nil {
		return nil, err
	}
	return result.(*db.DBMailbox), nil
}
