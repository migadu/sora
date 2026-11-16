package resilient

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// Results leave these wrappers only after a successful commit. A rolled-back
// retry or ambiguous failure must not suppress anything in a client's snapshot.
func (rd *ResilientDatabase) CreateMailboxReturningStateWithRetry(ctx context.Context, ownerID, viewerID int64, name string, parentID *int64, specialUse string) (*db.CreatedMailbox, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CreateMailboxReturningState(ctx, tx, ownerID, viewerID, name, parentID, specialUse)
	}
	r, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrDBUniqueViolation, consts.ErrMailboxInvalidName, consts.ErrMailboxSpecialUseInUse)
	if err != nil {
		return nil, err
	}
	return r.(*db.CreatedMailbox), nil
}

func (rd *ResilientDatabase) RenameMailboxReturningNamesWithRetry(ctx context.Context, id, ownerID, viewerID int64, name string, parentID *int64) ([]db.MailboxNameMutation, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RenameMailboxReturningNames(ctx, tx, id, ownerID, viewerID, name, parentID)
	}
	r, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrMailboxAlreadyExists, consts.ErrMailboxInvalidName)
	if err != nil {
		return nil, err
	}
	return r.([]db.MailboxNameMutation), nil
}

func (rd *ResilientDatabase) UpdateSubscriptionReturningStateWithRetry(ctx context.Context, actorID int64, name string, subscribe bool) (db.SubscriptionMutation, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).UpdateSubscriptionReturningState(ctx, tx, actorID, name, subscribe)
	}
	r, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	if err != nil {
		return db.SubscriptionMutation{}, err
	}
	return r.(db.SubscriptionMutation), nil
}

// A concurrently created parent is resolved but never attributed to this caller.
// Return already committed creations on a later error too: the old helper used
// one transaction per level, so a failing command may still have made parents.
func (rd *ResilientDatabase) ResolveOrCreateMailboxPathReturningStatesWithRetry(ctx context.Context, ownerID, viewerID int64, name string) (*int64, []db.CreatedMailbox, error) {
	ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	parts := strings.Split(name, string(consts.MailboxDelimiter))
	var parentID *int64
	var created []db.CreatedMailbox
	for i := 1; i <= len(parts); i++ {
		path := strings.Join(parts[:i], string(consts.MailboxDelimiter))
		id, err := rd.GetOwnedMailboxIDByNameWithRetry(ctx, ownerID, path)
		if errors.Is(err, consts.ErrMailboxNotFound) {
			state, createErr := rd.CreateMailboxReturningStateWithRetry(ctx, ownerID, viewerID, path, parentID, "")
			if createErr == nil {
				created = append(created, *state)
				id = state.ID
				err = nil
			} else if errors.Is(createErr, consts.ErrDBUniqueViolation) {
				id, err = rd.GetOwnedMailboxIDByNameWithRetry(ctx, ownerID, path)
			} else {
				return nil, created, fmt.Errorf("create parent mailbox %q: %w", path, createErr)
			}
		}
		if err != nil {
			return nil, created, fmt.Errorf("resolve parent mailbox %q: %w", path, err)
		}
		parentID = &id
	}
	return parentID, created, nil
}
