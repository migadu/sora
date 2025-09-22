package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// --- Sieve and Vacation Wrappers ---

func (rd *ResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, userID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetActiveScript(ctx, userID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrDBNotFound)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.SieveScript), nil
}

func (rd *ResilientDatabase) HasRecentVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string, duration time.Duration) (bool, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).HasRecentVacationResponse(ctx, userID, senderAddress, duration)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) RecordVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RecordVacationResponse(ctx, tx, userID, senderAddress)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}

// --- Sieve Script Management Wrappers ---

func (rd *ResilientDatabase) GetUserScriptsWithRetry(ctx context.Context, userID int64) ([]*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUserScripts(ctx, userID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []*db.SieveScript{}, nil
	}
	return result.([]*db.SieveScript), nil
}

func (rd *ResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, userID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op, consts.ErrDBNotFound)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.SieveScript), nil
}

func (rd *ResilientDatabase) CreateScriptWithRetry(ctx context.Context, userID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CreateScript(ctx, tx, userID, name, script)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrDBUniqueViolation)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.SieveScript), nil
}

func (rd *ResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, userID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).UpdateScript(ctx, tx, scriptID, userID, name, script)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrDBUniqueViolation)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*db.SieveScript), nil
}

func (rd *ResilientDatabase) DeleteScriptWithRetry(ctx context.Context, scriptID, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteScript(ctx, tx, scriptID, userID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, userID int64, active bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).SetScriptActive(ctx, tx, scriptID, userID, active)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, writeRetryConfig, timeoutWrite, op, consts.ErrDBUniqueViolation)
	return err
}
