package resilient

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Sieve and Vacation Wrappers ---

func (rd *ResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, userID int64) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var script *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetActiveScript(readCtx, userID)
		})
		if cbErr != nil {
			if errors.Is(cbErr, consts.ErrDBNotFound) {
				return retry.Stop(cbErr)
			}
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			script = result.(*db.SieveScript)
		}
		return nil
	}, config)
	return script, err
}

func (rd *ResilientDatabase) HasRecentVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string, duration time.Duration) (bool, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var hasRecent bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).HasRecentVacationResponse(readCtx, userID, senderAddress, duration)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		hasRecent = result.(bool)
		return nil
	}, config)
	return hasRecent, err
}

func (rd *ResilientDatabase) RecordVacationResponseWithRetry(ctx context.Context, userID int64, senderAddress string) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabaseForOperation(true).RecordVacationResponse(writeCtx, tx, userID, senderAddress)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return nil
	}, config)
}

// --- Sieve Script Management Wrappers ---

func (rd *ResilientDatabase) GetUserScriptsWithRetry(ctx context.Context, userID int64) ([]*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var scripts []*db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetUserScripts(readCtx, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		scripts = result.([]*db.SieveScript)
		return nil
	}, config)
	return scripts, err
}

func (rd *ResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, userID int64) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 3}
	var script *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetScriptByName(readCtx, name, userID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		if result != nil {
			script = result.(*db.SieveScript)
		}
		return nil
	}, config)
	return script, err
}

func (rd *ResilientDatabase) CreateScriptWithRetry(ctx context.Context, userID int64, name, script string) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var createdScript *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).CreateScript(writeCtx, tx, userID, name, script)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		if result != nil {
			createdScript = result.(*db.SieveScript)
		}
		return nil
	}, config)
	return createdScript, err
}

func (rd *ResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, userID int64, name, script string) (*db.SieveScript, error) {
	config := retry.BackoffConfig{MaxRetries: 2}
	var updatedScript *db.SieveScript
	err := retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(true).UpdateScript(writeCtx, tx, scriptID, userID, name, script)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		if result != nil {
			updatedScript = result.(*db.SieveScript)
		}
		return nil
	}, config)
	return updatedScript, err
}

func (rd *ResilientDatabase) DeleteScriptWithRetry(ctx context.Context, scriptID, userID int64) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			return nil, rd.getOperationalDatabaseForOperation(true).DeleteScript(writeCtx, tx, scriptID, userID)
		})
		if cbErr != nil && !rd.isRetryableError(cbErr) {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		return cbErr
	}, config)
}

func (rd *ResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, userID int64, active bool) error {
	config := retry.BackoffConfig{MaxRetries: 2}
	return retry.WithRetryAdvanced(ctx, func() error {
		tx, err := rd.BeginTxWithRetry(ctx, pgx.TxOptions{})
		if err != nil {
			if rd.isRetryableError(err) {
				return err
			}
			return retry.Stop(err)
		}
		defer tx.Rollback(ctx)

		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		_, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			// Assuming db.SetScriptActive is refactored to accept a transaction.
			return nil, rd.getOperationalDatabaseForOperation(true).SetScriptActive(writeCtx, tx, scriptID, userID, active)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}

		return tx.Commit(ctx)
	}, config)
}
