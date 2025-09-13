package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Connection Tracker Wrappers ---

func (rd *ResilientDatabase) RegisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr, instanceID string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).RegisterConnection(writeCtx, tx, accountID, protocol, clientAddr, serverAddr, instanceID)
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

func (rd *ResilientDatabase) UpdateConnectionActivityWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).UpdateConnectionActivity(writeCtx, tx, accountID, protocol, clientAddr)
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

func (rd *ResilientDatabase) UnregisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).UnregisterConnection(writeCtx, tx, accountID, protocol, clientAddr)
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

func (rd *ResilientDatabase) CheckConnectionTerminationWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) (bool, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	var shouldTerminate bool
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).CheckConnectionTermination(readCtx, accountID, protocol, clientAddr)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		shouldTerminate = result.(bool)
		return nil
	}, config)
	return shouldTerminate, err
}

func (rd *ResilientDatabase) BatchRegisterConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).BatchRegisterConnections(writeCtx, tx, connections)
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

func (rd *ResilientDatabase) BatchUpdateConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
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
			return nil, rd.getOperationalDatabaseForOperation(true).BatchUpdateConnections(writeCtx, tx, connections)
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

func (rd *ResilientDatabase) CleanupConnectionsByInstanceIDWithRetry(ctx context.Context, instanceID string) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 1} // No retries for cleanup
	var count int64
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
			return rd.getOperationalDatabaseForOperation(true).CleanupConnectionsByInstanceID(writeCtx, tx, instanceID)
		})
		if cbErr != nil {
			return retry.Stop(cbErr)
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}

		count = result.(int64)
		return nil
	}, config)
	return count, err
}

func (rd *ResilientDatabase) GetTerminatedConnectionsByInstanceWithRetry(ctx context.Context, instanceID string) ([]db.ConnectionInfo, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
	var connections []db.ConnectionInfo
	err := retry.WithRetryAdvanced(ctx, func() error {
		readCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			return rd.getOperationalDatabaseForOperation(false).GetTerminatedConnectionsByInstance(readCtx, instanceID)
		})
		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			return cbErr
		}
		connections = result.([]db.ConnectionInfo)
		return nil
	}, config)
	return connections, err
}
