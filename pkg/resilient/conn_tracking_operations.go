package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// --- Connection Tracker Wrappers ---

func (rd *ResilientDatabase) RegisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr, serverAddr, instanceID, email string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RegisterConnection(ctx, tx, accountID, protocol, clientAddr, serverAddr, instanceID, email)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return err
	}
	return nil
}

func (rd *ResilientDatabase) UpdateConnectionActivityWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).UpdateConnectionActivity(ctx, tx, accountID, protocol, clientAddr)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return err
	}
	return nil
}

func (rd *ResilientDatabase) UnregisterConnectionWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).UnregisterConnection(ctx, tx, accountID, protocol, clientAddr)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return err
	}
	return nil
}

func (rd *ResilientDatabase) CheckConnectionTerminationWithRetry(ctx context.Context, accountID int64, protocol, clientAddr string) (bool, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     1 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).CheckConnectionTermination(ctx, accountID, protocol, clientAddr)
	}
	result, err := rd.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

func (rd *ResilientDatabase) BatchRegisterConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).BatchRegisterConnections(ctx, tx, connections)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return err
	}
	return nil
}

func (rd *ResilientDatabase) BatchUpdateConnectionsWithRetry(ctx context.Context, connections []db.ConnectionInfo) error {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).BatchUpdateConnections(ctx, tx, connections)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return err
	}
	return nil
}

func (rd *ResilientDatabase) CleanupConnectionsByInstanceIDWithRetry(ctx context.Context, instanceID string) (int64, error) {
	config := retry.BackoffConfig{MaxRetries: 1} // No retries for cleanup
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CleanupConnectionsByInstanceID(ctx, tx, instanceID)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) GetTerminatedConnectionsByInstanceWithRetry(ctx context.Context, instanceID string) ([]db.ConnectionInfo, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetTerminatedConnectionsByInstance(ctx, instanceID)
	}
	result, err := rd.executeReadWithRetry(ctx, config, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return []db.ConnectionInfo{}, nil
	}
	return result.([]db.ConnectionInfo), nil
}
