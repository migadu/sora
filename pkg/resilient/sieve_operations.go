package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/retry"
)

// Standard retry configurations
var sieveReadRetryConfig = retry.BackoffConfig{
	InitialInterval: 250 * time.Millisecond,
	MaxInterval:     2 * time.Second,
	Multiplier:      1.5,
	Jitter:          true,
	MaxRetries:      3,
}

var sieveWriteRetryConfig = retry.BackoffConfig{
	InitialInterval: 500 * time.Millisecond,
	MaxInterval:     5 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      2,
}

// GetUserScriptsWithRetry retrieves all Sieve scripts for a user with retry logic
func (rd *ResilientDatabase) GetUserScriptsWithRetry(ctx context.Context, userID int64) ([]*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetUserScripts(ctx, userID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.([]*db.SieveScript), nil
}

// GetScriptByNameWithRetry retrieves a specific Sieve script by name with retry logic
func (rd *ResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, userID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// CreateOrUpdateScriptWithRetry creates or updates a Sieve script with retry logic
func (rd *ResilientDatabase) CreateOrUpdateScriptWithRetry(ctx context.Context, userID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		// Check if script exists
		existing, err := rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
		if err == nil {
			// Update existing script
			return rd.getOperationalDatabaseForOperation(true).UpdateScript(ctx, tx, existing.ID, userID, name, script)
		}
		// Create new script
		return rd.getOperationalDatabaseForOperation(true).CreateScript(ctx, tx, userID, name, script)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// DeleteScriptWithRetry deletes a Sieve script with retry logic
func (rd *ResilientDatabase) DeleteScriptWithRetry(ctx context.Context, name string, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		// Get script ID
		script, err := rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
		if err != nil {
			return nil, err
		}

		// Delete script
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteScript(ctx, tx, script.ID, userID)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// ActivateScriptWithRetry activates a Sieve script (deactivates all others) with retry logic
func (rd *ResilientDatabase) ActivateScriptWithRetry(ctx context.Context, name string, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		// Get script ID
		script, err := rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
		if err != nil {
			return nil, err
		}

		// Activate script (deactivates all others automatically)
		return nil, rd.getOperationalDatabaseForOperation(true).SetScriptActive(ctx, tx, script.ID, userID, true)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// DeactivateScriptWithRetry deactivates a Sieve script with retry logic
func (rd *ResilientDatabase) DeactivateScriptWithRetry(ctx context.Context, name string, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		// Get script ID
		script, err := rd.getOperationalDatabaseForOperation(false).GetScriptByName(ctx, name, userID)
		if err != nil {
			return nil, err
		}

		// Deactivate script
		return nil, rd.getOperationalDatabaseForOperation(true).SetScriptActive(ctx, tx, script.ID, userID, false)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// UpdateScriptWithRetry updates an existing Sieve script with retry logic
func (rd *ResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, userID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).UpdateScript(ctx, tx, scriptID, userID, name, script)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// CreateScriptWithRetry creates a new Sieve script with retry logic
func (rd *ResilientDatabase) CreateScriptWithRetry(ctx context.Context, userID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).CreateScript(ctx, tx, userID, name, script)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// SetScriptActiveWithRetry sets a script's active status with retry logic
func (rd *ResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, userID int64, active bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).SetScriptActive(ctx, tx, scriptID, userID, active)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// DeleteScriptByIDWithRetry deletes a Sieve script by ID with retry logic
func (rd *ResilientDatabase) DeleteScriptByIDWithRetry(ctx context.Context, scriptID, userID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).DeleteScript(ctx, tx, scriptID, userID)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// GetActiveScriptWithRetry retrieves the currently active Sieve script for a user with retry logic
func (rd *ResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, userID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).GetActiveScript(ctx, userID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// Vacation response methods

// HasRecentVacationResponseWithRetry checks if a vacation response was sent recently with retry logic
func (rd *ResilientDatabase) HasRecentVacationResponseWithRetry(ctx context.Context, userID int64, recipient string, duration time.Duration) (bool, error) {
	op := func(ctx context.Context) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(false).HasRecentVacationResponse(ctx, userID, recipient, duration)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}

	return result.(bool), nil
}

// RecordVacationResponseWithRetry records that a vacation response was sent with retry logic
func (rd *ResilientDatabase) RecordVacationResponseWithRetry(ctx context.Context, userID int64, recipient string) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).RecordVacationResponse(ctx, tx, userID, recipient)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}
