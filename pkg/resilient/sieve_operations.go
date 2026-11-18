package resilient

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
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
	OperationName:   "db_sieve_read",
}

var sieveWriteRetryConfig = retry.BackoffConfig{
	InitialInterval: 500 * time.Millisecond,
	MaxInterval:     5 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      2,
	OperationName:   "db_sieve_write",
}

// GetUserScriptsWithRetry retrieves all Sieve scripts for a user with retry logic
func (rd *ResilientDatabase) GetUserScriptsWithRetry(ctx context.Context, AccountID int64) ([]*db.SieveScript, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetUserScripts(ctx, AccountID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.([]*db.SieveScript), nil
}

// GetScriptByNameWithRetry retrieves a specific Sieve script by name with retry logic
func (rd *ResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, AccountID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetScriptByName(ctx, name, AccountID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// CreateOrUpdateScriptWithRetry stores script as the account's script called name,
// replacing the content of an existing one or creating it (inactive); updated reports
// which. The choice is made inside the write transaction (db.CreateOrUpdateScript),
// not from a read-pool lookup, which misses a create the replica has not replayed yet
// or that another session is committing.
func (rd *ResilientDatabase) CreateOrUpdateScriptWithRetry(ctx context.Context, AccountID int64, name, script string) (stored *db.SieveScript, updated bool, err error) {
	type outcome struct {
		script  *db.SieveScript
		updated bool
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		s, updated, err := rd.getOperationalDatabaseForOperation(ctx, true).CreateOrUpdateScript(ctx, tx, AccountID, name, script)
		if err != nil {
			return nil, err
		}
		return outcome{s, updated}, nil
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, false, err
	}

	o := result.(outcome)
	return o.script, o.updated, nil
}

// DeleteScriptWithRetry deletes the account's script called name, active or not. It
// returns consts.ErrDBNotFound when the account has no such script. The name is
// resolved inside the write transaction (db.DeleteScriptByName), not on the read
// pool, which misses a script the replica has not replayed yet or returns the ID of
// one deleted and created again.
func (rd *ResilientDatabase) DeleteScriptWithRetry(ctx context.Context, name string, AccountID int64) error {
	return rd.deleteScriptByName(ctx, AccountID, name, false)
}

// DeleteInactiveScriptWithRetry deletes the account's script called name unless it
// is the active script, which it refuses with db.ErrSieveScriptActive (ManageSieve
// DELETESCRIPT, RFC 5804 section 2.10). The script is checked under the row lock its
// delete holds, so an activation committed in between cannot be missed.
func (rd *ResilientDatabase) DeleteInactiveScriptWithRetry(ctx context.Context, name string, AccountID int64) error {
	return rd.deleteScriptByName(ctx, AccountID, name, true)
}

func (rd *ResilientDatabase) deleteScriptByName(ctx context.Context, AccountID int64, name string, keepActive bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).DeleteScriptByName(ctx, tx, AccountID, name, keepActive)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// ActivateScriptWithRetry activates the account's script called name (deactivating
// all others). It returns consts.ErrDBNotFound when the account has no such script.
// The name is resolved inside the write transaction (db.SetScriptActiveByName).
func (rd *ResilientDatabase) ActivateScriptWithRetry(ctx context.Context, name string, AccountID int64) error {
	return rd.setScriptActiveByName(ctx, AccountID, name, true)
}

// DeactivateScriptWithRetry deactivates the account's script called name. It returns
// consts.ErrDBNotFound when the account has no such script. The name is resolved
// inside the write transaction (db.SetScriptActiveByName).
func (rd *ResilientDatabase) DeactivateScriptWithRetry(ctx context.Context, name string, AccountID int64) error {
	return rd.setScriptActiveByName(ctx, AccountID, name, false)
}

func (rd *ResilientDatabase) setScriptActiveByName(ctx context.Context, AccountID int64, name string, active bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).SetScriptActiveByName(ctx, tx, AccountID, name, active)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// UpdateScriptWithRetry updates an existing Sieve script with retry logic
func (rd *ResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, AccountID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).UpdateScript(ctx, tx, scriptID, AccountID, name, script)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// CreateScriptWithRetry creates a new Sieve script with retry logic
func (rd *ResilientDatabase) CreateScriptWithRetry(ctx context.Context, AccountID int64, name, script string) (*db.SieveScript, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).CreateScript(ctx, tx, AccountID, name, script)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// SetScriptActiveWithRetry sets a script's active status with retry logic. It returns
// consts.ErrDBNotFound, changing nothing, when the account has no script with that ID.
func (rd *ResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, AccountID int64, active bool) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).SetScriptActive(ctx, tx, scriptID, AccountID, active)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// DeleteScriptByIDWithRetry deletes a Sieve script by ID with retry logic
func (rd *ResilientDatabase) DeleteScriptByIDWithRetry(ctx context.Context, scriptID, AccountID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).DeleteScript(ctx, tx, scriptID, AccountID)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// GetActiveScriptWithRetry retrieves the currently active Sieve script for a user with retry logic
func (rd *ResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, AccountID int64) (*db.SieveScript, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetActiveScript(ctx, AccountID)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.SieveScript), nil
}

// DeactivateAllScriptsWithRetry deactivates all Sieve scripts for an account with retry logic
func (rd *ResilientDatabase) DeactivateAllScriptsWithRetry(ctx context.Context, AccountID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).DeactivateAllScripts(ctx, tx, AccountID)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// RenameScriptWithRetry renames a Sieve script with retry logic. The rename is a
// single atomic UPDATE, so there is no read-then-write window: the script's active
// state is preserved and the UNIQUE (account_id, name) constraint resolves name
// collisions. It returns consts.ErrDBNotFound if oldName does not exist,
// consts.ErrDBUniqueViolation if newName already exists, or
// db.ErrSieveScriptNotStorable if newName contains NUL or invalid UTF-8.
func (rd *ResilientDatabase) RenameScriptWithRetry(ctx context.Context, AccountID int64, oldName, newName string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).RenameScript(ctx, tx, AccountID, oldName, newName)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op, consts.ErrDBNotFound, consts.ErrDBUniqueViolation, db.ErrSieveScriptNotStorable)
	return err
}

// Vacation response methods

// HasRecentVacationResponseWithRetry checks if a vacation response was sent recently with retry logic
func (rd *ResilientDatabase) HasRecentVacationResponseWithRetry(ctx context.Context, AccountID int64, recipient, responseIdentity string, duration time.Duration) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).HasRecentVacationResponse(ctx, AccountID, recipient, responseIdentity, duration)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}

	return result.(bool), nil
}

// ClaimVacationResponseWithRetry atomically consumes the sender/response period
// on the write pool. A failed COMMIT is not retried by the shared transaction
// wrapper: an ambiguous claim must fail closed rather than authorize a reply.
func (rd *ResilientDatabase) ClaimVacationResponseWithRetry(ctx context.Context, accountID int64, sender, responseIdentity string, duration time.Duration) (bool, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).ClaimVacationResponse(ctx, tx, accountID, sender, responseIdentity, duration)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// Redirect rate limit methods

// CountRedirectsSinceWithRetry returns the number of redirects performed by the given account within the specified duration window with retry logic
func (rd *ResilientDatabase) CountRedirectsSinceWithRetry(ctx context.Context, AccountID int64, duration time.Duration) (int, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).CountRedirectsSince(ctx, AccountID, duration)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return 0, err
	}

	return result.(int), nil
}

// RecordRedirectWithRetry records that a redirect action was performed, charged against a
// redirect rate limit of the given window and limit, with retry logic
func (rd *ResilientDatabase) RecordRedirectWithRetry(ctx context.Context, AccountID int64, window time.Duration, limit int) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).RecordRedirect(ctx, tx, AccountID, window, limit)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}

// RedirectRateWindowsOtherThanWithRetry returns the redirect rate windows other than windows
// that running redirect_log rows were charged under, with retry logic
func (rd *ResilientDatabase) RedirectRateWindowsOtherThanWithRetry(ctx context.Context, windows []time.Duration) ([]time.Duration, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).RedirectRateWindowsOtherThan(ctx, windows)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.([]time.Duration), nil
}

// RedirectRateLimitsOtherThanWithRetry returns the redirect rate limits other than limits
// that running redirect_log rows were charged under, with retry logic
func (rd *ResilientDatabase) RedirectRateLimitsOtherThanWithRetry(ctx context.Context, limits []int) ([]int, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).RedirectRateLimitsOtherThan(ctx, limits)
	}

	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}

	return result.([]int), nil
}

// RedirectedTargetsWithRetry returns the redirect targets already queued for the
// account's delivery of the message identified by deliveryHash, read from the primary.
func (rd *ResilientDatabase) RedirectedTargetsWithRetry(ctx context.Context, accountID int64, deliveryHash string) ([]string, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).RedirectedTargets(ctx, accountID, deliveryHash)
	}
	result, err := rd.executeReadWithRetry(ctx, sieveReadRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]string), nil
}

// RecordRedirectDeliveryWithRetry records that the account's delivery of the message
// identified by deliveryHash has queued its redirect to redirectTo.
func (rd *ResilientDatabase) RecordRedirectDeliveryWithRetry(ctx context.Context, accountID int64, deliveryHash, redirectTo string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).RecordRedirectDelivery(ctx, tx, accountID, deliveryHash, redirectTo)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, sieveWriteRetryConfig, timeoutWrite, op)
	return err
}
