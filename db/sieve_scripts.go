package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
)

type SieveScript struct {
	ID        int64
	AccountID int64
	Name      string
	Script    string
	Active    bool
	UpdatedAt time.Time
}

func (db *Database) GetUserScripts(ctx context.Context, AccountID int64) ([]*SieveScript, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1", AccountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scripts []*SieveScript
	for rows.Next() {
		var script SieveScript
		if err := rows.Scan(&script.ID, &script.AccountID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt); err != nil {
			return nil, err
		}
		scripts = append(scripts, &script)
	}

	return scripts, rows.Err()
}

func (db *Database) GetScript(ctx context.Context, scriptID, AccountID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE id = $1 AND account_id = $2",
		scriptID, AccountID).Scan(&script.ID, &script.AccountID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetActiveScript(ctx context.Context, AccountID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND active = true", AccountID).Scan(&script.ID, &script.AccountID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrDBNotFound
		}
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetScriptByName(ctx context.Context, name string, AccountID int64) (*SieveScript, error) {
	// A name PostgreSQL cannot hold (a NUL, invalid UTF-8) names no script, as in
	// GetMailboxByName. Querying with it fails with SQLSTATE 22021, which callers took
	// for a database failure: ManageSieve answered NO (TRYLATER), the User API 500.
	if !helpers.TextStorable(name) {
		return nil, consts.ErrDBNotFound
	}
	var script SieveScript
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, "SELECT id, name, script, active, updated_at FROM sieve_scripts WHERE name = $1 AND account_id = $2", name, AccountID).Scan(&script.ID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrDBNotFound
		}
		return nil, err
	}
	script.AccountID = AccountID

	return &script, nil
}

// maxScriptsPerAccount caps how many Sieve scripts one account may create, preventing
// an authenticated user from exhausting shared PostgreSQL storage by looping
// PUTSCRIPT/PUT with distinct names. Updates to existing scripts are unaffected.
const maxScriptsPerAccount = 100

// MaxScriptsPerAccount returns the per-account Sieve script limit enforced by
// CreateScript, so callers (e.g. ManageSieve HAVESPACE) can report it without
// attempting a create.
func MaxScriptsPerAccount() int { return maxScriptsPerAccount }

// ErrSieveScriptLimitReached is returned by CreateScript, and by CreateOrUpdateScript
// for a new name, when the account already has maxScriptsPerAccount scripts. It is a
// permanent condition (not transient), so callers can map it to a permanent protocol
// error rather than a retryable one.
var ErrSieveScriptLimitReached = errors.New("maximum number of sieve scripts reached")

// ErrSieveScriptNotStorable is returned by CreateScript, UpdateScript,
// CreateOrUpdateScript and RenameScript when a stored script name or content contains
// a NUL byte or invalid UTF-8, which PostgreSQL text columns reject with SQLSTATE 22021.
var ErrSieveScriptNotStorable = errors.New("sieve script contains NUL or invalid UTF-8")

// lockScriptCreates serialises the account's script creates and name changes for the
// rest of tx. The limit is checked against the stored count and then inserted, so two
// creates of the account must not both read the old count: each would pass, and
// together they would store past the limit. Renames (RenameScript, UpdateScript) take
// the same lock so CreateOrUpdateScript sees any in-flight rename into its target name
// before checking the limit. The lock is transaction-scoped (pgbouncer transaction
// mode), and statements run after it is granted take a new snapshot under READ
// COMMITTED, so they see what the previous holder committed.
func lockScriptCreates(ctx context.Context, tx pgx.Tx, AccountID int64) error {
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1::int4, hashint8($2::int8))",
		consts.SoraSieveScriptLimitLockClassID, AccountID); err != nil {
		return fmt.Errorf("failed to lock account sieve scripts: %w", err)
	}
	return nil
}

// checkScriptLimit refuses a create when the account already has
// maxScriptsPerAccount scripts. The caller holds lockScriptCreates.
func checkScriptLimit(ctx context.Context, tx pgx.Tx, AccountID int64) error {
	var count int
	if err := tx.QueryRow(ctx, "SELECT COUNT(*) FROM sieve_scripts WHERE account_id = $1", AccountID).Scan(&count); err != nil {
		return err
	}
	if count >= maxScriptsPerAccount {
		return fmt.Errorf("%w (limit %d)", ErrSieveScriptLimitReached, maxScriptsPerAccount)
	}
	return nil
}

func (db *Database) CreateScript(ctx context.Context, tx pgx.Tx, AccountID int64, name, script string) (*SieveScript, error) {
	if !helpers.TextStorable(name) || !helpers.TextStorable(script) {
		return nil, ErrSieveScriptNotStorable
	}
	if err := lockScriptCreates(ctx, tx, AccountID); err != nil {
		return nil, err
	}
	if err := checkScriptLimit(ctx, tx, AccountID); err != nil {
		return nil, err
	}

	var s SieveScript
	err := tx.QueryRow(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active)
		VALUES ($1, $2, $3, false) 
		RETURNING id, account_id, name, script, active, updated_at
	`, AccountID, name, script).Scan(&s.ID, &s.AccountID, &s.Name, &s.Script, &s.Active, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateOrUpdateScript stores script as the account's script called name: it
// replaces the content of the script of that name, keeping its active state, or
// creates the script, inactive, when the account has none. updated reports which.
//
// The choice is made in tx after lockScriptCreates, which CreateScript, UpdateScript
// and RenameScript also take, so it sees every create or rename into the name
// committed before it. A lookup outside tx (on a read replica that has not replayed a
// recent write, or racing another session's write) misses such a script, and the
// create that follows fails on UNIQUE (account_id, name) or checkScriptLimit.
func (db *Database) CreateOrUpdateScript(ctx context.Context, tx pgx.Tx, AccountID int64, name, script string) (s *SieveScript, updated bool, err error) {
	if !helpers.TextStorable(name) || !helpers.TextStorable(script) {
		return nil, false, ErrSieveScriptNotStorable
	}
	if err := lockScriptCreates(ctx, tx, AccountID); err != nil {
		return nil, false, err
	}
	for {
		if s, err := updateScriptByName(ctx, tx, AccountID, name, script); !errors.Is(err, pgx.ErrNoRows) {
			return s, err == nil, err
		}
		// Replacing a script adds none, so only the create is held to the limit.
		if err := checkScriptLimit(ctx, tx, AccountID); err != nil {
			return nil, false, err
		}

		s = &SieveScript{}
		err = tx.QueryRow(ctx, `
			INSERT INTO sieve_scripts (account_id, name, script, active)
			VALUES ($1, $2, $3, false)
			ON CONFLICT (account_id, name) DO NOTHING
			RETURNING id, account_id, name, script, active, updated_at
		`, AccountID, name, script).Scan(&s.ID, &s.AccountID, &s.Name, &s.Script, &s.Active, &s.UpdatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			// An unserialised write put this name in place after updateScriptByName
			// looked; loop to replace it (or re-check and insert if it disappeared).
			continue
		}
		if err != nil {
			return nil, false, err
		}
		return s, false, nil
	}
}

// updateScriptByName replaces the content of the account's script called name.
// It returns pgx.ErrNoRows when the account has no such script.
func updateScriptByName(ctx context.Context, tx pgx.Tx, AccountID int64, name, script string) (*SieveScript, error) {
	var s SieveScript
	err := tx.QueryRow(ctx, `
		UPDATE sieve_scripts SET script = $1, updated_at = now()
		WHERE account_id = $2 AND name = $3
		RETURNING id, account_id, name, script, active, updated_at
	`, script, AccountID, name).Scan(&s.ID, &s.AccountID, &s.Name, &s.Script, &s.Active, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (db *Database) UpdateScript(ctx context.Context, tx pgx.Tx, scriptID, AccountID int64, name, script string) (*SieveScript, error) {
	if !helpers.TextStorable(name) || !helpers.TextStorable(script) {
		return nil, ErrSieveScriptNotStorable
	}
	if err := lockScriptCreates(ctx, tx, AccountID); err != nil {
		return nil, err
	}
	var s SieveScript
	err := tx.QueryRow(ctx, `
		UPDATE sieve_scripts SET name = $1, script = $2, updated_at = now() 
		WHERE id = $3 AND account_id = $4
		RETURNING id, account_id, name, script, active, updated_at
	`, name, script, scriptID, AccountID).Scan(&s.ID, &s.AccountID, &s.Name, &s.Script, &s.Active, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// RenameScript renames a Sieve script in a single atomic statement. The script's
// active state and content are preserved (only the name changes). It returns:
//   - ErrSieveScriptNotStorable if newName contains a NUL byte or invalid UTF-8
//   - consts.ErrDBNotFound if no script named oldName exists for the account
//   - consts.ErrDBUniqueViolation if a script named newName already exists
//
// Because the rename is a single UPDATE under lockScriptCreates, there is no
// read-then-write window and a concurrent CreateOrUpdateScript at maxScriptsPerAccount
// sees the renamed script instead of failing checkScriptLimit.
func (db *Database) RenameScript(ctx context.Context, tx pgx.Tx, AccountID int64, oldName, newName string) error {
	if !helpers.TextStorable(newName) {
		return ErrSieveScriptNotStorable
	}
	if !helpers.TextStorable(oldName) { // names no script, see GetScriptByName
		return consts.ErrDBNotFound
	}
	if err := lockScriptCreates(ctx, tx, AccountID); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE sieve_scripts SET name = $1, updated_at = now()
		WHERE name = $2 AND account_id = $3
	`, newName, oldName, AccountID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return consts.ErrDBUniqueViolation
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return consts.ErrDBNotFound
	}
	return nil
}

func (db *Database) DeleteScript(ctx context.Context, tx pgx.Tx, scriptID, AccountID int64) error {
	_, err := tx.Exec(ctx, "DELETE FROM sieve_scripts WHERE id = $1 AND account_id = $2", scriptID, AccountID)
	return err
}

func (db *Database) SetScriptActive(ctx context.Context, tx pgx.Tx, scriptID, AccountID int64, active bool) error {
	// If we are activating a script, we must first deactivate all other scripts for this user
	// to ensure the UNIQUE index on (account_id, active=true) is not violated.
	if active {
		_, err := tx.Exec(ctx, "UPDATE sieve_scripts SET active = false WHERE account_id = $1 AND active = true", AccountID)
		if err != nil {
			return fmt.Errorf("failed to deactivate other scripts: %w", err)
		}
	}

	// Now, set the active status for the target script.
	_, err := tx.Exec(ctx, "UPDATE sieve_scripts SET active = $1, updated_at = now() WHERE id = $2 AND account_id = $3", active, scriptID, AccountID)
	return err
}

func (db *Database) DeactivateAllScripts(ctx context.Context, tx pgx.Tx, AccountID int64) error {
	// Deactivate all scripts for this account
	_, err := tx.Exec(ctx, "UPDATE sieve_scripts SET active = false, updated_at = now() WHERE account_id = $1 AND active = true", AccountID)
	return err
}
