package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
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
	rows, err := db.GetReadPool().Query(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1", AccountID)
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
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE id = $1 AND account_id = $2",
		scriptID, AccountID).Scan(&script.ID, &script.AccountID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetActiveScript(ctx context.Context, AccountID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND active = true", AccountID).Scan(&script.ID, &script.AccountID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrDBNotFound
		}
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetScriptByName(ctx context.Context, name string, AccountID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, name, script, active, updated_at FROM sieve_scripts WHERE name = $1 AND account_id = $2", name, AccountID).Scan(&script.ID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
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

func (db *Database) CreateScript(ctx context.Context, tx pgx.Tx, AccountID int64, name, script string) (*SieveScript, error) {
	var count int
	if err := tx.QueryRow(ctx, "SELECT COUNT(*) FROM sieve_scripts WHERE account_id = $1", AccountID).Scan(&count); err != nil {
		return nil, err
	}
	if count >= maxScriptsPerAccount {
		return nil, fmt.Errorf("maximum number of sieve scripts (%d) reached", maxScriptsPerAccount)
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

func (db *Database) UpdateScript(ctx context.Context, tx pgx.Tx, scriptID, AccountID int64, name, script string) (*SieveScript, error) {
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
//   - consts.ErrDBNotFound if no script named oldName exists for the account
//   - consts.ErrDBUniqueViolation if a script named newName already exists
//
// Because the rename is a single UPDATE, there is no read-then-write window: the
// UNIQUE (account_id, name) constraint resolves name collisions atomically.
func (db *Database) RenameScript(ctx context.Context, tx pgx.Tx, AccountID int64, oldName, newName string) error {
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
