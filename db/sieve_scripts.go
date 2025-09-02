package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

type SieveScript struct {
	ID        int64
	UserID    int64
	Name      string
	Script    string
	Active    bool
	UpdatedAt time.Time
}

func (db *Database) GetUserScripts(ctx context.Context, userID int64) ([]*SieveScript, error) {
	rows, err := db.GetReadPool().Query(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scripts []*SieveScript
	for rows.Next() {
		var script SieveScript
		if err := rows.Scan(&script.ID, &script.UserID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt); err != nil {
			return nil, err
		}
		scripts = append(scripts, &script)
	}

	return scripts, nil
}

func (db *Database) GetScript(ctx context.Context, scriptID, userID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE id = $1 AND account_id = $2",
		scriptID, userID).Scan(&script.ID, &script.UserID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetActiveScript(ctx context.Context, userID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, account_id, name, script, active, updated_at FROM sieve_scripts WHERE account_id = $1 AND active = true", userID).Scan(&script.ID, &script.UserID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrDBNotFound
		}
		return nil, err
	}

	return &script, nil
}

func (db *Database) GetScriptByName(ctx context.Context, name string, userID int64) (*SieveScript, error) {
	var script SieveScript
	err := db.GetReadPool().QueryRow(ctx, "SELECT id, name, script, active, updated_at FROM sieve_scripts WHERE name = $1 AND account_id = $2", name, userID).Scan(&script.ID, &script.Name, &script.Script, &script.Active, &script.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, consts.ErrDBNotFound
		}
		return nil, err
	}
	script.UserID = userID

	return &script, nil
}

func (db *Database) CreateScript(ctx context.Context, userID int64, name, script string) (*SieveScript, error) {
	var scriptID int64
	err := db.GetWritePool().QueryRow(ctx, "INSERT INTO sieve_scripts (account_id, name, script) VALUES ($1, $2, $3) RETURNING id", userID, name, script).Scan(&scriptID)
	if err != nil {
		return nil, err
	}

	return db.GetScript(ctx, scriptID, userID)
}

func (db *Database) UpdateScript(ctx context.Context, scriptID, userID int64, name, script string) (*SieveScript, error) {
	_, err := db.GetWritePool().Exec(ctx, "UPDATE sieve_scripts SET name = $1, script = $2 WHERE id = $3", name, script, scriptID)
	if err != nil {
		return nil, err
	}

	return db.GetScript(ctx, scriptID, userID)
}

func (db *Database) DeleteScript(ctx context.Context, scriptID, userID int64) error {
	_, err := db.GetWritePool().Exec(ctx, "DELETE FROM sieve_scripts WHERE id = $1 AND account_id = $2", scriptID, userID)
	return err
}

func (db *Database) SetScriptActive(ctx context.Context, scriptID, userID int64, active bool) error {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, "UPDATE sieve_scripts SET active = false WHERE id != $1 AND account_id = $2", scriptID, userID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, "UPDATE sieve_scripts SET active = true WHERE id = $1 AND account_id = $2", scriptID, userID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}
