package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// GetLastServerAddress retrieves the last server address a user connected to
func (db *Database) GetLastServerAddress(ctx context.Context, accountID int64) (string, time.Time, error) {
	var lastServer sql.NullString
	var lastTime sql.NullTime

	// Assuming is_prelookup_account = false for standard user accounts
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT last_server_addr, last_server_time 
		FROM server_affinity 
		WHERE account_id = $1 AND is_prelookup_account = false
	`, accountID).Scan(&lastServer, &lastTime)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "", time.Time{}, consts.ErrNoServerAffinity // Use the constant from the consts package
		}
		return "", time.Time{}, err
	}

	if !lastServer.Valid {
		return "", time.Time{}, nil
	}

	return lastServer.String, lastTime.Time, nil
}

// UpdateLastServerAddress updates the last server address a user connected to
func (db *Database) UpdateLastServerAddress(ctx context.Context, accountID int64, serverAddr string) error {
	// Use INSERT ON CONFLICT to handle both new and existing affinity records.
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO server_affinity (account_id, is_prelookup_account, last_server_addr, last_server_time)
		VALUES ($1, false, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (account_id, is_prelookup_account) DO UPDATE SET
			last_server_addr = EXCLUDED.last_server_addr,
			last_server_time = EXCLUDED.last_server_time
	`, accountID, serverAddr)
	return err
}
