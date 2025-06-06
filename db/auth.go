package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/migadu/sora/consts"
	"github.com/yugabyte/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// Authenticate verifies the provided address and password against the records
// in the `credentials` table. If successful, it returns the associated `account_id`.
func (db *Database) Authenticate(ctx context.Context, address string, password string) (int64, error) {
	var hashedPassword string
	var accountID int64

	normalizedAddress := strings.ToLower(strings.TrimSpace(address))
	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}
	if password == "" {
		return 0, errors.New("password cannot be empty")
	}

	err := db.Pool.QueryRow(ctx,
		"SELECT account_id, password FROM credentials WHERE address = $1",
		normalizedAddress).Scan(&accountID, &hashedPassword)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Address (identity) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		// Log other unexpected database errors
		log.Printf("error fetching credentials for address %s: %v", normalizedAddress, err)
		return 0, fmt.Errorf("database error during authentication: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		// Password does not match
		return 0, errors.New("invalid password")
	}

	// Authentication successful
	return accountID, nil
}

// GetAccountIDByAddress retrieves the main user ID associated with a given identity (address)
// by looking it up in the `credentials` table.
func (db *Database) GetAccountIDByAddress(ctx context.Context, address string) (int64, error) {
	var accountID int64
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))

	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}

	// Query the credentials table for the account_id associated with the address
	err := db.Pool.QueryRow(ctx, "SELECT account_id FROM credentials WHERE address = $1", normalizedAddress).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Identity (address) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		log.Printf("error fetching account ID for address %s: %v", normalizedAddress, err)
		return 0, fmt.Errorf("database error fetching account ID: %w", err)
	}
	return accountID, nil
}
