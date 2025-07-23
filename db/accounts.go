package db

import (
	"context"
	"fmt"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/server"
)

// CreateAccountRequest represents the parameters for creating a new account
type CreateAccountRequest struct {
	Email     string
	Password  string
	IsPrimary bool
	HashType  string
}

// CreateAccount creates a new account with the specified email and password
func (db *Database) CreateAccount(ctx context.Context, req CreateAccountRequest) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(req.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	if req.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Check if account already exists
	_, err = db.GetAccountIDByAddress(ctx, normalizedEmail)
	if err == nil {
		return fmt.Errorf("account with email %s already exists", normalizedEmail)
	}
	if err != consts.ErrUserNotFound {
		return fmt.Errorf("error checking existing account: %w", err)
	}

	// Generate password hash
	var hashedPassword string
	switch req.HashType {
	case "ssha512":
		hashedPassword, err = GenerateSSHA512Hash(req.Password)
		if err != nil {
			return fmt.Errorf("failed to generate SSHA512 hash: %w", err)
		}
	case "sha512":
		hashedPassword = GenerateSHA512Hash(req.Password)
	case "bcrypt":
		hashedPassword, err = GenerateBcryptHash(req.Password)
		if err != nil {
			return fmt.Errorf("failed to generate bcrypt hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported hash type: %s", req.HashType)
	}

	// Begin transaction
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Create account
	var accountID int64
	err = tx.QueryRow(ctx, "INSERT INTO accounts (created_at) VALUES (now()) RETURNING id").Scan(&accountID)
	if err != nil {
		return fmt.Errorf("failed to create account: %w", err)
	}

	// Create credential
	_, err = tx.Exec(ctx,
		"INSERT INTO credentials (account_id, address, password, primary_identity, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())",
		accountID, normalizedEmail, hashedPassword, req.IsPrimary)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// UpdateAccountRequest represents the parameters for updating an account
type UpdateAccountRequest struct {
	Email    string
	Password string
	HashType string
}

// UpdateAccount updates an existing account's password
func (db *Database) UpdateAccount(ctx context.Context, req UpdateAccountRequest) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(req.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	if req.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Check if account exists
	accountID, err := db.GetAccountIDByAddress(ctx, normalizedEmail)
	if err != nil {
		if err == consts.ErrUserNotFound {
			return fmt.Errorf("account with email %s does not exist", normalizedEmail)
		}
		return fmt.Errorf("error checking account: %w", err)
	}

	// Generate password hash
	var hashedPassword string
	switch req.HashType {
	case "ssha512":
		hashedPassword, err = GenerateSSHA512Hash(req.Password)
		if err != nil {
			return fmt.Errorf("failed to generate SSHA512 hash: %w", err)
		}
	case "sha512":
		hashedPassword = GenerateSHA512Hash(req.Password)
	case "bcrypt":
		hashedPassword, err = GenerateBcryptHash(req.Password)
		if err != nil {
			return fmt.Errorf("failed to generate bcrypt hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported hash type: %s", req.HashType)
	}

	// Update password
	_, err = db.Pool.Exec(ctx,
		"UPDATE credentials SET password = $1, updated_at = now() WHERE account_id = $2 AND address = $3",
		hashedPassword, accountID, normalizedEmail)
	if err != nil {
		return fmt.Errorf("failed to update account password: %w", err)
	}

	return nil
}

// AccountExists checks if an account with the given email exists
func (db *Database) AccountExists(ctx context.Context, email string) (bool, error) {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return false, fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	_, err = db.GetAccountIDByAddress(ctx, normalizedEmail)
	if err == nil {
		return true, nil
	}
	if err == consts.ErrUserNotFound {
		return false, nil
	}
	return false, err
}
