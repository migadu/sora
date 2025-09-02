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
	tx, err := db.GetWritePool().Begin(ctx)
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

// AddCredentialRequest represents the parameters for adding a credential to an existing account
type AddCredentialRequest struct {
	PrimaryIdentity string // The primary identity to identify the account
	NewEmail        string // The new email address to add
	Password        string
	IsPrimary       bool // Whether to make this the new primary identity
	HashType        string
}

// AddCredential adds a new credential to an existing account identified by its primary identity
func (db *Database) AddCredential(ctx context.Context, req AddCredentialRequest) error {
	// Validate primary identity email address format
	primaryAddress, err := server.NewAddress(req.PrimaryIdentity)
	if err != nil {
		return fmt.Errorf("invalid primary identity email address: %w", err)
	}
	normalizedPrimaryEmail := primaryAddress.FullAddress()

	// Validate new email address format
	newAddress, err := server.NewAddress(req.NewEmail)
	if err != nil {
		return fmt.Errorf("invalid new email address: %w", err)
	}
	normalizedNewEmail := newAddress.FullAddress()

	if req.Password == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Check if new email already exists
	_, err = db.GetAccountIDByAddress(ctx, normalizedNewEmail)
	if err == nil {
		return fmt.Errorf("credential with email %s already exists", normalizedNewEmail)
	}
	if err != consts.ErrUserNotFound {
		return fmt.Errorf("error checking existing credential: %w", err)
	}

	// Find the account ID by primary identity
	var accountID int64
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx,
		"SELECT account_id FROM credentials WHERE address = $1 AND primary_identity = true",
		normalizedPrimaryEmail).Scan(&accountID)
	if err != nil {
		return fmt.Errorf("primary identity %s not found or is not a primary identity", normalizedPrimaryEmail)
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
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// If this should be the new primary identity, unset the current primary
	if req.IsPrimary {
		_, err = tx.Exec(ctx,
			"UPDATE credentials SET primary_identity = false WHERE account_id = $1 AND primary_identity = true",
			accountID)
		if err != nil {
			return fmt.Errorf("failed to unset current primary identity: %w", err)
		}
	}

	// Create credential
	_, err = tx.Exec(ctx,
		"INSERT INTO credentials (account_id, address, password, primary_identity, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())",
		accountID, normalizedNewEmail, hashedPassword, req.IsPrimary)
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
	Email       string
	Password    string
	HashType    string
	MakePrimary bool // Whether to make this credential the primary identity
}

// UpdateAccount updates an existing account's password and/or makes it primary
func (db *Database) UpdateAccount(ctx context.Context, req UpdateAccountRequest) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(req.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Validate that we have at least one operation to perform
	if req.Password == "" && !req.MakePrimary {
		return fmt.Errorf("either password or make-primary must be specified")
	}

	// Check if account exists
	accountID, err := db.GetAccountIDByAddress(ctx, normalizedEmail)
	if err != nil {
		if err == consts.ErrUserNotFound {
			return fmt.Errorf("account with email %s does not exist", normalizedEmail)
		}
		return fmt.Errorf("error checking account: %w", err)
	}

	// Generate password hash if password is provided
	var hashedPassword string
	var updatePassword bool
	if req.Password != "" {
		updatePassword = true
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
	}

	// Begin transaction if we need to handle primary identity change
	if req.MakePrimary {
		tx, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx)

		// First, unset any existing primary identity for this account
		_, err = tx.Exec(ctx,
			"UPDATE credentials SET primary_identity = false WHERE account_id = $1 AND primary_identity = true",
			accountID)
		if err != nil {
			return fmt.Errorf("failed to unset current primary identity: %w", err)
		}

		// Update password and/or set as primary
		if updatePassword {
			_, err = tx.Exec(ctx,
				"UPDATE credentials SET password = $1, primary_identity = true, updated_at = now() WHERE account_id = $2 AND address = $3",
				hashedPassword, accountID, normalizedEmail)
			if err != nil {
				return fmt.Errorf("failed to update account password and set primary: %w", err)
			}
		} else {
			_, err = tx.Exec(ctx,
				"UPDATE credentials SET primary_identity = true, updated_at = now() WHERE account_id = $1 AND address = $2",
				accountID, normalizedEmail)
			if err != nil {
				return fmt.Errorf("failed to set credential as primary: %w", err)
			}
		}

		// Commit transaction
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
	} else {
		// Just update password without changing primary status
		_, err = db.GetWritePool().Exec(ctx,
			"UPDATE credentials SET password = $1, updated_at = now() WHERE account_id = $2 AND address = $3",
			hashedPassword, accountID, normalizedEmail)
		if err != nil {
			return fmt.Errorf("failed to update account password: %w", err)
		}
	}

	return nil
}

// Credential represents a credential with its details
type Credential struct {
	Address         string
	PrimaryIdentity bool
	CreatedAt       string
	UpdatedAt       string
}

// ListCredentials lists all credentials for an account by providing any credential email
func (db *Database) ListCredentials(ctx context.Context, email string) ([]Credential, error) {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Get the account ID for this email
	accountID, err := db.GetAccountIDByAddress(ctx, normalizedEmail)
	if err != nil {
		if err == consts.ErrUserNotFound {
			return nil, fmt.Errorf("no account found with email %s", normalizedEmail)
		}
		return nil, fmt.Errorf("error finding account: %w", err)
	}

	// Get all credentials for this account
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx,
		"SELECT address, primary_identity, created_at, updated_at FROM credentials WHERE account_id = $1 ORDER BY primary_identity DESC, address ASC",
		accountID)
	if err != nil {
		return nil, fmt.Errorf("error querying credentials: %w", err)
	}
	defer rows.Close()

	var credentials []Credential
	for rows.Next() {
		var cred Credential
		var createdAt, updatedAt interface{}

		err := rows.Scan(&cred.Address, &cred.PrimaryIdentity, &createdAt, &updatedAt)
		if err != nil {
			return nil, fmt.Errorf("error scanning credential: %w", err)
		}

		cred.CreatedAt = fmt.Sprintf("%v", createdAt)
		cred.UpdatedAt = fmt.Sprintf("%v", updatedAt)
		credentials = append(credentials, cred)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating credentials: %w", err)
	}

	return credentials, nil
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
