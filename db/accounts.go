package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
func (db *Database) CreateAccount(ctx context.Context, tx pgx.Tx, req CreateAccountRequest) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(req.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if there's an existing credential with this email (including soft-deleted accounts)
	var existingAccountID int64
	var deletedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = $1
	`, normalizedEmail).Scan(&existingAccountID, &deletedAt)

	if err == nil {
		if deletedAt != nil {
			return fmt.Errorf("cannot create account with email %s: an account with this email is in deletion grace period", normalizedEmail)
		}
		return fmt.Errorf("account with email %s already exists", normalizedEmail)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("error checking for existing account: %w", err)
	}

	if req.Password == "" {
		return fmt.Errorf("password cannot be empty")
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return consts.ErrDBUniqueViolation
		}
		return fmt.Errorf("failed to create credential: %w", err)
	}

	return nil
}

// AddCredentialRequest represents the parameters for adding a credential to an existing account
type AddCredentialRequest struct {
	AccountID   int64  // The ID of the account to add the credential to
	NewEmail    string // The new email address to add
	NewPassword string
	IsPrimary   bool // Whether to make this the new primary identity
	NewHashType string
}

// AddCredential adds a new credential to an existing account identified by its primary identity
func (db *Database) AddCredential(ctx context.Context, tx pgx.Tx, req AddCredentialRequest) error {
	if req.AccountID <= 0 {
		return fmt.Errorf("a valid AccountID is required")
	}

	// Validate new email address format
	newAddress, err := server.NewAddress(req.NewEmail)
	if err != nil {
		return fmt.Errorf("invalid new email address: %w", err)
	}
	normalizedNewEmail := newAddress.FullAddress()

	if req.NewPassword == "" {
		return fmt.Errorf("password cannot be empty")
	}

	// Generate password hash
	var hashedPassword string

	switch req.NewHashType {
	case "ssha512":
		hashedPassword, err = GenerateSSHA512Hash(req.NewPassword)
		if err != nil {
			return fmt.Errorf("failed to generate SSHA512 hash: %w", err)
		}
	case "sha512":
		hashedPassword = GenerateSHA512Hash(req.NewPassword)
	case "bcrypt":
		hashedPassword, err = GenerateBcryptHash(req.NewPassword)
		if err != nil {
			return fmt.Errorf("failed to generate bcrypt hash: %w", err)
		}
	default:
		return fmt.Errorf("unsupported hash type: %s", req.NewHashType)
	}

	// If this should be the new primary identity, unset the current primary
	if req.IsPrimary {
		_, err = tx.Exec(ctx,
			"UPDATE credentials SET primary_identity = false WHERE account_id = $1 AND primary_identity = true",
			req.AccountID)
		if err != nil {
			return fmt.Errorf("failed to unset current primary identity: %w", err)
		}
	}

	// Create credential
	_, err = tx.Exec(ctx,
		"INSERT INTO credentials (account_id, address, password, primary_identity, created_at, updated_at) VALUES ($1, $2, $3, $4, now(), now())",
		req.AccountID, normalizedNewEmail, hashedPassword, req.IsPrimary)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return consts.ErrDBUniqueViolation
		}
		return fmt.Errorf("failed to create new credential: %w", err)
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
func (db *Database) UpdateAccount(ctx context.Context, tx pgx.Tx, req UpdateAccountRequest) error {
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
	accountID, err := db.getAccountIDByAddressInTx(ctx, tx, normalizedEmail)
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
				"UPDATE credentials SET password = $1, primary_identity = true, updated_at = now() WHERE account_id = $2 AND LOWER(address) = $3",
				hashedPassword, accountID, normalizedEmail)
			if err != nil {
				return fmt.Errorf("failed to update account password and set primary: %w", err)
			}
		} else {
			_, err = tx.Exec(ctx,
				"UPDATE credentials SET primary_identity = true, updated_at = now() WHERE account_id = $1 AND LOWER(address) = $2",
				accountID, normalizedEmail)
			if err != nil {
				return fmt.Errorf("failed to set credential as primary: %w", err)
			}
		}

	} else {
		// Just update password without changing primary status
		_, err = tx.Exec(ctx,
			"UPDATE credentials SET password = $1, updated_at = now() WHERE account_id = $2 AND LOWER(address) = $3",
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
		// Pass the error through. GetAccountIDByAddress should return a wrapped consts.ErrUserNotFound.
		return nil, err
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

var (
	ErrCannotDeletePrimaryCredential = errors.New("cannot delete the primary credential. Use update-account to make another credential primary first")
	ErrCannotDeleteLastCredential    = errors.New("cannot delete the last credential for an account. Use delete-account to remove the entire account")
)

// DeleteCredential deletes a specific credential from an account
func (db *Database) DeleteCredential(ctx context.Context, tx pgx.Tx, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Use a single atomic DELETE statement with conditions to prevent race conditions.
	// This is more efficient and safer than a separate SELECT then DELETE.
	var deletedID int64
	err = tx.QueryRow(ctx, `
		DELETE FROM credentials
		WHERE
			LOWER(address) = $1
		AND
			-- Condition: Do not delete the primary credential.
			primary_identity = false
		AND
			-- Condition: Do not delete the last credential for the account.
			(SELECT COUNT(*) FROM credentials WHERE account_id = (SELECT account_id FROM credentials WHERE LOWER(address) = $1)) > 1
		RETURNING id
	`, normalizedEmail).Scan(&deletedID)

	// If the DELETE returned no rows, it means one of the conditions failed.
	// We now perform a read-only query to find out why and return a specific error.
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			var isPrimary bool
			var credentialCount int
			errCheck := tx.QueryRow(ctx, `
				SELECT c.primary_identity, (SELECT COUNT(*) FROM credentials WHERE account_id = c.account_id)
				FROM credentials c WHERE LOWER(c.address) = $1
			`, normalizedEmail).Scan(&isPrimary, &credentialCount)

			if errCheck != nil {
				if errors.Is(errCheck, pgx.ErrNoRows) {
					return fmt.Errorf("credential with email %s not found: %w", normalizedEmail, consts.ErrUserNotFound)
				}
				return fmt.Errorf("error checking credential status after failed delete: %w", errCheck)
			}

			if isPrimary {
				return ErrCannotDeletePrimaryCredential
			}
			if credentialCount <= 1 {
				return ErrCannotDeleteLastCredential
			}
			return fmt.Errorf("failed to delete credential for an unknown reason, possibly a concurrent modification")
		}
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

// AccountExists checks if an account with the given email exists and is not soft-deleted
func (db *Database) AccountExists(ctx context.Context, email string) (bool, error) {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return false, fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if account exists and is not soft-deleted
	var accountID int64
	var deletedAt interface{}
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = $1
	`, normalizedEmail).Scan(&accountID, &deletedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("error checking account existence: %w", err)
	}

	// Return false if account is soft-deleted
	return deletedAt == nil, nil
}

var (
	ErrAccountAlreadyDeleted = errors.New("account is already deleted")
	ErrAccountNotDeleted     = errors.New("account is not deleted")
)

// DeleteAccount soft deletes an account by marking it as deleted
func (db *Database) DeleteAccount(ctx context.Context, tx pgx.Tx, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if account exists and is not already deleted
	var accountID int64
	var deletedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = $1
	`, normalizedEmail).Scan(&accountID, &deletedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("account with email %s not found: %w", normalizedEmail, consts.ErrUserNotFound)
		}
		return fmt.Errorf("error finding account: %w", err)
	}

	if deletedAt != nil {
		return ErrAccountAlreadyDeleted
	}

	// Soft delete the account by setting deleted_at timestamp
	result, err := tx.Exec(ctx, `
		UPDATE accounts 
		SET deleted_at = now() 
		WHERE id = $1 AND deleted_at IS NULL
	`, accountID)
	if err != nil {
		return fmt.Errorf("failed to soft delete account: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("account not found or already deleted")
	}

	// Disconnect all active connections for this account
	_, err = tx.Exec(ctx, "DELETE FROM active_connections WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to disconnect active connections: %w", err)
	}

	return nil
}

// RestoreAccount restores a soft-deleted account
func (db *Database) RestoreAccount(ctx context.Context, tx pgx.Tx, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if account exists and is deleted
	var accountID int64
	var deletedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = $1
	`, normalizedEmail).Scan(&accountID, &deletedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("account with email %s not found: %w", normalizedEmail, consts.ErrUserNotFound)
		}
		return fmt.Errorf("error finding account: %w", err)
	}

	if deletedAt == nil {
		return ErrAccountNotDeleted
	}

	// Restore the account by clearing deleted_at
	result, err := tx.Exec(ctx, `
		UPDATE accounts 
		SET deleted_at = NULL 
		WHERE id = $1 AND deleted_at IS NOT NULL
	`, accountID)
	if err != nil {
		return fmt.Errorf("failed to restore account: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("account not found or not deleted")
	}

	return nil
}

// getAccountIDByAddressInTx retrieves the main user ID associated with a given identity (address)
// within a transaction.
func (db *Database) getAccountIDByAddressInTx(ctx context.Context, tx pgx.Tx, address string) (int64, error) {
	var accountID int64
	normalizedAddress := strings.ToLower(strings.TrimSpace(address))

	if normalizedAddress == "" {
		return 0, errors.New("address cannot be empty")
	}

	// Query the credentials table for the account_id associated with the address
	err := tx.QueryRow(ctx, "SELECT account_id FROM credentials WHERE LOWER(address) = $1", normalizedAddress).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Identity (address) not found in the credentials table
			return 0, consts.ErrUserNotFound
		}
		return 0, fmt.Errorf("database error fetching account ID: %w", err)
	}
	return accountID, nil
}

// CredentialDetails holds comprehensive information about a single credential and its account.
type CredentialDetails struct {
	Address         string    `json:"address"`
	PrimaryIdentity bool      `json:"primary_identity"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Account         struct {
		ID               int64      `json:"account_id"`
		CreatedAt        time.Time  `json:"account_created_at"`
		DeletedAt        *time.Time `json:"account_deleted_at,omitempty"`
		Status           string     `json:"account_status"`
		MailboxCount     int64      `json:"mailbox_count"`
		MessageCount     int64      `json:"message_count"`
		TotalCredentials int64      `json:"total_credentials"`
	} `json:"account"`
}

// GetCredentialDetails retrieves comprehensive details for a specific credential and its account.
func (db *Database) GetCredentialDetails(ctx context.Context, email string) (*CredentialDetails, error) {
	var details CredentialDetails
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT c.address, c.primary_identity, c.created_at, c.updated_at,
			   a.id, a.created_at, a.deleted_at,
			   (SELECT COUNT(*) FROM credentials WHERE account_id = a.id) AS total_credentials,
			   (SELECT COUNT(*) FROM mailboxes WHERE account_id = a.id) AS mailbox_count,
			   (SELECT COUNT(*) FROM messages WHERE account_id = a.id AND expunged_at IS NULL) AS message_count
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		WHERE LOWER(c.address) = LOWER($1)
	`, email).Scan(
		&details.Address, &details.PrimaryIdentity, &details.CreatedAt, &details.UpdatedAt,
		&details.Account.ID, &details.Account.CreatedAt, &details.Account.DeletedAt,
		&details.Account.TotalCredentials, &details.Account.MailboxCount, &details.Account.MessageCount,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("credential with email %s not found: %w", email, consts.ErrUserNotFound)
		}
		return nil, fmt.Errorf("error finding credential details: %w", err)
	}

	// Set account status
	details.Account.Status = "active"
	if details.Account.DeletedAt != nil {
		details.Account.Status = "deleted"
	}

	return &details, nil
}

// AccountCredentialDetails holds information about a single credential.
type AccountCredentialDetails struct {
	Address         string    `json:"address"`
	PrimaryIdentity bool      `json:"primary_identity"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AccountDetails holds comprehensive information about an account.
type AccountDetails struct {
	ID           int64                      `json:"account_id"`
	CreatedAt    time.Time                  `json:"created_at"`
	DeletedAt    *time.Time                 `json:"deleted_at,omitempty"`
	PrimaryEmail string                     `json:"primary_email"`
	Status       string                     `json:"status"`
	Credentials  []AccountCredentialDetails `json:"credentials"`
	MailboxCount int64                      `json:"mailbox_count"`
	MessageCount int64                      `json:"message_count"`
}

// GetAccountDetails retrieves comprehensive details for an account by any associated email.
func (db *Database) GetAccountDetails(ctx context.Context, email string) (*AccountDetails, error) {
	address, err := server.NewAddress(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email address: %w", err)
	}
	normalizedEmail := address.FullAddress()

	// Fetch all details for the account associated with the email.
	// This combines fetching the account and its statistics in one query.
	var details AccountDetails
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT a.id, a.created_at, a.deleted_at,
			   (SELECT count(*) FROM mailboxes WHERE account_id = a.id) AS mailbox_count,
			   (SELECT count(*) FROM messages WHERE account_id = a.id AND expunged_at IS NULL) AS message_count
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE LOWER(c.address) = $1
	`, normalizedEmail).Scan(&details.ID, &details.CreatedAt, &details.DeletedAt, &details.MailboxCount, &details.MessageCount)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrUserNotFound
		}
		return nil, fmt.Errorf("error fetching account main details: %w", err)
	}

	// Set status
	details.Status = "active"
	if details.DeletedAt != nil {
		details.Status = "deleted"
	}

	// Fetch credentials
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT address, primary_identity, created_at, updated_at
		FROM credentials WHERE account_id = $1 ORDER BY primary_identity DESC, address ASC
	`, details.ID)
	if err != nil {
		return nil, fmt.Errorf("error fetching credentials: %w", err)
	}
	defer rows.Close()

	details.Credentials, err = pgx.CollectRows(rows, pgx.RowToStructByName[AccountCredentialDetails])
	if err != nil {
		return nil, fmt.Errorf("error scanning credentials: %w", err)
	}

	for _, cred := range details.Credentials {
		if cred.PrimaryIdentity {
			details.PrimaryEmail = cred.Address
			break
		}
	}

	return &details, nil
}

// AccountSummary represents basic account information for listing
type AccountSummary struct {
	AccountID       int64  `json:"account_id"`
	PrimaryEmail    string `json:"primary_email"`
	CredentialCount int    `json:"credential_count"`
	MailboxCount    int    `json:"mailbox_count"`
	MessageCount    int64  `json:"message_count"`
	CreatedAt       string `json:"created_at"`
}

// ListAccounts returns a summary of all accounts in the system
func (db *Database) ListAccounts(ctx context.Context) ([]AccountSummary, error) {
	query := `
		SELECT a.id,
			   a.created_at,
			   COALESCE(pc.address, '') AS primary_email,
			   (SELECT COUNT(*) FROM credentials WHERE account_id = a.id) AS credential_count,
			   (SELECT COUNT(*) FROM mailboxes WHERE account_id = a.id) AS mailbox_count,
			   (SELECT COUNT(*) FROM messages WHERE expunged_at IS NULL AND account_id = a.id) AS message_count
		FROM accounts a
				 LEFT JOIN credentials pc ON a.id = pc.account_id AND pc.primary_identity = TRUE
		WHERE a.deleted_at IS NULL
		ORDER BY a.created_at DESC`

	rows, err := db.GetReadPool().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []AccountSummary
	for rows.Next() {
		var account AccountSummary
		var createdAt interface{}
		err := rows.Scan(&account.AccountID, &createdAt, &account.PrimaryEmail,
			&account.CredentialCount, &account.MailboxCount, &account.MessageCount)
		if err != nil {
			return nil, fmt.Errorf("failed to scan account: %w", err)
		}
		account.CreatedAt = fmt.Sprintf("%v", createdAt)
		accounts = append(accounts, account)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating accounts: %w", err)
	}

	return accounts, nil
}
