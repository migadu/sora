package db

import (
	"context"
	"errors"
	"fmt"
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
func (db *Database) CreateAccount(ctx context.Context, req CreateAccountRequest) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(req.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if there's an existing credential with this email (including soft-deleted accounts)
	var existingAccountID int64
	var deletedAt *time.Time
	err = db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id 
		WHERE c.address = $1
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

	// Begin transaction
	tx, err := db.BeginTx(ctx)
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
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return consts.ErrDBUniqueViolation
		}
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
	AccountID   int64  // The ID of the account to add the credential to
	NewEmail    string // The new email address to add
	NewPassword string
	IsPrimary   bool // Whether to make this the new primary identity
	NewHashType string
}

// AddCredential adds a new credential to an existing account identified by its primary identity
func (db *Database) AddCredential(ctx context.Context, req AddCredentialRequest) error {
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

	// Begin transaction
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

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
		tx, err := db.BeginTx(ctx)
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
func (db *Database) DeleteCredential(ctx context.Context, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if credential exists and get account info
	var accountID int64
	var isPrimary bool
	var credentialCount int

	err = db.GetReadPool().QueryRow(ctx, `
		SELECT c.account_id, c.primary_identity,
		       (SELECT COUNT(*) FROM credentials WHERE account_id = c.account_id)
		FROM credentials c 
		WHERE c.address = $1
	`, normalizedEmail).Scan(&accountID, &isPrimary, &credentialCount)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("credential with email %s not found: %w", normalizedEmail, consts.ErrUserNotFound)
		}
		return fmt.Errorf("error finding credential: %w", err)
	}

	// Prevent deletion of the last credential
	if credentialCount <= 1 {
		return ErrCannotDeleteLastCredential
	}

	// Prevent deletion of the primary credential
	if isPrimary {
		return ErrCannotDeletePrimaryCredential
	}

	// Delete the credential (no transaction needed since it's a single operation)
	result, err := db.GetWritePool().Exec(ctx, "DELETE FROM credentials WHERE address = $1", normalizedEmail)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("credential with email %s not found during deletion: %w", normalizedEmail, consts.ErrUserNotFound)
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
		WHERE c.address = $1
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
	ErrNoServerAffinity      = errors.New("no server affinity found")
	ErrAccountAlreadyDeleted = errors.New("account is already deleted")
	ErrAccountNotDeleted     = errors.New("account is not deleted")
)

// DeleteAccount soft deletes an account by marking it as deleted
func (db *Database) DeleteAccount(ctx context.Context, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if account exists and is not already deleted
	var accountID int64
	var deletedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE c.address = $1
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

	// Begin transaction for soft delete
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

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

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit account soft deletion transaction: %w", err)
	}

	return nil
}

// RestoreAccount restores a soft-deleted account
func (db *Database) RestoreAccount(ctx context.Context, email string) error {
	// Validate email address format using server.NewAddress
	address, err := server.NewAddress(email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	normalizedEmail := address.FullAddress()

	// Check if account exists and is deleted
	var accountID int64
	var deletedAt *time.Time
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT a.id, a.deleted_at 
		FROM accounts a
		JOIN credentials c ON a.id = c.account_id
		WHERE c.address = $1
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
	result, err := db.GetWritePool().Exec(ctx, `
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

// HardDeleteAccount permanently deletes an account and all associated data
// This should only be called by the cleaner after the grace period
func (db *Database) HardDeleteAccount(ctx context.Context, accountID int64) error {
	// Begin transaction
	tx, err := db.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Delete in order to respect foreign key constraints
	// Note: Some tables have CASCADE deletes, but we'll be explicit for clarity

	// Delete active connections
	_, err = tx.Exec(ctx, "DELETE FROM active_connections WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete active connections: %w", err)
	}

	// Delete vacation responses
	_, err = tx.Exec(ctx, "DELETE FROM vacation_responses WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete vacation responses: %w", err)
	}

	// Delete SIEVE scripts
	_, err = tx.Exec(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete SIEVE scripts: %w", err)
	}

	// Delete pending_uploads entries
	_, err = tx.Exec(ctx, "DELETE FROM pending_uploads WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete pending uploads entries: %w", err)
	}

	// First, get the account's deleted_at timestamp to use for expunging messages
	var deletedAt time.Time
	err = tx.QueryRow(ctx, "SELECT deleted_at FROM accounts WHERE id = $1", accountID).Scan(&deletedAt)
	if err != nil {
		return fmt.Errorf("failed to get account deleted_at timestamp: %w", err)
	}

	// Mark all messages as expunged with the account's deletion timestamp.
	// This signals the cleaner to start the S3 cleanup process for these messages.
	// The message rows themselves will be deleted by the cleaner after S3 objects are gone.
	// The account row is preserved until all messages are cleaned up to prevent orphaning S3 objects.
	_, err = tx.Exec(ctx, `
		UPDATE messages 
		SET expunged_at = $2
		WHERE account_id = $1 AND expunged_at IS NULL
	`, accountID, deletedAt)
	if err != nil {
		return fmt.Errorf("failed to expunge messages: %w", err)
	}

	// Delete mailboxes
	_, err = tx.Exec(ctx, "DELETE FROM mailboxes WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete mailboxes: %w", err)
	}

	// The account row itself is NOT deleted here.
	// Credentials are also NOT deleted here. They are required by the cleaner's next phase
	// to look up the user's email address for S3 object deletion.
	// The cleaner worker will perform the final deletion of the 'accounts' row
	// and 'credentials' after all associated messages and S3 objects have been cleaned up.
	// This prevents orphaning S3 objects, as the account's email is needed to construct S3 keys.

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit account data cleanup transaction: %w", err)
	}

	return nil
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
		SELECT
			c.address, c.primary_identity, c.created_at, c.updated_at,
			a.id, a.created_at, a.deleted_at,
			COALESCE(cc.credential_count, 0),
			COALESCE(mc.mailbox_count, 0),
			COALESCE(msgc.message_count, 0)
		FROM credentials c
		JOIN accounts a ON c.account_id = a.id
		LEFT JOIN (SELECT account_id, COUNT(*) as credential_count FROM credentials GROUP BY account_id) cc ON a.id = cc.account_id
		LEFT JOIN (SELECT account_id, COUNT(*) as mailbox_count FROM mailboxes GROUP BY account_id) mc ON a.id = mc.account_id
		LEFT JOIN (SELECT account_id, COUNT(*) as message_count FROM messages WHERE expunged_at IS NULL GROUP BY account_id) msgc ON a.id = msgc.account_id
		WHERE c.address = $1
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

	// First, find the account ID from the provided email.
	var accountID int64
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT account_id FROM credentials WHERE address = $1
	`, normalizedEmail).Scan(&accountID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, consts.ErrUserNotFound
		}
		return nil, fmt.Errorf("error finding account by email: %w", err)
	}

	// Now, fetch all details for that account ID.
	var details AccountDetails
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT
			a.id, a.created_at, a.deleted_at,
			COALESCE(mc.mailbox_count, 0),
			COALESCE(msgc.message_count, 0)
		FROM accounts a
		LEFT JOIN (
			SELECT account_id, COUNT(*) as mailbox_count FROM mailboxes GROUP BY account_id
		) mc ON a.id = mc.account_id
		LEFT JOIN (
			SELECT account_id, COUNT(*) as message_count FROM messages WHERE expunged_at IS NULL GROUP BY account_id
		) msgc ON a.id = msgc.account_id
		WHERE a.id = $1
	`, accountID).Scan(&details.ID, &details.CreatedAt, &details.DeletedAt, &details.MailboxCount, &details.MessageCount)

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
	`, accountID)
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
		SELECT 
			a.id,
			a.created_at,
			COALESCE(pc.address, '') as primary_email,
			COALESCE(cc.credential_count, 0) as credential_count,
			COALESCE(mc.mailbox_count, 0) as mailbox_count,
			COALESCE(msgc.message_count, 0) as message_count
		FROM accounts a
		LEFT JOIN credentials pc ON a.id = pc.account_id AND pc.primary_identity = true
		LEFT JOIN (
			SELECT account_id, COUNT(*) as credential_count
			FROM credentials
			GROUP BY account_id
		) cc ON a.id = cc.account_id
		LEFT JOIN (
			SELECT account_id, COUNT(*) as mailbox_count
			FROM mailboxes
			GROUP BY account_id
		) mc ON a.id = mc.account_id
		LEFT JOIN (
			SELECT account_id, COUNT(*) as message_count
			FROM messages
			WHERE expunged_at IS NULL
			GROUP BY account_id
		) msgc ON a.id = msgc.account_id
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
