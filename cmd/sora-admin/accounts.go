package main

// accounts.go - Command handlers for accounts
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

func handleAccountsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printAccountsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		handleCreateAccount(ctx)
	case "list":
		handleListAccounts(ctx)
	case "show":
		handleShowAccount(ctx)
	case "update":
		handleUpdateAccount(ctx)
	case "delete":
		handleDeleteAccount(ctx)
	case "restore":
		handleRestoreAccount(ctx)
	case "purge-domain":
		handlePurgeDomain(ctx)
	case "help", "--help", "-h":
		printAccountsUsage()
	default:
		fmt.Printf("Unknown accounts subcommand: %s\n\n", subcommand)
		printAccountsUsage()
		os.Exit(1)
	}
}

func handleCreateAccount(ctx context.Context) {
	// Parse accounts create specific flags
	fs := flag.NewFlagSet("accounts create", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the new account (required unless --credentials is provided)")
	password := fs.String("password", "", "Password for the new account (required unless --password-hash or --credentials is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")
	credentials := fs.String("credentials", "", "JSON string containing multiple credentials (alternative to single email/password)")

	fs.Usage = func() {
		fmt.Printf(`Create a new account

Usage:
  sora-admin accounts create [options]

Options:
  --email string         Email address for the new account (required unless --credentials is provided)
  --password string      Password for the new account (required unless --password-hash or --credentials is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --credentials string   JSON string containing multiple credentials (alternative to single email/password)

Examples:
  # Create account with single credential
  sora-admin --config config.toml accounts create --email user@example.com --password mypassword
  sora-admin --config config.toml accounts create --email user@example.com --password mypassword --hash ssha512
  sora-admin --config config.toml accounts create --email user@example.com --password-hash '$2a$12$xyz...'

  # Create account with multiple credentials
  sora-admin --config config.toml accounts create --credentials '[{"email":"user@example.com","password":"pass1","is_primary":true},{"email":"alias@example.com","password":"pass2","is_primary":false}]'

  # Create account with mixed credentials (password and password_hash)
  sora-admin --config config.toml accounts create --credentials '[{"email":"user@example.com","password":"pass1","is_primary":true},{"email":"alias@example.com","password_hash":"$2a$12$xyz...","is_primary":false}]'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *credentials == "" && *email == "" {
		fmt.Printf("Error: either --email or --credentials is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *credentials != "" && (*email != "" || *password != "" || *passwordHash != "") {
		fmt.Printf("Error: cannot specify --credentials with --email, --password, or --password-hash\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *credentials == "" {
		if *password == "" && *passwordHash == "" {
			fmt.Printf("Error: either --password or --password-hash is required\n\n")
			fs.Usage()
			os.Exit(1)
		}

		if *password != "" && *passwordHash != "" {
			fmt.Printf("Error: cannot specify both --password and --password-hash\n\n")
			fs.Usage()
			os.Exit(1)
		}
	}

	// Validate hash type
	validHashTypes := []string{"bcrypt", "ssha512", "sha512"}
	hashTypeValid := false
	for _, validType := range validHashTypes {
		if *hashType == validType {
			hashTypeValid = true
			break
		}
	}
	if !hashTypeValid {
		fmt.Printf("Error: --hash must be one of: %s\n\n", strings.Join(validHashTypes, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Create the account
	if *credentials != "" {
		// Create account with multiple credentials
		if err := createAccountWithCredentials(ctx, globalConfig, *credentials); err != nil {
			logger.Fatalf("Failed to create account with credentials: %v", err)
		}
		fmt.Printf("Successfully created account with multiple credentials\n")
	} else {
		// Create account with single credential (always as primary identity)
		if err := createAccount(ctx, globalConfig, *email, *password, *passwordHash, true, *hashType); err != nil {
			logger.Fatalf("Failed to create account: %v", err)
		}
		fmt.Printf("Successfully created account: %s\n", *email)
	}
}

func handleListAccounts(ctx context.Context) {
	// Parse list-accounts specific flags
	fs := flag.NewFlagSet("accounts list", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`List all accounts in the system

This command displays a summary of all accounts including:
- Account ID and primary email address
- Number of credentials (aliases) per account
- Number of mailboxes per account
- Total message count per account (excluding expunged messages)
- Account creation date

Usage:
  sora-admin list-accounts [options]

Options:
  --config string        Path to TOML configuration file (required)

Examples:
  sora-admin list-accounts
  sora-admin list-accounts --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments

	// List accounts
	if err := listAccounts(ctx, globalConfig); err != nil {
		logger.Fatalf("Failed to list accounts: %v", err)
	}
}

func handleShowAccount(ctx context.Context) {
	// Parse show-account specific flags
	fs := flag.NewFlagSet("accounts show", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account to show")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show detailed information for a specific account
This command displays comprehensive information about an account including:
- Account ID and status (active/deleted)
- Primary email address and all credential aliases
- Account creation date and deletion date (if soft-deleted)
- Number of mailboxes and total message count
- All associated email addresses with their status

Usage:
  sora-admin accounts show --email <email> [options]

Options:
  --email string      Email address of the account to show (required)
  --config string        Path to TOML configuration file (required)
  --json             Output in JSON format instead of human-readable format

Examples:
  sora-admin accounts show --email user@example.com
  sora-admin accounts show --email user@example.com --json
  sora-admin accounts show --email user@example.com --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.Usage()
		os.Exit(1)
	}

	// Show the account details
	if err := showAccount(ctx, globalConfig, *email, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show account: %v", err)
	}
}

func handleUpdateAccount(ctx context.Context) {
	// Parse update-account specific flags
	fs := flag.NewFlagSet("accounts update", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the account to update (required)")
	password := fs.String("password", "", "New password for the account (optional if --password-hash or --make-primary is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	makePrimary := fs.Bool("make-primary", false, "Make this credential the primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Update an existing account's password and/or primary status

Usage:
  sora-admin accounts update [options]

Options:
  --email string         Email address for the account to update (required)
  --password string      New password for the account (optional if --password-hash or --make-primary is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --make-primary         Make this credential the primary identity for the account
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)

Examples:
  sora-admin --config config.toml accounts update --email user@example.com --password newpassword
  sora-admin --config config.toml accounts update --email user@example.com --password newpassword --make-primary
  sora-admin --config config.toml accounts update --email user@example.com --make-primary
  sora-admin --config config.toml accounts update --email user@example.com --password newpassword --hash ssha512
  sora-admin --config config.toml accounts update --email user@example.com --password-hash '$2a$12$xyz...'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password == "" && *passwordHash == "" && !*makePrimary {
		fmt.Printf("Error: either --password, --password-hash, or --make-primary must be specified\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password != "" && *passwordHash != "" {
		fmt.Printf("Error: cannot specify both --password and --password-hash\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate hash type
	validHashTypes := []string{"bcrypt", "ssha512", "sha512"}
	hashTypeValid := false
	for _, validType := range validHashTypes {
		if *hashType == validType {
			hashTypeValid = true
			break
		}
	}
	if !hashTypeValid {
		fmt.Printf("Error: --hash must be one of: %s\n\n", strings.Join(validHashTypes, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Update the account
	if err := updateAccount(ctx, globalConfig, *email, *password, *passwordHash, *makePrimary, *hashType); err != nil {
		logger.Fatalf("Failed to update account: %v", err)
	}

	// Print appropriate success message based on what was updated
	if (*password != "" || *passwordHash != "") && *makePrimary {
		fmt.Printf("Successfully updated password and set as primary for account: %s\n", *email)
	} else if *password != "" || *passwordHash != "" {
		fmt.Printf("Successfully updated password for account: %s\n", *email)
	} else if *makePrimary {
		fmt.Printf("Successfully set as primary identity for account: %s\n", *email)
	}
}

func handleDeleteAccount(ctx context.Context) {
	// Parse delete-account specific flags
	fs := flag.NewFlagSet("accounts delete", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the account to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm account deletion (required)")
	purge := fs.Bool("purge", false, "Purge all account data immediately (messages, mailboxes, credentials) without grace period")

	fs.Usage = func() {
		fmt.Printf(`Delete an account

This command soft-deletes an account by marking it for deletion. The account and
its data will be permanently removed by a background worker after a configurable
grace period.

During the grace period, the account can be restored using the 'accounts restore' command.

Use the --purge flag to immediately delete all data (messages from S3, mailboxes,
credentials) without any grace period. This action is irreversible.

Usage:
  sora-admin accounts delete [options]

Options:
  --email string      Email address for the account to delete (required)
  --confirm           Confirm account deletion (required for safety)
  --purge             Purge all account data immediately without grace period (irreversible)

Examples:
  # Soft-delete (with grace period)
  sora-admin --config config.toml accounts delete --email user@example.com --confirm

  # Hard-delete immediately (purge everything)
  sora-admin --config config.toml accounts delete --email user@example.com --confirm --purge
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if !*confirm {
		fmt.Printf("Error: --confirm is required for account deletion\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Delete the account
	if err := deleteAccount(ctx, globalConfig, *email, *purge); err != nil {
		logger.Fatalf("Failed to delete account: %v", err)
	}

	if *purge {
		fmt.Printf("Successfully purged account: %s. All data (messages, mailboxes, credentials) has been permanently deleted.\n", *email)
	} else {
		fmt.Printf("Successfully soft-deleted account: %s. It will be permanently removed after the grace period.\n", *email)
	}
}

func handleRestoreAccount(ctx context.Context) {
	// Parse accounts restore specific flags
	fs := flag.NewFlagSet("accounts restore", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the account to restore (required)")

	fs.Usage = func() {
		fmt.Printf(`Restore a soft-deleted account

This command restores an account that was previously deleted and is still within
the grace period. The account and all its data (mailboxes, messages, credentials)
will be restored to active status.

Usage:
  sora-admin accounts restore [options]

Options:
  --email string      Email address for the account to restore (required)
  --config string        Path to TOML configuration file (required)

Examples:
  sora-admin accounts restore --email user@example.com
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Restore the account
	if err := restoreAccount(ctx, globalConfig, *email); err != nil {
		logger.Fatalf("Failed to restore account: %v", err)
	}

	fmt.Printf("Successfully restored account: %s\n", *email)
}

func handlePurgeDomain(ctx context.Context) {
	// Parse purge-domain specific flags
	fs := flag.NewFlagSet("accounts purge-domain", flag.ExitOnError)

	domain := fs.String("domain", "", "Domain to purge (e.g., example.com) (required)")
	confirm := fs.Bool("confirm", false, "Confirm domain purge (required for safety)")

	fs.Usage = func() {
		fmt.Printf(`Purge all accounts in a domain

This command purges ALL accounts under a domain (e.g., *@example.com).
It iterates through all accounts and purges each one using the resumable
expunge-then-cleanup pattern.

⚠️  WARNING: This is IRREVERSIBLE and will delete:
  - All accounts with emails ending in @<domain>
  - All their messages (from S3 and database)
  - All their mailboxes
  - All their credentials

The operation is RESUMABLE - you can interrupt with Ctrl+C and re-run
the same command to continue where you left off.

Usage:
  sora-admin accounts purge-domain [options]

Options:
  --domain string     Domain to purge (e.g., example.com) (required)
  --confirm           Confirm domain purge (required for safety)

Examples:
  # Purge all *@example.com accounts
  sora-admin --config config.toml accounts purge-domain --domain example.com --confirm

  # If interrupted, re-run same command to resume
  sora-admin --config config.toml accounts purge-domain --domain example.com --confirm
`)
	}

	// Parse the remaining arguments
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *domain == "" {
		fmt.Printf("Error: --domain is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if !*confirm {
		fmt.Printf("Error: --confirm is required for domain purge\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Purge the domain
	if err := purgeDomain(ctx, globalConfig, *domain); err != nil {
		logger.Fatalf("Failed to purge domain: %v", err)
	}

	fmt.Printf("\n✅ Successfully purged all accounts for domain: %s\n", *domain)
}

func printAccountsUsage() {
	fmt.Printf(`Account Management

Usage:
  sora-admin accounts <subcommand> [options]

Subcommands:
  create        Create a new account
  list          List all accounts in the system
  show          Show detailed information for a specific account
  update        Update an existing account's password
  delete        Delete an account (soft delete with grace period, or hard delete with --purge)
  restore       Restore a soft-deleted account
  purge-domain  Purge all accounts in a domain (irreversible, resumable)

Examples:
  sora-admin accounts create --email user@example.com --password mypassword
  sora-admin accounts list
  sora-admin accounts show --email user@example.com
  sora-admin accounts update --email user@example.com --password newpassword
  sora-admin accounts delete --email user@example.com --confirm
  sora-admin accounts delete --email user@example.com --confirm --purge
  sora-admin accounts restore --email user@example.com
  sora-admin accounts purge-domain --domain example.com --confirm

Use 'sora-admin accounts <subcommand> --help' for detailed help.
`)
}

func createAccount(ctx context.Context, cfg AdminConfig, email, password, passwordHash string, isPrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Create account using the new db operation
	req := db.CreateAccountRequest{
		Email:        email,
		Password:     password,
		PasswordHash: passwordHash,
		IsPrimary:    isPrimary,
		HashType:     hashType,
	}

	if err := rdb.CreateAccountWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

func createAccountWithCredentials(ctx context.Context, cfg AdminConfig, credentialsJSON string) error {

	// Parse credentials JSON
	var credentialInputs []CredentialInput
	if err := json.Unmarshal([]byte(credentialsJSON), &credentialInputs); err != nil {
		return fmt.Errorf("invalid credentials JSON: %w", err)
	}

	if len(credentialInputs) == 0 {
		return fmt.Errorf("at least one credential must be provided")
	}

	// Convert to db.CredentialSpec
	credentials := make([]db.CredentialSpec, len(credentialInputs))
	for i, input := range credentialInputs {
		// Set default hash type if not specified
		hashType := input.HashType
		if hashType == "" {
			hashType = "bcrypt"
		}

		credentials[i] = db.CredentialSpec{
			Email:        input.Email,
			Password:     input.Password,
			PasswordHash: input.PasswordHash,
			IsPrimary:    input.IsPrimary,
			HashType:     hashType,
		}
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Create account with multiple credentials
	req := db.CreateAccountWithCredentialsRequest{
		Credentials: credentials,
	}

	accountID, err := rdb.CreateAccountWithCredentialsWithRetry(ctx, req)
	if err != nil {
		return err
	}

	logger.Info("Created account", "account_id", accountID, "credentials", len(credentials))
	return nil
}

func listAccounts(ctx context.Context, cfg AdminConfig) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// List accounts using the database function
	accounts, err := rdb.ListAccountsWithRetry(ctx)
	if err != nil {
		return err
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts found in the system.")
		return nil
	}

	fmt.Printf("Found %d account(s):\n\n", len(accounts))

	// Print header
	fmt.Printf("%-8s %-30s %-10s %-10s %-12s %-20s\n",
		"ID", "Primary Email", "Credentials", "Mailboxes", "Messages", "Created")
	fmt.Printf("%-8s %-30s %-10s %-10s %-12s %-20s\n",
		"--", "-------------", "-----------", "---------", "--------", "-------")

	// Print account details
	for _, account := range accounts {
		primaryEmail := account.PrimaryEmail
		if primaryEmail == "" {
			primaryEmail = "<no primary>"
		}

		fmt.Printf("%-8d %-30s %-10d %-10d %-12d %-20s\n",
			account.AccountID,
			primaryEmail,
			account.CredentialCount,
			account.MailboxCount,
			account.MessageCount,
			account.CreatedAt)
	}

	fmt.Printf("\nTotal accounts: %d\n", len(accounts))
	return nil
}

func showAccount(ctx context.Context, cfg AdminConfig, email string, jsonOutput bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get detailed account information
	accountDetails, err := rdb.GetAccountDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			return fmt.Errorf("account with email %s does not exist", email)
		}
		return fmt.Errorf("failed to get account details: %w", err)
	}

	// Output the results
	if jsonOutput {
		jsonData, err := json.MarshalIndent(accountDetails, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable output
		fmt.Printf("Account Details:\n")
		fmt.Printf("  Account ID:    %d\n", accountDetails.ID)
		fmt.Printf("  Primary Email: %s\n", accountDetails.PrimaryEmail)
		fmt.Printf("  Status:        %s\n", accountDetails.Status)
		fmt.Printf("  Created:       %s\n", accountDetails.CreatedAt.Format("2006-01-02 15:04:05 UTC"))

		if accountDetails.DeletedAt != nil {
			fmt.Printf("  Deleted:       %s\n", accountDetails.DeletedAt.Format("2006-01-02 15:04:05 UTC"))
		}

		fmt.Printf("  Mailboxes:     %d\n", accountDetails.MailboxCount)
		fmt.Printf("  Messages:      %d\n", accountDetails.MessageCount)

		fmt.Printf("\nCredentials (%d):\n", len(accountDetails.Credentials))
		for _, cred := range accountDetails.Credentials {
			status := "alias"
			if cred.PrimaryIdentity {
				status = "primary"
			}
			fmt.Printf("  %-30s %-8s created: %s\n",
				cred.Address,
				status,
				cred.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

func updateAccount(ctx context.Context, cfg AdminConfig, email, password, passwordHash string, makePrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Update account using the new db operation
	req := db.UpdateAccountRequest{
		Email:        email,
		Password:     password,
		PasswordHash: passwordHash,
		HashType:     hashType,
		MakePrimary:  makePrimary,
	}

	if err := rdb.UpdateAccountWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

func deleteAccount(ctx context.Context, cfg AdminConfig, email string, purge bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get account ID first (needed for purge)
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find account: %w", err)
	}

	// If purge flag is set, delete all data immediately using the expunge-then-cleanup pattern
	if purge {
		// Use the shared purgeAccount function
		if err := purgeAccount(ctx, cfg, rdb, accountID, email); err != nil {
			return err
		}
	} else {
		// Soft-delete the account using the existing database function
		if err := rdb.DeleteAccountWithRetry(ctx, email); err != nil {
			return fmt.Errorf("failed to delete account: %w", err)
		}
	}

	return nil
}

func restoreAccount(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Restore the account using the database function
	if err := rdb.RestoreAccountWithRetry(ctx, email); err != nil {
		return fmt.Errorf("failed to restore account: %w", err)
	}

	return nil
}
