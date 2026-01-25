package main

// credentials.go - Command handlers for credentials
// Extracted from main.go for better organization

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
)

func handleCredentialsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printCredentialsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "add":
		handleAddCredential(ctx)
	case "list":
		handleListCredentials(ctx)
	case "show":
		handleShowCredential(ctx)
	case "delete":
		handleDeleteCredential(ctx)
	case "help", "--help", "-h":
		printCredentialsUsage()
	default:
		fmt.Printf("Unknown credentials subcommand: %s\n\n", subcommand)
		printCredentialsUsage()
		os.Exit(1)
	}
}

func handleAddCredential(ctx context.Context) {
	// Parse add-credential specific flags
	fs := flag.NewFlagSet("credentials add", flag.ExitOnError)

	primaryIdentity := fs.String("primary", "", "Primary identity of the account to add credential to (required)")
	email := fs.String("email", "", "New email address to add as credential (required)")
	password := fs.String("password", "", "Password for the new credential (required unless --password-hash is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	makePrimary := fs.Bool("make-primary", false, "Make this the new primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Add a credential to an existing account

Usage:
  sora-admin credentials add [options]

Options:
  --primary string       Primary identity of the account to add credential to (required)
  --email string         New email address to add as credential (required)
  --password string      Password for the new credential (required unless --password-hash is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --make-primary         Make this the new primary identity for the account
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)

Examples:
  sora-admin --config config.toml credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin --config config.toml credentials add --primary admin@example.com --email newalias@example.com --password mypassword --make-primary
  sora-admin --config config.toml credentials add --primary admin@example.com --email alias@example.com --password-hash '$2a$12$xyz...'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *primaryIdentity == "" {
		fmt.Printf("Error: --primary is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

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

	// Add the credential
	if err := addCredential(ctx, globalConfig, *primaryIdentity, *email, *password, *passwordHash, *makePrimary, *hashType); err != nil {
		logger.Fatalf("Failed to add credential: %v", err)
	}

	fmt.Printf("Successfully added credential: %s to account with primary identity: %s\n", *email, *primaryIdentity)
}

func handleListCredentials(ctx context.Context) {
	// Parse list-credentials specific flags
	fs := flag.NewFlagSet("credentials list", flag.ExitOnError)

	email := fs.String("email", "", "Email address associated with the account (required)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`List all credentials for an account

Usage:
  sora-admin list-credentials [options]

Options:
  --email string       Email address associated with the account (required)

Examples:
  sora-admin --config config.toml list-credentials --email user@example.com
  sora-admin --config custom.toml list-credentials --email alias@example.com
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

	// List the credentials
	if err := listCredentials(ctx, globalConfig, *email); err != nil {
		logger.Fatalf("Failed to list credentials: %v", err)
	}
}

func handleShowCredential(ctx context.Context) {
	// Parse show-credential specific flags
	fs := flag.NewFlagSet("credentials show", flag.ExitOnError)
	email := fs.String("email", "", "Email address (credential) to show details for")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show detailed information for a specific credential

This command displays comprehensive information about a specific credential including:
- The email address and its account association
- Whether it's a primary identity or alias
- Creation and last update timestamps
- Account status (active/deleted)
- Associated account summary information

Usage:
  sora-admin credentials show --email <email> [options]

Options:
  --email string      Email address (credential) to show details for (required)
  --config string        Path to TOML configuration file (required)
  --json             Output in JSON format instead of human-readable format

Examples:
  sora-admin credentials show --email user@example.com
  sora-admin credentials show --email alias@example.com --json
  sora-admin credentials show --email user@example.com --config /path/to/config.toml
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

	// Show the credential details
	if err := showCredential(ctx, globalConfig, *email, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show credential: %v", err)
	}
}

func handleDeleteCredential(ctx context.Context) {
	// Parse delete-credential specific flags
	fs := flag.NewFlagSet("credentials delete", flag.ExitOnError)

	email := fs.String("email", "", "Email address of the credential to delete (required)")

	fs.Usage = func() {
		fmt.Printf(`Delete a specific credential from an account

This command removes a specific credential (email/password combination) from an account.

Restrictions:
- You cannot delete the primary credential. Use update-account to make another
  credential primary first, then delete the old one.
- You cannot delete the last credential of an account. Use delete-account to
  remove the entire account and all its data.

Usage:
  sora-admin delete-credential [options]

Options:
  --email string      Email address of the credential to delete (required)

Examples:
  sora-admin --config config.toml delete-credential --email alias@example.com
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

	// Delete the credential
	if err := deleteCredential(ctx, globalConfig, *email); err != nil {
		logger.Fatalf("Failed to delete credential: %v", err)
	}

	fmt.Printf("Successfully deleted credential: %s\n", *email)
}

func printCredentialsUsage() {
	fmt.Printf(`Credential Management

Usage:
  sora-admin credentials <subcommand> [options]

Subcommands:
  add      Add a credential to an existing account
  list     List all credentials for an account
  show     Show detailed information for a specific credential
  delete   Delete a specific credential from an account

Examples:
  sora-admin credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin credentials list --email user@example.com
  sora-admin credentials show --email user@example.com
  sora-admin credentials delete --email alias@example.com

Use 'sora-admin credentials <subcommand> --help' for detailed help.
`)
}

func addCredential(ctx context.Context, cfg AdminConfig, primaryIdentity, email, password, passwordHash string, makePrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get the account ID for the primary identity
	// This read operation also needs resilience.
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, primaryIdentity)
	if err != nil {
		return fmt.Errorf("failed to find account with primary identity '%s': %w", primaryIdentity, err)
	}

	// Add credential using the new db operation
	req := db.AddCredentialRequest{
		AccountID:       accountID,
		NewEmail:        email,
		NewPassword:     password,
		NewPasswordHash: passwordHash,
		IsPrimary:       makePrimary,
		NewHashType:     hashType,
	}

	if err = rdb.AddCredentialWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

func listCredentials(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// List credentials using the new db operation
	credentials, err := rdb.ListCredentialsWithRetry(ctx, email)
	if err != nil {
		return err
	}

	fmt.Printf("Credentials for account associated with %s:\n\n", email)

	for _, cred := range credentials {
		primaryMarker := ""
		if cred.PrimaryIdentity {
			primaryMarker = " * primary"
		}
		fmt.Printf("  %s%s\n", cred.Address, primaryMarker)
		fmt.Printf("    Created: %s\n", cred.CreatedAt)
		fmt.Printf("    Updated: %s\n", cred.UpdatedAt)
		fmt.Printf("\n")
	}

	fmt.Printf("Total credentials: %d\n", len(credentials))

	return nil
}

func showCredential(ctx context.Context, cfg AdminConfig, email string, jsonOutput bool) error {

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get credential details and associated account information
	credentialDetails, err := rdb.GetCredentialDetailsWithRetry(ctx, email)
	if err != nil {
		return err // The error from the DB function is already descriptive
	}

	// Output the results
	if jsonOutput {
		jsonData, err := json.MarshalIndent(credentialDetails, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable output
		fmt.Printf("Credential Details:\n")
		fmt.Printf("  Email Address: %s\n", credentialDetails.Address)

		roleType := "Alias"
		if credentialDetails.PrimaryIdentity {
			roleType = "Primary Identity"
		}
		fmt.Printf("  Role: %s\n", roleType)

		fmt.Printf("  Created: %s\n", credentialDetails.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("  Updated: %s\n", credentialDetails.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))

		fmt.Printf("\nAssociated Account:\n")
		fmt.Printf("  Account ID: %d\n", credentialDetails.Account.ID)
		fmt.Printf("  Status: %s\n", credentialDetails.Account.Status)
		fmt.Printf("  Created: %s\n", credentialDetails.Account.CreatedAt.Format("2006-01-02 15:04:05 UTC"))

		if credentialDetails.Account.DeletedAt != nil {
			fmt.Printf("  Deleted: %s\n", credentialDetails.Account.DeletedAt.Format("2006-01-02 15:04:05 UTC"))
		}

		fmt.Printf("  Total Credentials: %d\n", credentialDetails.Account.TotalCredentials)
		fmt.Printf("  Mailboxes: %d\n", credentialDetails.Account.MailboxCount)
		fmt.Printf("  Messages: %d\n", credentialDetails.Account.MessageCount)
	}

	return nil
}

func deleteCredential(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Delete the credential using the database function
	if err := rdb.DeleteCredentialWithRetry(ctx, email); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}
