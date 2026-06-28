package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// handleMailboxCommand handles the 'mailbox' command
func handleMailboxCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printMailboxUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		handleMailboxCreate(ctx)
	case "list":
		handleMailboxList(ctx)
	case "delete":
		handleMailboxDelete(ctx)
	case "rename":
		handleMailboxRename(ctx)
	case "subscribe":
		handleMailboxSubscribe(ctx)
	case "unsubscribe":
		handleMailboxUnsubscribe(ctx)
	case "fix-utf7":
		handleMailboxFixUTF7(ctx)
	case "help", "--help", "-h":
		printMailboxUsage()
	default:
		fmt.Printf("Unknown mailbox subcommand: %s\n\n", subcommand)
		printMailboxUsage()
		os.Exit(1)
	}
}

// handleMailboxCreate creates a new mailbox for a user
func handleMailboxCreate(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox create", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to create, e.g., 'Work' or 'Projects/2024' (required)")

	fs.Usage = func() {
		fmt.Printf(`Create a new mailbox for an account

Usage:
  sora-admin mailbox create --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to create (required)

Examples:
  # Create a top-level mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Work"

  # Create a nested mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Projects/2024/Q1"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Create mailbox
	err = rdb.CreateMailboxForUserWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to create mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully created mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxList lists all mailboxes for a user
func handleMailboxList(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox list", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	subscribedOnly := fs.Bool("subscribed", false, "Show only subscribed mailboxes")

	fs.Usage = func() {
		fmt.Printf(`List mailboxes for an account

Usage:
  sora-admin mailbox list --config PATH --email EMAIL [--subscribed]

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of the account (required)
  --subscribed     Show only subscribed mailboxes (default: false)

Examples:
  # List all mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com

  # List only subscribed mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com --subscribed
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Get mailboxes
	mailboxes, err := rdb.GetMailboxesForUserWithRetry(ctx, accountID, *subscribedOnly)
	if err != nil {
		fmt.Printf("Failed to list mailboxes: %v\n", err)
		os.Exit(1)
	}

	// Print results
	if len(mailboxes) == 0 {
		fmt.Println("No mailboxes found")
		return
	}

	fmt.Printf("Mailboxes for %s:\n\n", *email)
	fmt.Printf("%-40s %-12s %-10s %-12s\n", "Name", "Subscribed", "Children", "UID Validity")
	fmt.Printf("%-40s %-12s %-10s %-12s\n", "----", "----------", "--------", "------------")

	for _, mbox := range mailboxes {
		subscribed := "No"
		if mbox.Subscribed {
			subscribed = "Yes"
		}
		hasChildren := "No"
		if mbox.HasChildren {
			hasChildren = "Yes"
		}
		fmt.Printf("%-40s %-12s %-10s %-12d\n", mbox.Name, subscribed, hasChildren, mbox.UIDValidity)
	}
}

// handleMailboxDelete deletes a mailbox
func handleMailboxDelete(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox delete", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm deletion without interactive prompt (required)")
	purge := fs.Bool("purge", false, "Purge all messages from S3 and database immediately (no grace period)")

	fs.Usage = func() {
		fmt.Printf(`Delete a mailbox

Usage:
  sora-admin mailbox delete --config PATH --email EMAIL --mailbox MAILBOX --confirm [--purge]

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to delete (required)
  --confirm           Confirm deletion (required for safety)
  --purge             Purge all messages from S3 and database immediately without grace period

Examples:
  # Delete mailbox (messages enter grace period for cleanup)
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm

  # Delete mailbox and purge all messages immediately from S3 and database
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm --purge
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if !*confirm {
		fmt.Println("Error: --confirm is required for safety")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// If purge flag is set, purge all messages from S3 and database
	if *purge {
		fmt.Printf("Purging all messages from mailbox '%s' and its children...\n", *mailbox)

		// Initialize S3 storage
		useSSL := !globalConfig.S3.DisableTLS
		s3Timeout, err := globalConfig.S3.GetTimeout()
		if err != nil {
			fmt.Printf("Invalid S3 timeout configuration: %v\n", err)
			os.Exit(1)
		}
		s3Storage, err := storage.New(
			globalConfig.S3.Endpoint,
			globalConfig.S3.AccessKey,
			globalConfig.S3.SecretKey,
			globalConfig.S3.Bucket,
			useSSL,
			false,     // debug mode
			s3Timeout, // timeout
		)
		if err != nil {
			fmt.Printf("Failed to initialize S3 storage: %v\n", err)
			os.Exit(1)
		}

		// Enable encryption if configured
		if globalConfig.S3.Encrypt {
			if err := s3Storage.EnableEncryption(globalConfig.S3.EncryptionKey); err != nil {
				fmt.Printf("Failed to enable S3 encryption: %v\n", err)
				os.Exit(1)
			}
		}

		err = purgeMailboxMessages(ctx, rdb, s3Storage, accountID, *mailbox)
		if err != nil {
			fmt.Printf("Failed to purge messages: %v\n", err)
			os.Exit(1)
		}
	}

	// Delete mailbox
	err = rdb.DeleteMailboxForUserWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to delete mailbox: %v\n", err)
		os.Exit(1)
	}

	if *purge {
		fmt.Printf("Successfully purged and deleted mailbox '%s' for account %s\n", *mailbox, *email)
	} else {
		fmt.Printf("Successfully deleted mailbox '%s' for account %s (messages will be cleaned up after grace period)\n", *mailbox, *email)
	}
}

// handleMailboxRename renames or moves a mailbox
func handleMailboxRename(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox rename", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	oldName := fs.String("old-name", "", "Current mailbox name/path (required)")
	newName := fs.String("new-name", "", "New mailbox name/path (required)")

	fs.Usage = func() {
		fmt.Printf(`Rename or move a mailbox

Usage:
  sora-admin mailbox rename --config PATH --email EMAIL --old-name OLD --new-name NEW

Options:
  --config PATH     Path to TOML configuration file (required)
  --email EMAIL     Email address of the account (required)
  --old-name OLD    Current mailbox name/path (required)
  --new-name NEW    New mailbox name/path (required)

Examples:
  # Rename a mailbox
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Work" --new-name "Business"

  # Move a mailbox to a different parent
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Projects/2024" --new-name "Archive/Projects/2024"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *oldName == "" {
		fmt.Println("Error: --old-name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *newName == "" {
		fmt.Println("Error: --new-name is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Get the mailbox to rename
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, *oldName)
	if err != nil {
		fmt.Printf("Failed to find mailbox '%s': %v\n", *oldName, err)
		os.Exit(1)
	}

	// Rename mailbox - newParentID is handled internally by RenameMailbox
	err = rdb.RenameMailboxWithRetry(ctx, mbox.ID, accountID, *newName, nil)
	if err != nil {
		fmt.Printf("Failed to rename mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully renamed mailbox '%s' to '%s' for account %s\n", *oldName, *newName, *email)
}

// handleMailboxSubscribe subscribes to a mailbox
func handleMailboxSubscribe(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox subscribe", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to subscribe to (required)")

	fs.Usage = func() {
		fmt.Printf(`Subscribe to a mailbox

Usage:
  sora-admin mailbox subscribe --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to subscribe to (required)

Examples:
  sora-admin mailbox subscribe --config config.toml --email user@example.com --mailbox "Work"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Subscribe to mailbox
	err = rdb.SubscribeToMailboxWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to subscribe to mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully subscribed to mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxUnsubscribe unsubscribes from a mailbox
func handleMailboxUnsubscribe(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox unsubscribe", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Mailbox name/path to unsubscribe from (required)")

	fs.Usage = func() {
		fmt.Printf(`Unsubscribe from a mailbox

Usage:
  sora-admin mailbox unsubscribe --config PATH --email EMAIL --mailbox MAILBOX

Options:
  --config PATH       Path to TOML configuration file (required)
  --email EMAIL       Email address of the account (required)
  --mailbox MAILBOX   Mailbox name/path to unsubscribe from (required)

Examples:
  sora-admin mailbox unsubscribe --config config.toml --email user@example.com --mailbox "Work"
`)
	}

	fs.Parse(os.Args[3:])

	// Validate required parameters
	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *mailbox == "" {
		fmt.Println("Error: --mailbox is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Get account
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
	if err != nil {
		fmt.Printf("Failed to find account: %v\n", err)
		os.Exit(1)
	}

	// Unsubscribe from mailbox
	err = rdb.UnsubscribeFromMailboxWithRetry(ctx, accountID, *mailbox)
	if err != nil {
		fmt.Printf("Failed to unsubscribe from mailbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully unsubscribed from mailbox '%s' for account %s\n", *mailbox, *email)
}

// handleMailboxFixUTF7 finds and fixes mailbox names that contain un-decoded Modified UTF-7 sequences.
// This can happen when mailboxes were imported from Dovecot without decoding the filesystem names.
func handleMailboxFixUTF7(ctx context.Context) {
	fs := flag.NewFlagSet("mailbox fix-utf7", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account (optional, fixes all accounts if omitted)")
	dryRun := fs.Bool("dry-run", false, "Show what would be changed without making changes")

	fs.Usage = func() {
		fmt.Printf(`Fix mailbox names containing un-decoded Modified UTF-7 sequences

This command finds mailbox names that were imported with raw Modified UTF-7
encoding (e.g., from Dovecot) and renames them to proper UTF-8.

For example:
  "R&AOk-pertoire"  ->  "Répertoire"
  "&AMk-l&AOk-ments envoy&AOk-s"  ->  "Éléments envoyés"

Usage:
  sora-admin mailbox fix-utf7 --config PATH [--email EMAIL] [--dry-run]

Options:
  --config PATH    Path to TOML configuration file (required)
  --email EMAIL    Email address of a specific account (optional, all accounts if omitted)
  --dry-run        Show what would be changed without making changes

Examples:
  # Preview changes for all accounts
  sora-admin mailbox fix-utf7 --config config.toml --dry-run

  # Fix all accounts
  sora-admin mailbox fix-utf7 --config config.toml

  # Fix a specific account
  sora-admin mailbox fix-utf7 --config config.toml --email user@example.com
`)
	}

	fs.Parse(os.Args[3:])

	// Create database connection
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer rdb.Close()

	// Find affected mailboxes using a regex that matches Modified UTF-7 sequences.
	// Modified UTF-7 uses '&' followed by base64 chars and terminated by '-'.
	// We exclude '&-' (which is a literal ampersand escape).
	var query string
	var args []any

	if *email != "" {
		accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, *email)
		if err != nil {
			fmt.Printf("Failed to find account: %v\n", err)
			os.Exit(1)
		}
		query = `SELECT id, account_id, name FROM mailboxes WHERE account_id = $1 AND name ~ '&[A-Za-z0-9+,]+-' AND deleted_at IS NULL ORDER BY account_id, name`
		args = []any{accountID}
	} else {
		query = `SELECT id, account_id, name FROM mailboxes WHERE name ~ '&[A-Za-z0-9+,]+-' AND deleted_at IS NULL ORDER BY account_id, name`
	}

	db := rdb.GetOperationalDatabase()

	// Fetch all affected mailboxes, decode their names, and process them
	// shallowest-first. RenameMailbox cascades name changes to children,
	// so after renaming a parent its children's prefixes are updated.
	// We re-query after each depth level to pick up the cascaded changes.

	fixed := 0
	skipped := 0
	failed := 0
	firstQuery := true

	// Track mailbox IDs we've already skipped/failed so we don't retry them
	processedIDs := make(map[int64]bool)

	for {
		var rows []struct {
			MailboxID   int64
			AccountID   int64
			MailboxName string
		}

		dbRows, err := db.WritePool.Query(ctx, query, args...)
		if err != nil {
			fmt.Printf("Failed to query mailboxes: %v\n", err)
			os.Exit(1)
		}

		for dbRows.Next() {
			var r struct {
				MailboxID   int64
				AccountID   int64
				MailboxName string
			}
			if err := dbRows.Scan(&r.MailboxID, &r.AccountID, &r.MailboxName); err != nil {
				fmt.Printf("Failed to scan row: %v\n", err)
				os.Exit(1)
			}
			rows = append(rows, r)
		}
		if err := dbRows.Err(); err != nil {
			fmt.Printf("Failed to iterate mailbox rows: %v\n", err)
			os.Exit(1)
		}
		dbRows.Close()

		// Filter out already-processed IDs
		var unprocessed []struct {
			MailboxID   int64
			AccountID   int64
			MailboxName string
		}
		for _, r := range rows {
			if !processedIDs[r.MailboxID] {
				unprocessed = append(unprocessed, r)
			}
		}

		if len(unprocessed) == 0 {
			if firstQuery {
				fmt.Println("No mailboxes with Modified UTF-7 encoded names found.")
			}
			break
		}

		if firstQuery {
			fmt.Printf("Found %d mailbox(es) with potential Modified UTF-7 names:\n\n", len(unprocessed))
			firstQuery = false
		}

		// Find the shallowest depth (fewest '/' separators) among unprocessed mailboxes
		minDepth := -1
		for _, r := range unprocessed {
			d := strings.Count(r.MailboxName, "/")
			if minDepth == -1 || d < minDepth {
				minDepth = d
			}
		}

		renamedInRound := 0
		for _, r := range unprocessed {
			// Only process mailboxes at the shallowest depth in this round
			if strings.Count(r.MailboxName, "/") != minDepth {
				continue
			}

			decoded, err := helpers.DecodeModifiedUTF7(r.MailboxName)
			if err != nil {
				fmt.Printf("  SKIP  %-40s  (decode error: %v)\n", r.MailboxName, err)
				skipped++
				processedIDs[r.MailboxID] = true
				continue
			}

			if decoded == r.MailboxName {
				// Regex matched but no actual Modified UTF-7 (e.g., false positive)
				fmt.Printf("  SKIP  %-40s  (no change after decode)\n", r.MailboxName)
				skipped++
				processedIDs[r.MailboxID] = true
				continue
			}

			if *dryRun {
				fmt.Printf("  WOULD RENAME  account_id=%-6d  %q  ->  %q\n", r.AccountID, r.MailboxName, decoded)
				fixed++
				processedIDs[r.MailboxID] = true
				renamedInRound++
				continue
			}

			// Perform the rename (this cascades to children)
			err = rdb.RenameMailboxWithRetry(ctx, r.MailboxID, r.AccountID, decoded, nil)
			if err != nil {
				fmt.Printf("  FAIL  account_id=%-6d  %q  ->  %q  (error: %v)\n", r.AccountID, r.MailboxName, decoded, err)
				failed++
				processedIDs[r.MailboxID] = true
				continue
			}

			fmt.Printf("  OK    account_id=%-6d  %q  ->  %q\n", r.AccountID, r.MailboxName, decoded)
			fixed++
			processedIDs[r.MailboxID] = true
			renamedInRound++
		}

		// In dry-run mode nothing changes in the DB, so process all depths in one pass
		if *dryRun {
			for _, r := range unprocessed {
				if processedIDs[r.MailboxID] {
					continue
				}
				processedIDs[r.MailboxID] = true
				decoded, err := helpers.DecodeModifiedUTF7(r.MailboxName)
				if err != nil {
					fmt.Printf("  SKIP  %-40s  (decode error: %v)\n", r.MailboxName, err)
					skipped++
				} else if decoded == r.MailboxName {
					fmt.Printf("  SKIP  %-40s  (no change after decode)\n", r.MailboxName)
					skipped++
				} else {
					fmt.Printf("  WOULD RENAME  account_id=%-6d  %q  ->  %q\n", r.AccountID, r.MailboxName, decoded)
					fixed++
				}
			}
			break
		}

		if renamedInRound == 0 {
			// No successful renames at this depth. Continue to next round
			// which will re-query and skip already-processed IDs.
			continue
		}

		// Renames happened — re-query to pick up cascaded name changes
	}

	fmt.Println()
	if *dryRun {
		fmt.Printf("Dry run complete: %d would be renamed, %d skipped\n", fixed, skipped)
	} else {
		fmt.Printf("Done: %d renamed, %d skipped, %d failed\n", fixed, skipped, failed)
	}
}

// printMailboxUsage prints usage information for the 'mailbox' command
func printMailboxUsage() {
	fmt.Println(`Usage: sora-admin mailbox <subcommand> [options]

Subcommands:
  create        Create a new mailbox
  list          List all mailboxes for an account
  delete        Delete a mailbox
  rename        Rename or move a mailbox
  subscribe     Subscribe to a mailbox
  unsubscribe   Unsubscribe from a mailbox
  fix-utf7      Fix mailbox names with un-decoded Modified UTF-7 encoding

Examples:
  # Create a new mailbox
  sora-admin mailbox create --config config.toml --email user@example.com --mailbox "Work"

  # List all mailboxes
  sora-admin mailbox list --config config.toml --email user@example.com

  # Delete a mailbox (messages enter grace period)
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm

  # Delete a mailbox and purge all messages immediately
  sora-admin mailbox delete --config config.toml --email user@example.com --mailbox "OldFolder" --confirm --purge

  # Rename a mailbox
  sora-admin mailbox rename --config config.toml --email user@example.com --old-name "Work" --new-name "Business"

  # Subscribe to a mailbox
  sora-admin mailbox subscribe --config config.toml --email user@example.com --mailbox "Work"

  # Fix mailbox names with un-decoded Modified UTF-7 (preview)
  sora-admin mailbox fix-utf7 --config config.toml --dry-run

For more information on a subcommand, run:
  sora-admin mailbox <subcommand> --help`)
}

// purgeMailboxMessages purges all messages from a mailbox and its children
// by deleting them from both S3 and the database immediately
func purgeMailboxMessages(ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage objectStorage, accountID int64, mailboxName string) error {
	// Get the mailbox
	mbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
	if err != nil {
		return fmt.Errorf("failed to get mailbox: %w", err)
	}

	// Get all messages for this mailbox and its children by querying messages with matching path
	messages, err := rdb.GetMessagesForMailboxAndChildren(ctx, accountID, mbox.ID, mbox.Path)
	if err != nil {
		return fmt.Errorf("failed to get messages for purge: %w", err)
	}

	if len(messages) == 0 {
		fmt.Println("No messages to purge")
		return nil
	}

	fmt.Printf("Found %d messages to purge\n", len(messages))

	// Track unique S3 objects to delete (deduplicated by content hash)
	s3ObjectsToDelete := make(map[string]db.UserScopedObjectForCleanup)
	messageIDs := make([]int64, 0, len(messages))

	for _, msg := range messages {
		messageIDs = append(messageIDs, msg.ID)

		// Track unique S3 objects by user-scoped key (AccountID + ContentHash)
		key := fmt.Sprintf("%d:%s", msg.AccountID, msg.ContentHash)
		if _, exists := s3ObjectsToDelete[key]; !exists {
			s3ObjectsToDelete[key] = db.UserScopedObjectForCleanup{
				AccountID:   msg.AccountID,
				ContentHash: msg.ContentHash,
				S3Domain:    msg.S3Domain,
				S3Localpart: msg.S3Localpart,
			}
		}
	}

	fmt.Printf("Deleting %d unique S3 objects...\n", len(s3ObjectsToDelete))

	// Delete from S3 first (before database, so if S3 fails we don't lose track of objects)
	deletedCount := 0
	failedCount := 0
	for _, obj := range s3ObjectsToDelete {
		s3Key := helpers.NewS3Key(obj.S3Domain, obj.S3Localpart, obj.ContentHash)
		err := s3Storage.Delete(s3Key)
		if err != nil {
			fmt.Printf("Warning: Failed to delete S3 object %s: %v\n", s3Key, err)
			failedCount++
		} else {
			deletedCount++
		}
	}

	fmt.Printf("Deleted %d S3 objects (%d failed)\n", deletedCount, failedCount)

	// Now delete from database - delete messages directly (hard delete)
	fmt.Printf("Deleting %d messages from database...\n", len(messageIDs))
	deletedFromDB, err := rdb.PurgeMessagesByIDs(ctx, messageIDs)
	if err != nil {
		return fmt.Errorf("failed to purge messages from database: %w", err)
	}

	fmt.Printf("Purged %d messages from database\n", deletedFromDB)

	return nil
}
