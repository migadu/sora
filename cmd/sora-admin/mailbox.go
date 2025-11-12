package main

import (
	"context"
	"flag"
	"fmt"
	"os"

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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
		s3Storage, err := storage.New(
			globalConfig.S3.Endpoint,
			globalConfig.S3.AccessKey,
			globalConfig.S3.SecretKey,
			globalConfig.S3.Bucket,
			useSSL,
			false, // debug mode
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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
	rdb, err := resilient.NewResilientDatabase(ctx, &globalConfig.Database, false, false)
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
