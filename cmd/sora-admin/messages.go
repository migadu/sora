package main

// messages.go - Command handlers for messages
// Extracted from main.go for better organization

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
)

func handleMessagesCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printMessagesUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list-deleted":
		handleListDeletedMessages(ctx)
	case "restore":
		handleRestoreMessages(ctx)
	case "help", "--help", "-h":
		printMessagesUsage()
	default:
		fmt.Printf("Unknown messages subcommand: %s\n\n", subcommand)
		printMessagesUsage()
		os.Exit(1)
	}
}

func handleListDeletedMessages(ctx context.Context) {
	// Parse list-deleted-messages specific flags
	fs := flag.NewFlagSet("messages list-deleted", flag.ExitOnError)

	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Filter by mailbox path (optional)")
	since := fs.String("since", "", "Show messages deleted since this date (YYYY-MM-DD or RFC3339)")
	until := fs.String("until", "", "Show messages deleted until this date (YYYY-MM-DD or RFC3339)")
	limit := fs.Int("limit", 100, "Maximum number of messages to show")

	fs.Usage = func() {
		fmt.Printf(`List deleted (expunged) messages for an account

This command shows messages that have been deleted (expunged) but not yet
permanently removed by the cleanup worker. Messages in the grace period
can be restored using the 'restore' subcommand.

Usage:
  sora-admin messages list-deleted --email <email> [options]

Required Options:
  --email string        Email address of the account

Optional Filters:
  --mailbox string      Only show messages from this mailbox
  --since string        Only show messages deleted since this date (YYYY-MM-DD or RFC3339)
  --until string        Only show messages deleted until this date (YYYY-MM-DD or RFC3339)
  --limit int           Maximum number of messages to show (default: 100)

Other Options:
  --config string        Path to TOML configuration file (required)

Examples:
  sora-admin messages list-deleted --email user@example.com
  sora-admin messages list-deleted --email user@example.com --mailbox INBOX
  sora-admin messages list-deleted --email user@example.com --since 2024-01-01
  sora-admin messages list-deleted --email user@example.com --limit 50
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	// Validate required flags
	if *email == "" {
		fmt.Println("ERROR: --email is required")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Parse time filters
	var sinceTime, untilTime *time.Time
	if *since != "" {
		t, err := parseTimeFlag(*since)
		if err != nil {
			logger.Fatalf("Invalid --since value: %v", err)
		}
		sinceTime = &t
	}
	if *until != "" {
		t, err := parseTimeFlag(*until)
		if err != nil {
			logger.Fatalf("Invalid --until value: %v", err)
		}
		untilTime = &t
	}

	// List deleted messages
	if err := listDeletedMessages(ctx, globalConfig, *email, mailbox, sinceTime, untilTime, *limit); err != nil {
		logger.Fatalf("Failed to list deleted messages: %v", err)
	}
}

func handleRestoreMessages(ctx context.Context) {
	// Parse restore-messages specific flags
	fs := flag.NewFlagSet("messages restore", flag.ExitOnError)

	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Restore all deleted messages from this mailbox")
	ids := fs.String("ids", "", "Comma-separated list of message IDs to restore")
	since := fs.String("since", "", "Restore messages deleted since this date (YYYY-MM-DD or RFC3339)")
	until := fs.String("until", "", "Restore messages deleted until this date (YYYY-MM-DD or RFC3339)")
	confirm := fs.Bool("confirm", false, "Confirm restoration without prompting")

	fs.Usage = func() {
		fmt.Printf(`Restore deleted messages to their original mailboxes

This command restores deleted (expunged) messages back to their original mailboxes.
If the original mailbox no longer exists, it will be recreated. Messages are
assigned new UIDs in their target mailboxes.

You can restore messages by:
  - Specific message IDs (--ids)
  - All messages from a mailbox (--mailbox)
  - Messages deleted within a time range (--since/--until)

Usage:
  sora-admin messages restore --email <email> [options]

Required Options:
  --email string        Email address of the account

Filter Options (choose one or combine):
  --ids string          Comma-separated list of message IDs to restore
  --mailbox string      Restore all deleted messages from this mailbox
  --since string        Restore messages deleted since this date (YYYY-MM-DD or RFC3339)
  --until string        Restore messages deleted until this date (YYYY-MM-DD or RFC3339)

Other Options:
  --confirm             Skip confirmation prompt
  --config string        Path to TOML configuration file (required)

Examples:
  # Restore specific messages by ID
  sora-admin messages restore --email user@example.com --ids 123,456,789 --confirm

  # Restore all deleted messages from INBOX
  sora-admin messages restore --email user@example.com --mailbox INBOX --confirm

  # Restore messages deleted in the last 24 hours
  sora-admin messages restore --email user@example.com --since $(date -u -d '1 day ago' '+%%Y-%%m-%%d') --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	// Validate required flags
	if *email == "" {
		fmt.Println("ERROR: --email is required")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Validate that at least one filter is provided
	if *ids == "" && *mailbox == "" && *since == "" && *until == "" {
		fmt.Println("ERROR: At least one filter option is required (--ids, --mailbox, --since, or --until)")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Parse message IDs if provided
	var messageIDs []int64
	if *ids != "" {
		parts := strings.Split(*ids, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			var id int64
			if _, err := fmt.Sscanf(part, "%d", &id); err != nil {
				logger.Fatalf("Invalid message ID '%s': %v", part, err)
			}
			messageIDs = append(messageIDs, id)
		}
	}

	// Parse time filters
	var sinceTime, untilTime *time.Time
	if *since != "" {
		t, err := parseTimeFlag(*since)
		if err != nil {
			logger.Fatalf("Invalid --since value: %v", err)
		}
		sinceTime = &t
	}
	if *until != "" {
		t, err := parseTimeFlag(*until)
		if err != nil {
			logger.Fatalf("Invalid --until value: %v", err)
		}
		untilTime = &t
	}

	// Restore messages
	if err := restoreMessages(ctx, globalConfig, *email, mailbox, messageIDs, sinceTime, untilTime, *confirm); err != nil {
		logger.Fatalf("Failed to restore messages: %v", err)
	}
}

func printMessagesUsage() {
	fmt.Printf(`Message Management

Usage:
  sora-admin messages <subcommand> [options]

Subcommands:
  list-deleted   List deleted (expunged) messages for an account
  restore        Restore deleted messages to their original mailboxes

Examples:
  sora-admin messages list-deleted --email user@example.com
  sora-admin messages list-deleted --email user@example.com --mailbox INBOX --since 2024-01-01
  sora-admin messages restore --email user@example.com --mailbox INBOX
  sora-admin messages restore --email user@example.com --ids 123,456,789

Use 'sora-admin messages <subcommand> --help' for detailed help.
`)
}

func listDeletedMessages(ctx context.Context, cfg AdminConfig, email string, mailbox *string, since *time.Time, until *time.Time, limit int) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Build parameters
	params := db.ListDeletedMessagesParams{
		Email: email,
		Limit: limit,
	}
	if mailbox != nil && *mailbox != "" {
		params.MailboxPath = mailbox
	}
	if since != nil {
		params.Since = since
	}
	if until != nil {
		params.Until = until
	}

	// List deleted messages
	messages, err := rdb.ListDeletedMessagesWithRetry(ctx, params)
	if err != nil {
		return err
	}

	if len(messages) == 0 {
		fmt.Println("No deleted messages found matching the criteria.")
		return nil
	}

	fmt.Printf("Found %d deleted message(s):\n\n", len(messages))

	// Print header
	fmt.Printf("%-10s %-20s %-40s %-50s %-20s\n",
		"ID", "Mailbox", "Message-ID", "Subject", "Deleted At")
	fmt.Printf("%-10s %-20s %-40s %-50s %-20s\n",
		"--", "-------", "----------", "-------", "----------")

	// Print message details
	for _, msg := range messages {
		subject := msg.Subject
		if len(subject) > 47 {
			subject = subject[:47] + "..."
		}

		messageID := msg.MessageID
		if len(messageID) > 37 {
			messageID = messageID[:37] + "..."
		}

		mailboxPath := msg.MailboxPath
		if len(mailboxPath) > 17 {
			mailboxPath = mailboxPath[:17] + "..."
		}

		fmt.Printf("%-10d %-20s %-40s %-50s %-20s\n",
			msg.ID,
			mailboxPath,
			messageID,
			subject,
			msg.ExpungedAt.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTotal deleted messages: %d\n", len(messages))

	if len(messages) == limit {
		fmt.Printf("Note: Result limited to %d messages. Use --limit to see more.\n", limit)
	}

	return nil
}

func restoreMessages(ctx context.Context, cfg AdminConfig, email string, mailbox *string, messageIDs []int64, since *time.Time, until *time.Time, confirm bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Build parameters
	params := db.RestoreMessagesParams{
		Email:      email,
		MessageIDs: messageIDs,
	}
	if mailbox != nil && *mailbox != "" {
		params.MailboxPath = mailbox
	}
	if since != nil {
		params.Since = since
	}
	if until != nil {
		params.Until = until
	}

	// If not confirmed, show what will be restored and ask for confirmation
	if !confirm {
		// First, list what will be restored
		listParams := db.ListDeletedMessagesParams{
			Email: email,
			Limit: 0, // no limit for preview
		}
		if mailbox != nil && *mailbox != "" {
			listParams.MailboxPath = mailbox
		}
		if since != nil {
			listParams.Since = since
		}
		if until != nil {
			listParams.Until = until
		}

		messages, err := rdb.ListDeletedMessagesWithRetry(ctx, listParams)
		if err != nil {
			return fmt.Errorf("failed to preview messages: %w", err)
		}

		// Filter by message IDs if provided
		if len(messageIDs) > 0 {
			idMap := make(map[int64]bool)
			for _, id := range messageIDs {
				idMap[id] = true
			}

			var filtered []db.DeletedMessage
			for _, msg := range messages {
				if idMap[msg.ID] {
					filtered = append(filtered, msg)
				}
			}
			messages = filtered
		}

		if len(messages) == 0 {
			fmt.Println("No messages found matching the criteria.")
			return nil
		}

		fmt.Printf("The following %d message(s) will be restored:\n\n", len(messages))
		for i, msg := range messages {
			if i >= 10 {
				fmt.Printf("... and %d more messages\n", len(messages)-10)
				break
			}
			fmt.Printf("  ID: %d, Mailbox: %s, Subject: %s\n", msg.ID, msg.MailboxPath, msg.Subject)
		}

		fmt.Printf("\nContinue with restoration? (yes/no): ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" && strings.ToLower(response) != "y" {
			fmt.Println("Restoration cancelled.")
			return nil
		}
	}

	// Perform restoration
	count, err := rdb.RestoreMessagesWithRetry(ctx, params)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully restored %d message(s).\n", count)
	return nil
}

func parseTimeFlag(value string) (time.Time, error) {
	// Try parsing as YYYY-MM-DD first
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid date format (use YYYY-MM-DD or RFC3339)")
}
