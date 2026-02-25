package main

// import_export.go - Command handlers for import/export
// Extracted from main.go for better organization

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/storage"
)

func handleImportCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printImportUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "maildir":
		handleImportMaildir(ctx)
	case "s3":
		handleImportS3(ctx)
	case "--help", "-h":
		printImportUsage()
	default:
		fmt.Printf("Unknown import subcommand: %s\n\n", subcommand)
		printImportUsage()
		os.Exit(1)
	}
}

func handleImportMaildir(ctx context.Context) {
	// Parse import specific flags
	fs := flag.NewFlagSet("import", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the account to import mail to (required)")
	maildirPath := fs.String("maildir-path", "", "Path to the maildir to import (required)")
	jobs := fs.Int("jobs", 4, "Number of parallel import jobs")
	batchSize := fs.Int("batch-size", 20, "Number of messages to process in each batch (default: 20)")
	batchTxMode := fs.Bool("batch-transaction", false, "Use single transaction per batch (20x faster but less resilient)")
	dryRun := fs.Bool("dry-run", false, "Preview what would be imported without making changes")
	preserveFlags := fs.Bool("preserve-flags", true, "Preserve maildir flags (Seen, Answered, etc)")
	showProgress := fs.Bool("progress", true, "Show import progress")
	delay := fs.Duration("delay", 0, "Delay between operations to control rate (e.g. 500ms)")
	forceReimport := fs.Bool("force-reimport", false, "Force reimport of messages even if they already exist")
	cleanupDB := fs.Bool("cleanup-db", false, "Remove the SQLite import database after successful import")
	dovecot := fs.Bool("dovecot", false, "Process Dovecot-specific files (subscriptions, keywords, uidlist)")
	sievePath := fs.String("sieve", "", "Path to Sieve script file to import for the user")
	preserveUIDs := fs.Bool("preserve-uids", false, "Preserve original UIDs from dovecot-uidlist files")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to import (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Import only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Import only messages before this date (YYYY-MM-DD)")
	incremental := fs.Bool("incremental", false, "Skip messages already marked as imported in SQLite cache")

	fs.Usage = func() {
		fmt.Printf(`Import maildir from a given path

Usage:
  sora-admin import maildir [options]

Options:
  --email string          Email address for the account to import mail to (required)
  --maildir-path string   Path to the maildir root directory (must contain cur/, new/, tmp/) (required)
  --jobs int              Number of parallel import jobs (default: 4)
  --batch-size int        Number of messages to process in each batch (default: 20)
  --batch-transaction     Use single transaction per batch (20x faster but less resilient, default: false)
  --dry-run               Preview what would be imported without making changes
  --preserve-flags        Preserve maildir flags (default: true)
  --progress              Show import progress (default: true)
  --delay duration        Delay between operations to control rate (e.g. 500ms)
  --force-reimport        Force reimport of messages even if they already exist
  --cleanup-db            Remove the SQLite import database after successful import
  --incremental           Skip messages already marked as imported in SQLite cache (default: false = read all)
  --dovecot               Process Dovecot-specific files (subscriptions, dovecot-keywords, dovecot-uidlist)
  --sieve string          Path to Sieve script file to import for the user
  --preserve-uids         Preserve original UIDs from dovecot-uidlist files (implied by --dovecot)
  --mailbox-filter string Comma-separated list of mailboxes to import (e.g. INBOX,Sent,Archive*)
  --start-date string     Import only messages after this date (YYYY-MM-DD)
  --end-date string       Import only messages before this date (YYYY-MM-DD)
  --config string        Path to TOML configuration file (required)

IMPORTANT: --maildir-path must point to a maildir root directory (containing cur/, new/, tmp/ subdirectories),
not to a parent directory containing multiple maildirs.

The --incremental flag controls whether to use the SQLite cache to skip already-imported messages:
  - Without --incremental (default): All files are read and processed every time
  - With --incremental: Only files not marked as imported in the SQLite cache are processed

Use --dovecot flag to process Dovecot-specific files including 'subscriptions', 'dovecot-keywords', and
'dovecot-uidlist'. This will create missing mailboxes, subscribe the user to specified folders, preserve
custom IMAP keywords/flags, and maintain original UIDs from dovecot-uidlist files.

Examples:
  # Import all mail (correct path points to maildir root)
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/example.com/user/Maildir

  # Incremental import (skip already imported messages based on SQLite cache)
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --incremental

  # Dry run to preview (note: correct maildir path)
  sora-admin import maildir --email user@example.com --maildir-path /home/user/Maildir --dry-run

  # Import only INBOX and Sent folders
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --mailbox-filter INBOX,Sent

  # Import messages from 2023
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --start-date 2023-01-01 --end-date 2023-12-31

  # Import with cleanup (removes SQLite database after completion)
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --cleanup-db

  # Import from Dovecot with subscriptions and custom keywords
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --dovecot

  # Import with Sieve script
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --sieve /path/to/user.sieve
`)
	}

	// Parse the remaining arguments (skip the command name and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *maildirPath == "" {
		fmt.Printf("Error: --maildir-path is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Parse date filters
	var startDateParsed, endDateParsed *time.Time
	if *startDate != "" {
		t, err := time.Parse("2006-01-02", *startDate)
		if err != nil {
			fmt.Printf("Error: Invalid start date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		startDateParsed = &t
	}
	if *endDate != "" {
		t, err := time.Parse("2006-01-02", *endDate)
		if err != nil {
			fmt.Printf("Error: Invalid end date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		// Add 23:59:59 to include the entire end date
		t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		endDateParsed = &t
	}

	// Parse mailbox filter
	var mailboxList []string
	if *mailboxFilter != "" {
		mailboxList = strings.Split(*mailboxFilter, ",")
		for i := range mailboxList {
			mailboxList[i] = strings.TrimSpace(mailboxList[i])
		}
	}

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	// NOTE: Importer supports TestMode, but the CLI normally requires S3 connectivity.
	// For integration tests (and some migration workflows), we allow skipping S3 by
	// setting SORA_ADMIN_SKIP_S3=1.
	var s3 *storage.S3Storage
	if os.Getenv("SORA_ADMIN_SKIP_S3") == "1" {
		logger.Info("S3 disabled via SORA_ADMIN_SKIP_S3=1")
		s3 = nil
	} else {
		s3, err = storage.New(globalConfig.S3.Endpoint, globalConfig.S3.AccessKey, globalConfig.S3.SecretKey, globalConfig.S3.Bucket, !globalConfig.S3.DisableTLS, globalConfig.S3.GetDebug())
		if err != nil {
			logger.Fatalf("Failed to connect to S3: %v", err)
		}
		if globalConfig.S3.Encrypt {
			if err := s3.EnableEncryption(globalConfig.S3.EncryptionKey); err != nil {
				logger.Fatalf("Failed to enable S3 encryption: %v", err)
			}
		}
	}

	// Get FTS retention from config
	ftsSourceRetention, err := globalConfig.Cleanup.GetFTSSourceRetention()
	if err != nil {
		logger.Fatalf("Failed to parse FTS retention: %v", err)
	}

	// Create importer options
	options := ImporterOptions{
		DryRun:               *dryRun,
		StartDate:            startDateParsed,
		EndDate:              endDateParsed,
		MailboxFilter:        mailboxList,
		PreserveFlags:        *preserveFlags,
		ShowProgress:         *showProgress,
		ForceReimport:        *forceReimport,
		CleanupDB:            *cleanupDB,
		Dovecot:              *dovecot,
		ImportDelay:          *delay,
		SievePath:            *sievePath,
		PreserveUIDs:         *preserveUIDs || *dovecot,
		FTSSourceRetention:   ftsSourceRetention,
		TestMode:             s3 == nil,
		BatchSize:            *batchSize,
		BatchTransactionMode: *batchTxMode,
		Incremental:          *incremental,
	}

	importer, err := NewImporter(ctx, *maildirPath, *email, *jobs, rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		logger.Fatalf("Failed to import maildir: %v", err)
	}
	os.Exit(0)
}

func handleImportS3(ctx context.Context) {
	// Define flag set for S3 import
	fs := flag.NewFlagSet("import s3", flag.ExitOnError)

	// Define flags
	email := fs.String("email", "", "Email address to import messages for")
	batchSize := fs.Int("batch-size", 1000, "Number of S3 objects to process in each batch")
	maxObjects := fs.Int("max-objects", 0, "Maximum number of objects to process (0 = unlimited)")
	workers := fs.Int("workers", 5, "Number of concurrent workers")
	dryRun := fs.Bool("dry-run", false, "Show what would be imported without making changes")
	showProgress := fs.Bool("show-progress", true, "Show import progress")
	forceReimport := fs.Bool("force-reimport", false, "Force reimport even if message already exists")
	cleanupDB := fs.Bool("cleanup-db", true, "Cleanup temporary database when done")
	importDelay := fs.Duration("import-delay", 0, "Delay between imports to control rate")
	continuationToken := fs.String("continuation-token", "", "S3 continuation token to resume from")

	// Parse the flags
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Failed to parse flags: %v", err)
	}

	// Validate required arguments
	// Validate required flags
	if *email == "" {
		logger.Fatal("--email is required (e.g., 'user@example.com')")
	}

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	s3, err := storage.New(globalConfig.S3.Endpoint, globalConfig.S3.AccessKey, globalConfig.S3.SecretKey, globalConfig.S3.Bucket, !globalConfig.S3.DisableTLS, globalConfig.S3.GetDebug())
	if err != nil {
		logger.Fatalf("Failed to connect to S3: %v", err)
	}
	if globalConfig.S3.Encrypt {
		if err := s3.EnableEncryption(globalConfig.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	// Configure S3 importer options
	options := S3ImporterOptions{
		Email:             *email,
		DryRun:            *dryRun,
		BatchSize:         *batchSize,
		MaxObjects:        *maxObjects,
		ShowProgress:      *showProgress,
		ForceReimport:     *forceReimport,
		CleanupDB:         *cleanupDB,
		ImportDelay:       *importDelay,
		ContinuationToken: *continuationToken,
		Workers:           *workers,
	}

	importer, err := NewS3Importer(rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create S3 importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		logger.Fatalf("Failed to import from S3: %v", err)
	}
	os.Exit(0)
}

func handleExportCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printExportUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "maildir":
		handleExportMaildir(ctx)
	case "--help", "-h":
		printExportUsage()
	default:
		fmt.Printf("Unknown export subcommand: %s\n\n", subcommand)
		printExportUsage()
		os.Exit(1)
	}
}

func handleExportMaildir(ctx context.Context) {
	// Parse export specific flags
	fs := flag.NewFlagSet("export", flag.ExitOnError)

	email := fs.String("email", "", "Email address for the account to export mail from (required)")
	maildirPath := fs.String("maildir-path", "", "Path where the maildir will be created/updated (required)")
	jobs := fs.Int("jobs", 4, "Number of parallel export jobs")
	dryRun := fs.Bool("dry-run", false, "Preview what would be exported without making changes")
	showProgress := fs.Bool("progress", true, "Show export progress")
	delay := fs.Duration("delay", 0, "Delay between operations to control rate (e.g. 500ms)")
	dovecot := fs.Bool("dovecot", false, "Export Dovecot-specific files (subscriptions and dovecot-uidlist)")
	exportUIDList := fs.Bool("export-dovecot-uidlist", false, "Export dovecot-uidlist files with UID mappings")
	overwriteFlags := fs.Bool("overwrite-flags", false, "Update flags on existing messages")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to export (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Export only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Export only messages before this date (YYYY-MM-DD)")

	fs.Usage = func() {
		fmt.Printf(`Export messages to maildir format

Usage:
  sora-admin export maildir [options]

Options:
  --email string          Email address for the account to export mail from (required)
  --maildir-path string   Path where the maildir will be created/updated (required)
  --jobs int              Number of parallel export jobs (default: 4)
  --dry-run               Preview what would be exported without making changes
  --progress              Show export progress (default: true)
  --delay duration        Delay between operations to control rate (e.g. 500ms)
  --dovecot               Export Dovecot-specific files (subscriptions, dovecot-uidlist)
  --export-dovecot-uidlist Export dovecot-uidlist files with UID mappings (implied by --dovecot)
  --overwrite-flags       Update flags on existing messages (default: false)
  --mailbox-filter string Comma-separated list of mailboxes to export (e.g. INBOX,Sent,Archive*)
  --start-date string     Export only messages after this date (YYYY-MM-DD)
  --end-date string       Export only messages before this date (YYYY-MM-DD)
  --config string        Path to TOML configuration file (required)

The exporter creates a SQLite database (sora-export.db) in the maildir path to track
exported messages and avoid duplicates. If exporting to an existing maildir, messages
with the same content hash will be skipped unless --overwrite-flags is specified.

Examples:
  # Export all mail to a new maildir
  sora-admin export maildir --email user@example.com --maildir-path /var/backup/user/Maildir

  # Export only INBOX and Sent folders
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --mailbox-filter INBOX,Sent

  # Export with Dovecot metadata (includes dovecot-uidlist files)
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --dovecot
  
  # Export with only dovecot-uidlist files (no subscriptions)
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --export-dovecot-uidlist

  # Update flags on existing messages
  sora-admin export maildir --email user@example.com --maildir-path /existing/maildir --overwrite-flags
`)
	}

	// Parse the remaining arguments (skip the command name and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *maildirPath == "" {
		fmt.Printf("Error: --maildir-path is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Parse date filters
	var startDateParsed, endDateParsed *time.Time
	if *startDate != "" {
		t, err := time.Parse("2006-01-02", *startDate)
		if err != nil {
			fmt.Printf("Error: Invalid start date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		startDateParsed = &t
	}
	if *endDate != "" {
		t, err := time.Parse("2006-01-02", *endDate)
		if err != nil {
			fmt.Printf("Error: Invalid end date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		// Add 23:59:59 to include the entire end date
		t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		endDateParsed = &t
	}

	// Parse mailbox filter
	var mailboxList []string
	if *mailboxFilter != "" {
		mailboxList = strings.Split(*mailboxFilter, ",")
		for i := range mailboxList {
			mailboxList[i] = strings.TrimSpace(mailboxList[i])
		}
	}

	// Connect to resilient database
	rdb, err := newAdminDatabase(ctx, &globalConfig.Database)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	s3, err := storage.New(globalConfig.S3.Endpoint, globalConfig.S3.AccessKey, globalConfig.S3.SecretKey, globalConfig.S3.Bucket, !globalConfig.S3.DisableTLS, globalConfig.S3.GetDebug())
	if err != nil {
		logger.Fatalf("Failed to connect to S3: %v", err)
	}
	if globalConfig.S3.Encrypt {
		if err := s3.EnableEncryption(globalConfig.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	// If dovecot flag is enabled, also enable UID list export
	exportUIDListEnabled := *exportUIDList || *dovecot

	// Create exporter options
	options := ExporterOptions{
		DryRun:         *dryRun,
		StartDate:      startDateParsed,
		EndDate:        endDateParsed,
		MailboxFilter:  mailboxList,
		ShowProgress:   *showProgress,
		Dovecot:        *dovecot,
		OverwriteFlags: *overwriteFlags,
		ExportDelay:    *delay,
		ExportUIDList:  exportUIDListEnabled,
	}

	exporter, err := NewExporter(ctx, *maildirPath, *email, *jobs, rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create exporter: %v", err)
	}

	if err := exporter.Run(); err != nil {
		logger.Fatalf("Failed to export maildir: %v", err)
	}
	os.Exit(0)
}

func printImportUsage() {
	fmt.Printf(`Import Management

Usage:
  sora-admin import <subcommand> [options]

Subcommands:
  maildir        Import maildir data
  s3             Import messages from S3 storage (recovery scenario)
  fix-subscriptions  Fix subscription status for default mailboxes

Examples:
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir
  sora-admin import maildir --email user@example.com --maildir-path /home/user/Maildir --dry-run
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --dovecot
  sora-admin import s3 --email user@example.com --dry-run
  sora-admin import s3 --email user@example.com --workers 5 --batch-size 500

Use 'sora-admin import <subcommand> --help' for detailed help.
`)
}

func printExportUsage() {
	fmt.Printf(`Export Management

Usage:
  sora-admin export <subcommand> [options]

Subcommands:
  maildir  Export messages to maildir format

Examples:
  sora-admin export maildir --email user@example.com --maildir-path /var/backup/user/Maildir
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --mailbox-filter INBOX,Sent
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --dovecot

Use 'sora-admin export <subcommand> --help' for detailed help.
`)
}
