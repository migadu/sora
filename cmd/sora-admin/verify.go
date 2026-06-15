package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

func handleVerifyCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printVerifyUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "s3":
		handleVerifyS3(ctx)
	case "hash":
		handleVerifyHash(ctx)
	case "help", "--help", "-h":
		printVerifyUsage()
	default:
		fmt.Printf("Unknown verify subcommand: %s\n\n", subcommand)
		printVerifyUsage()
		os.Exit(1)
	}
}

func printVerifyUsage() {
	fmt.Printf(`Verification Commands

Usage:
  sora-admin verify <subcommand> [options]

Subcommands:
  s3       Verify S3 storage consistency for a user
  hash     Verify a specific content hash exists in S3 and is intact (download + decrypt + re-hash)

Examples:
  sora-admin verify s3 --email user@example.com --config config.toml
  sora-admin verify s3 --email user@example.com --show-missing
  sora-admin verify s3 --email user@example.com --fix-orphaned --dry-run
  sora-admin verify hash --hash 31feeacf... --email user@example.com --config config.toml

Use 'sora-admin verify <subcommand> --help' for detailed help.
`)
}

func handleVerifyS3(ctx context.Context) {
	// Parse verify s3 specific flags
	fs := flag.NewFlagSet("verify s3", flag.ExitOnError)

	email := fs.String("email", "", "Email address to verify (required)")
	showMissing := fs.Bool("show-missing", false, "Show detailed list of missing/orphaned objects")
	fixOrphaned := fs.Bool("fix-orphaned", false, "Delete orphaned S3 objects not in DB")
	fixMissing := fs.Bool("fix-missing", false, "Mark DB messages with missing S3 objects as not uploaded")
	dryRun := fs.Bool("dry-run", false, "Report issues without making changes")
	batchSize := fs.Int("batch-size", 1000, "Number of messages to check in each batch")

	fs.Usage = func() {
		fmt.Printf(`Verify S3 storage consistency for a user

Usage:
  sora-admin verify s3 --email <email> --config <config> [options]

Options:
  --email string       Email address to verify (required)
  --config string      Path to TOML configuration file (required)
  --show-missing       Show detailed list of missing/orphaned objects
  --fix-orphaned       Delete orphaned S3 objects not in DB
  --fix-missing        Mark DB messages with missing S3 objects as not uploaded
  --dry-run            Report issues without making changes
  --batch-size int     Number of messages to check in each batch (default: 1000)

This command performs bidirectional verification:
  1. DB → S3: Checks that all database messages exist in S3
  2. S3 → DB: Checks that all S3 objects exist in the database

Examples:
  # Basic verification (read-only)
  sora-admin verify s3 --email user@example.com --config config.toml

  # Show detailed information about missing objects
  sora-admin verify s3 --email user@example.com --show-missing --config config.toml

  # Preview fixes without applying them
  sora-admin verify s3 --email user@example.com --fix-orphaned --dry-run --config config.toml

  # Actually delete orphaned S3 objects
  sora-admin verify s3 --email user@example.com --fix-orphaned --config config.toml
`)
	}

	// Parse the remaining arguments
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Run verification
	if err := verifyS3Storage(ctx, globalConfig, *email, *showMissing, *fixOrphaned, *fixMissing, *dryRun, *batchSize); err != nil {
		logger.Fatalf("Verification failed: %v", err)
	}
}

type verificationResult struct {
	MessagesInDB  int
	ObjectsInS3   int
	MissingFromS3 []string
	OrphanedInS3  []string
	CheckedDBToS3 int
	CheckedS3ToDB int
	FixedOrphaned int
	FixedMissing  int
}

func verifyS3Storage(ctx context.Context, cfg AdminConfig, email string, showMissing, fixOrphaned, fixMissing, dryRun bool, batchSize int) error {
	startTime := time.Now()

	// Initialize database
	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer rdb.Close()

	// Initialize S3 storage
	s3Timeout, err := cfg.S3.GetTimeout()
	if err != nil {
		return fmt.Errorf("invalid S3 timeout configuration: %w", err)
	}

	s3Storage, err := storage.New(
		cfg.S3.Endpoint,
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		cfg.S3.Bucket,
		!cfg.S3.DisableTLS, // useSSL = !DisableTLS
		false,              // no debug
		s3Timeout,          // timeout
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// Enable encryption if configured
	if cfg.S3.Encrypt {
		if err := s3Storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			return fmt.Errorf("failed to enable encryption: %w", err)
		}
	}

	fmt.Printf("Verifying S3 consistency for %s...\n\n", email)

	// Get account ID
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find account: %w", err)
	}

	result := &verificationResult{}

	// Phase 1: Check DB → S3 (messages exist in S3)
	fmt.Printf("[1/2] Checking DB → S3 (messages exist in S3)...\n")
	if err := checkDBToS3(ctx, rdb, s3Storage, accountID, result, batchSize); err != nil {
		return fmt.Errorf("DB → S3 check failed: %w", err)
	}
	fmt.Printf("  ✓ Checked %d messages\n", result.CheckedDBToS3)
	if len(result.MissingFromS3) > 0 {
		fmt.Printf("  ✗ %d missing from S3\n", len(result.MissingFromS3))
	}
	fmt.Println()

	// Phase 2: Check S3 → DB (objects exist in DB)
	fmt.Printf("[2/2] Checking S3 → DB (objects exist in DB)...\n")
	if err := checkS3ToDB(ctx, rdb, s3Storage, accountID, email, result); err != nil {
		return fmt.Errorf("S3 → DB check failed: %w", err)
	}
	fmt.Printf("  ✓ Found %d S3 objects\n", result.ObjectsInS3)
	if len(result.OrphanedInS3) > 0 {
		fmt.Printf("  ✗ %d orphaned objects (not in DB)\n", len(result.OrphanedInS3))
	}
	fmt.Println()

	// Apply fixes if requested
	if (fixOrphaned || fixMissing) && !dryRun {
		fmt.Printf("Applying fixes...\n")
		if err := applyFixes(ctx, rdb, s3Storage, result, fixOrphaned, fixMissing); err != nil {
			return fmt.Errorf("failed to apply fixes: %w", err)
		}
		fmt.Println()
	}

	// Print summary
	printVerificationSummary(result, showMissing, dryRun, fixOrphaned, fixMissing, startTime)

	// Exit with error code if issues found
	if len(result.MissingFromS3) > 0 || len(result.OrphanedInS3) > 0 {
		if !fixOrphaned && !fixMissing {
			fmt.Printf("\n⚠️  Issues found. Run with --show-missing to see details or --fix-orphaned/--fix-missing to repair.\n")
		}
		return nil // Don't return error, we've printed the issues
	}

	fmt.Printf("\n✓ No issues found. S3 storage is consistent.\n")
	return nil
}

func checkDBToS3(ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage *storage.S3Storage, accountID int64, result *verificationResult, batchSize int) error {
	// Get all messages for the user
	messages, err := rdb.GetAllMessagesForUserVerificationWithRetry(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	result.MessagesInDB = len(messages)
	result.CheckedDBToS3 = len(messages)

	// Check each message exists in S3 (in batches for better performance)
	for i := 0; i < len(messages); i += batchSize {
		end := i + batchSize
		if end > len(messages) {
			end = len(messages)
		}

		batch := messages[i:end]
		for _, msg := range batch {
			exists, _, err := s3Storage.Exists(msg.S3Key)
			if err != nil {
				return fmt.Errorf("failed to check S3 key %s: %w", msg.S3Key, err)
			}
			if !exists {
				result.MissingFromS3 = append(result.MissingFromS3, msg.S3Key)
			}
		}
	}

	return nil
}

func checkS3ToDB(ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage *storage.S3Storage, accountID int64, email string, result *verificationResult) error {
	// Parse email to get domain and localpart
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format: %s", email)
	}
	localpart := parts[0]
	domain := parts[1]

	// Construct S3 prefix for the user
	prefix := fmt.Sprintf("%s/%s/", domain, localpart)

	// Get all DB messages for quick lookup
	messages, err := rdb.GetAllMessagesForUserVerificationWithRetry(ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	// Create a map for fast lookup
	dbKeys := make(map[string]bool, len(messages))
	for _, msg := range messages {
		dbKeys[msg.S3Key] = true
	}

	// List all S3 objects with the prefix
	objectCh, errCh := s3Storage.ListObjects(ctx, prefix, true)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("S3 list error: %w", err)
			}
		case object, ok := <-objectCh:
			if !ok {
				return nil // Done
			}

			result.ObjectsInS3++

			// Check if this S3 key exists in the database
			if !dbKeys[object.Key] {
				result.OrphanedInS3 = append(result.OrphanedInS3, object.Key)
			}
		}
	}
}

func applyFixes(ctx context.Context, rdb *resilient.ResilientDatabase, s3Storage *storage.S3Storage, result *verificationResult, fixOrphaned, fixMissing bool) error {
	var wg sync.WaitGroup
	errors := make(chan error, 2)

	// Fix orphaned S3 objects
	if fixOrphaned && len(result.OrphanedInS3) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("  Deleting %d orphaned S3 objects...\n", len(result.OrphanedInS3))
			for _, key := range result.OrphanedInS3 {
				if err := s3Storage.Delete(key); err != nil {
					errors <- fmt.Errorf("failed to delete S3 key %s: %w", key, err)
					return
				}
				result.FixedOrphaned++
			}
			fmt.Printf("  ✓ Deleted %d orphaned objects\n", result.FixedOrphaned)
		}()
	}

	// Fix missing S3 objects (mark as not uploaded in DB)
	if fixMissing && len(result.MissingFromS3) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fmt.Printf("  Marking %d messages as not uploaded...\n", len(result.MissingFromS3))

			rowsAffected, err := rdb.MarkMessagesAsNotUploadedWithRetry(ctx, result.MissingFromS3)
			if err != nil {
				errors <- fmt.Errorf("failed to mark messages as not uploaded: %w", err)
				return
			}

			result.FixedMissing = int(rowsAffected)
			fmt.Printf("  ✓ Marked %d messages as not uploaded\n", result.FixedMissing)
		}()
	}

	// Wait for all fixes to complete
	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		if err != nil {
			return err
		}
	}

	return nil
}

func printVerificationSummary(result *verificationResult, showMissing, dryRun, fixOrphaned, fixMissing bool, startTime time.Time) {
	fmt.Printf("Summary:\n")
	fmt.Printf("  Messages in DB:        %d\n", result.MessagesInDB)
	fmt.Printf("  Objects in S3:         %d\n", result.ObjectsInS3)
	fmt.Printf("  Missing from S3:       %d\n", len(result.MissingFromS3))
	fmt.Printf("  Orphaned in S3:        %d\n", len(result.OrphanedInS3))

	if fixOrphaned || fixMissing {
		if dryRun {
			fmt.Printf("\n  [DRY RUN] No changes were made\n")
			if fixOrphaned {
				fmt.Printf("  Would delete:          %d orphaned objects\n", len(result.OrphanedInS3))
			}
			if fixMissing {
				fmt.Printf("  Would mark:            %d messages as not uploaded\n", len(result.MissingFromS3))
			}
		} else {
			if result.FixedOrphaned > 0 {
				fmt.Printf("  Fixed orphaned:        %d\n", result.FixedOrphaned)
			}
			if result.FixedMissing > 0 {
				fmt.Printf("  Fixed missing:         %d\n", result.FixedMissing)
			}
		}
	}

	fmt.Printf("\n  Duration:              %s\n", time.Since(startTime).Round(time.Millisecond))

	// Show detailed missing objects if requested
	if showMissing {
		if len(result.MissingFromS3) > 0 {
			fmt.Printf("\nMissing from S3:\n")
			for _, key := range result.MissingFromS3 {
				fmt.Printf("  - %s\n", key)
			}
		}

		if len(result.OrphanedInS3) > 0 {
			fmt.Printf("\nOrphaned in S3:\n")
			for i, key := range result.OrphanedInS3 {
				if i >= 100 {
					fmt.Printf("  ... and %d more (use --json for full list)\n", len(result.OrphanedInS3)-100)
					break
				}
				fmt.Printf("  - %s\n", key)
			}
		}
	}
}

// verifyS3Content downloads the full object body, decrypts it (storage.Get
// handles decryption transparently when client-side encryption is enabled),
// and verifies that the BLAKE3 hash of the content matches the expected hash
// embedded in the S3 key. It returns an error if the body cannot be fully
// read (truncation → "unexpected EOF"), decryption fails (GCM auth failure on
// a corrupt tail), or the recomputed hash does not match.
func verifyS3Content(s3Storage *storage.S3Storage, s3Key, expectedHash string) error {
	reader, err := s3Storage.Get(s3Key)
	if err != nil {
		return fmt.Errorf("download/decrypt failed: %w", err)
	}
	defer reader.Close()

	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read failed: %w", err)
	}

	fmt.Printf("  Size: %d bytes (decrypted)\n", len(content))

	actualHash := helpers.HashContent(content)
	if actualHash != expectedHash {
		return fmt.Errorf("BLAKE3 mismatch: content hashes to %s (object is corrupt)", actualHash)
	}
	return nil
}

func handleVerifyHash(ctx context.Context) {
	// Parse verify hash specific flags
	fs := flag.NewFlagSet("verify hash", flag.ExitOnError)

	hash := fs.String("hash", "", "Content hash to verify (required)")
	email := fs.String("email", "", "Email address (required)")
	showDetails := fs.Bool("details", false, "Show detailed information about messages using this hash")
	skipDB := fs.Bool("skip-db", false, "Verify S3 content only, without connecting to the database")

	fs.Usage = func() {
		fmt.Printf(`Verify if a specific content hash exists in S3

Usage:
  sora-admin verify hash --hash <hash> --email <email> --config <config> [options]

Options:
  --hash string       Content hash to verify (required)
  --email string      Email address for the account (required)
  --config string     Path to TOML configuration file (required)
  --details           Show detailed information about messages using this hash
  --skip-db           Verify S3 content only, without connecting to the database

This command checks:
  1. If the content hash exists in S3 (HEAD)
  2. That the full object body downloads, decrypts, and re-hashes to the
     expected BLAKE3 hash (catches truncated/corrupt objects that pass HEAD
     but fail on read with "unexpected EOF")
  3. Which messages in the database reference this hash
  4. Upload status of messages with this hash

The S3 key is derived entirely from --email and --hash, so steps 1-2 need no
database. Steps 3-4 are best-effort: if the database is unreachable (or
--skip-db is given) they are skipped and S3 verification still runs.

Examples:
  # Check if hash exists and is intact
  sora-admin verify hash --hash 31feeacf2ac918697614eab56d70098ed08fd44b6ab3a6a6726785128989402b --email user@example.com --config config.toml

  # Verify S3 content only, no database connection
  sora-admin verify hash --hash 31feeacf... --email user@example.com --skip-db --config config.toml

  # Show detailed message information
  sora-admin verify hash --hash 31feeacf... --email user@example.com --details --config config.toml
`)
	}

	// Parse the remaining arguments
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *hash == "" {
		fmt.Printf("Error: --hash is required\n\n")
		fs.Usage()
		os.Exit(1)
	}
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Run verification
	if err := verifyContentHash(ctx, globalConfig, *hash, *email, *showDetails, *skipDB); err != nil {
		logger.Fatalf("Verification failed: %v", err)
	}
}

func verifyContentHash(ctx context.Context, cfg AdminConfig, hash, email string, showDetails, skipDB bool) error {
	// Parse email to get domain and localpart. The S3 key is derived entirely
	// from this and the hash — no database lookup is required to verify the
	// object itself.
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email format: %s", email)
	}
	localpart := parts[0]
	domain := parts[1]
	s3Key := fmt.Sprintf("%s/%s/%s", domain, localpart, hash)

	// Initialize S3 storage
	s3Timeout, err := cfg.S3.GetTimeout()
	if err != nil {
		return fmt.Errorf("invalid S3 timeout configuration: %w", err)
	}

	s3Storage, err := storage.New(
		cfg.S3.Endpoint,
		cfg.S3.AccessKey,
		cfg.S3.SecretKey,
		cfg.S3.Bucket,
		!cfg.S3.DisableTLS,
		false,
		s3Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 storage: %w", err)
	}

	// Enable encryption if configured
	if cfg.S3.Encrypt {
		if err := s3Storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			return fmt.Errorf("failed to enable encryption: %w", err)
		}
	}

	fmt.Printf("Checking content hash: %s\n", hash)
	fmt.Printf("Account: %s\n", email)
	fmt.Printf("S3 Key: %s\n\n", s3Key)

	// Check if exists in S3. This is only a HEAD request — it confirms the key
	// is indexed by the provider, NOT that the body is fully readable. The
	// second return value is the object's version ID (the native file ID on
	// Backblaze B2), not its size.
	exists, versionID, err := s3Storage.Exists(s3Key)
	if err != nil {
		return fmt.Errorf("failed to check S3: %w", err)
	}

	// contentIntact tracks whether the deep verification (download + decrypt +
	// re-hash) succeeded. It stays true when the object is absent so the
	// existing "missing" branches in the summary remain authoritative.
	contentIntact := true

	if !exists {
		fmt.Printf("✗ Content MISSING from S3\n")
	} else {
		fmt.Printf("✓ Content EXISTS in S3 (HEAD ok)\n")
		if versionID != "" {
			fmt.Printf("  Version ID: %s\n", versionID)
		}

		// Deep verification: a clean HEAD does not prove the body is intact.
		// Truncated or corrupt objects (e.g. an incomplete B2 large-file
		// upload) pass HEAD but fail on GET with a short read, decryption
		// failure, or hash mismatch — this is the check that actually catches
		// the "unexpected EOF" failures seen when fetching messages.
		if err := verifyS3Content(s3Storage, s3Key, hash); err != nil {
			contentIntact = false
			fmt.Printf("  ✗ Content verification FAILED: %v\n", err)
		} else {
			fmt.Printf("  ✓ Content verified: full body downloaded, decrypted, BLAKE3 matches\n")
		}
	}

	// The S3 verification above is complete and required no database. The
	// remaining DB cross-reference (which messages use this hash, upload status)
	// is best-effort: it is skipped on --skip-db or if the database is
	// unreachable, so a storage-only node can still verify object integrity.
	if skipDB {
		fmt.Printf("\nDatabase cross-reference skipped (--skip-db).\n")
		printS3OnlySummary(exists, contentIntact)
		return nil
	}

	rdb, err := newAdminDatabase(ctx, &cfg.Database)
	if err != nil {
		fmt.Printf("\n⚠️  Database unavailable, skipping message cross-reference: %v\n", err)
		printS3OnlySummary(exists, contentIntact)
		return nil
	}
	defer rdb.Close()

	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		return fmt.Errorf("failed to find account: %w", err)
	}

	// Get messages with this hash from database
	messages, err := rdb.GetMessagesByContentHashWithRetry(ctx, accountID, hash)
	if err != nil {
		return fmt.Errorf("failed to query messages: %w", err)
	}

	fmt.Printf("\nDatabase messages using this hash: %d\n", len(messages))

	if len(messages) == 0 {
		fmt.Printf("  (No messages found in database)\n")
		if exists {
			fmt.Printf("\n⚠️  WARNING: Orphaned S3 object (exists in S3 but not in DB)\n")
		}
		return nil
	}

	// Count uploaded vs not uploaded
	uploaded := 0
	notUploaded := 0
	for _, msg := range messages {
		if msg.Uploaded {
			uploaded++
		} else {
			notUploaded++
		}
	}

	fmt.Printf("  Uploaded: %d\n", uploaded)
	fmt.Printf("  Not uploaded: %d\n", notUploaded)

	// Show detailed information if requested
	if showDetails {
		fmt.Printf("\nDetailed message information:\n")
		fmt.Printf("%-10s %-20s %-15s %-10s %s\n", "ID", "Mailbox", "UID", "Uploaded", "Subject")
		fmt.Printf("%s\n", strings.Repeat("-", 100))
		for _, msg := range messages {
			uploadStatus := "FALSE"
			if msg.Uploaded {
				uploadStatus = "TRUE"
			}
			subject := msg.Subject
			if len(subject) > 40 {
				subject = subject[:37] + "..."
			}
			fmt.Printf("%-10d %-20s %-15d %-10s %s\n",
				msg.ID, msg.MailboxPath, msg.UID, uploadStatus, subject)
		}
	}

	// Summary and recommendations
	fmt.Printf("\nSummary:\n")
	if exists && !contentIntact {
		fmt.Printf("✗ CRITICAL: Object exists in S3 but its body is corrupt or unreadable\n")
		fmt.Printf("  HEAD succeeds but the full body cannot be downloaded/decrypted or fails the hash check.\n")
		fmt.Printf("  Users will get errors (e.g. \"unexpected EOF\") trying to read these messages.\n")
		fmt.Printf("  The S3 object must be re-uploaded from the original source, or the messages deleted.\n")
	} else if exists && uploaded > 0 {
		fmt.Printf("✓ Everything looks good\n")
	} else if !exists && notUploaded > 0 {
		fmt.Printf("✗ Problem detected: Content missing from S3 and messages marked as not uploaded\n")
		fmt.Printf("  This likely indicates stuck uploads from the race condition bug\n")
		fmt.Printf("  Safe to delete these messages (content was never successfully stored)\n")
	} else if !exists && uploaded > 0 {
		fmt.Printf("✗ CRITICAL: Messages marked as uploaded but content missing from S3\n")
		fmt.Printf("  Users will get errors trying to read these messages\n")
		fmt.Printf("  Need to either restore S3 content or delete messages\n")
	} else if exists && notUploaded > 0 {
		fmt.Printf("⚠️  Content exists in S3 but messages marked as not uploaded\n")
		fmt.Printf("  Can fix by marking messages as uploaded:\n")
		fmt.Printf("  UPDATE messages SET uploaded = TRUE WHERE content_hash = '%s' AND account_id = %d;\n", hash, accountID)
	}

	return nil
}

// printS3OnlySummary prints a verdict for the S3-only case, where no database
// cross-reference was performed (--skip-db or DB unavailable).
func printS3OnlySummary(exists, contentIntact bool) {
	fmt.Printf("\nSummary:\n")
	switch {
	case exists && contentIntact:
		fmt.Printf("✓ S3 object exists and its content is intact (downloaded, decrypted, BLAKE3 verified)\n")
	case exists && !contentIntact:
		fmt.Printf("✗ CRITICAL: Object exists in S3 but its body is corrupt or unreadable\n")
		fmt.Printf("  HEAD succeeds but the full body cannot be downloaded/decrypted or fails the hash check.\n")
		fmt.Printf("  Users will get errors (e.g. \"unexpected EOF\") trying to read these messages.\n")
		fmt.Printf("  The S3 object must be re-uploaded from the original source, or the messages deleted.\n")
	default:
		fmt.Printf("✗ Content MISSING from S3\n")
	}
}
