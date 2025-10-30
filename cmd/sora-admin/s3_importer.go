package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"github.com/migadu/sora/logger"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
	"github.com/minio/minio-go/v7"
	_ "modernc.org/sqlite"
)

// S3ImporterOptions contains configuration options for the S3 importer
type S3ImporterOptions struct {
	Email             string // Email address to import messages for
	DryRun            bool
	BatchSize         int // Number of S3 objects to process in each batch
	MaxObjects        int // Maximum number of objects to process (0 = unlimited)
	ShowProgress      bool
	ForceReimport     bool          // Force reimport even if message already exists
	CleanupDB         bool          // Cleanup temporary database when done
	ImportDelay       time.Duration // Delay between imports to control rate
	ContinuationToken string        // S3 continuation token to resume from
	Workers           int           // Number of concurrent workers
}

// S3Importer handles the S3 import process
type S3Importer struct {
	s3      *resilient.ResilientS3Storage
	rdb     *resilient.ResilientDatabase
	db      *sql.DB
	dbPath  string
	options S3ImporterOptions

	totalObjects     int64
	processedObjects int64
	importedMessages int64
	skippedMessages  int64
	failedMessages   int64
	startTime        time.Time

	// Progress tracking
	lastContinuationToken string
}

// S3ObjectInfo represents an S3 object found during scanning
type S3ObjectInfo struct {
	Key          string
	Size         int64
	LastModified time.Time
	ETag         string
}

// NewS3Importer creates a new S3Importer instance
func NewS3Importer(rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, options S3ImporterOptions) (*S3Importer, error) {
	// Wrap S3 storage with resilient patterns
	resilientS3 := resilient.NewResilientS3Storage(s3)
	// Create temporary SQLite database to track S3 objects
	tempDir := os.TempDir()
	dbPath := filepath.Join(tempDir, fmt.Sprintf("sora-s3-import-%d.db", time.Now().Unix()))
	logger.Info("Using temporary database", "path", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Create the table for storing S3 object information
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS s3_objects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			key TEXT NOT NULL UNIQUE,
			size INTEGER NOT NULL,
			last_modified TEXT NOT NULL,
			etag TEXT NOT NULL,
			processed BOOLEAN DEFAULT FALSE,
			success BOOLEAN DEFAULT FALSE,
			error_message TEXT,
			domain TEXT,
			local_part TEXT,
			content_hash TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_key ON s3_objects(key);
		CREATE INDEX IF NOT EXISTS idx_processed ON s3_objects(processed);
		CREATE INDEX IF NOT EXISTS idx_domain_localpart ON s3_objects(domain, local_part);
		CREATE INDEX IF NOT EXISTS idx_content_hash ON s3_objects(content_hash);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create s3_objects table: %w", err)
	}

	return &S3Importer{
		s3:        resilientS3,
		rdb:       rdb,
		db:        db,
		dbPath:    dbPath,
		options:   options,
		startTime: time.Now(),
	}, nil
}

// Close cleans up resources used by the importer
func (si *S3Importer) Close() error {
	if si.db != nil {
		if err := si.db.Close(); err != nil {
			return fmt.Errorf("failed to close s3 importer database: %w", err)
		}
		if si.options.CleanupDB {
			logger.Info("Cleaning up temporary database", "path", si.dbPath)
			if err := os.Remove(si.dbPath); err != nil {
				return fmt.Errorf("failed to remove temporary database file: %w", err)
			}
		} else {
			logger.Info("Temporary database saved", "path", si.dbPath)
		}
	}
	return nil
}

// Run starts the S3 import process
func (si *S3Importer) Run() error {
	defer si.Close()

	logger.Info("Starting S3 import process...")

	// Step 1: Scan S3 bucket for objects
	if err := si.scanS3Objects(); err != nil {
		return fmt.Errorf("failed to scan S3 objects: %w", err)
	}

	// Count total objects found
	var totalCount int64
	err := si.db.QueryRow("SELECT COUNT(*) FROM s3_objects").Scan(&totalCount)
	if err != nil {
		return fmt.Errorf("failed to count S3 objects: %w", err)
	}

	atomic.StoreInt64(&si.totalObjects, totalCount)
	logger.Info("Found S3 objects to process", "count", totalCount)

	if totalCount == 0 {
		logger.Info("No S3 objects found to import")
		return nil
	}

	if si.options.DryRun {
		logger.Info("DRY RUN: Analyzing what would be imported...")
		return si.performDryRun()
	}

	// Step 2: Process objects and import messages
	logger.Info("Starting import process", "count", totalCount)
	if err := si.importFromS3(); err != nil {
		return fmt.Errorf("failed to import from S3: %w", err)
	}

	return si.printSummary()
}

// scanS3Objects scans the S3 bucket and stores object information in the database
func (si *S3Importer) scanS3Objects() error {
	// Parse email address to get domain and local part
	address, err := server.NewAddress(si.options.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	// Construct S3 prefix from email address (same format as helpers.NewS3Key)
	s3Prefix := fmt.Sprintf("%s/%s/", address.Domain(), address.LocalPart())
	logger.Info("Scanning S3 bucket for user", "email", si.options.Email, "prefix", s3Prefix)

	ctx := context.Background()
	opts := minio.ListObjectsOptions{
		Prefix:       s3Prefix,
		Recursive:    true,
		MaxKeys:      1000, // Process in batches
		StartAfter:   si.options.ContinuationToken,
		WithMetadata: false,
	}

	objectCount := 0
	batchCount := 0

	for object := range si.s3.GetStorage().Client.ListObjects(ctx, si.s3.GetStorage().BucketName, opts) {
		if object.Err != nil {
			return fmt.Errorf("error listing S3 objects: %w", object.Err)
		}

		// Parse the S3 key to extract domain, local_part, and content_hash
		// Expected format: domain/local_part/content_hash
		parts := strings.Split(object.Key, "/")
		if len(parts) != 3 {
			logger.Info("Skipping S3 object with unexpected key format", "key", object.Key)
			continue
		}

		domain := parts[0]
		localPart := parts[1]
		contentHash := parts[2]

		// Validate that this matches our expected user
		expectedDomain := address.Domain()
		expectedLocalPart := address.LocalPart()
		if domain != expectedDomain || localPart != expectedLocalPart {
			logger.Info("Skipping S3 object for different user", "key", object.Key,
				"expected_email", fmt.Sprintf("%s@%s", expectedLocalPart, expectedDomain))
			continue
		}

		// Validate content hash format (should be hex)
		if len(contentHash) != 64 { // SHA256 hex string length
			logger.Info("Skipping S3 object with invalid hash format", "key", object.Key)
			continue
		}
		if _, err := hex.DecodeString(contentHash); err != nil {
			logger.Info("Skipping S3 object with non-hex hash", "key", object.Key)
			continue
		}

		// Store object information in SQLite
		_, err := si.db.Exec(`
			INSERT OR IGNORE INTO s3_objects 
			(key, size, last_modified, etag, domain, local_part, content_hash) 
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			object.Key, object.Size, object.LastModified.Format(time.RFC3339),
			object.ETag, domain, localPart, contentHash)
		if err != nil {
			return fmt.Errorf("failed to insert S3 object info: %w", err)
		}

		objectCount++
		if objectCount%1000 == 0 {
			logger.Info("Scanned S3 objects", "count", objectCount)
		}

		// Check if we've reached the maximum object limit
		if si.options.MaxObjects > 0 && objectCount >= si.options.MaxObjects {
			logger.Info("Reached maximum object limit", "max", si.options.MaxObjects)
			break
		}

		batchCount++
		if batchCount >= si.options.BatchSize {
			// Store continuation token for resumable operations
			si.lastContinuationToken = object.Key
			batchCount = 0
		}
	}

	logger.Info("Completed S3 scan", "count", objectCount)
	return nil
}

// performDryRun analyzes what would be imported without making changes
func (si *S3Importer) performDryRun() error {
	fmt.Printf("\n=== DRY RUN: S3 Import Analysis ===\n\n")
	fmt.Printf("Analyzing S3 messages for user: %s\n\n", si.options.Email)

	ctx := context.Background()

	// Parse email address for user lookup
	address, err := server.NewAddress(si.options.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	// Get account ID once
	accountID, err := si.rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", si.options.Email, err, si.options.Email)
	}
	user := server.NewUser(address, accountID)

	// Ensure default mailboxes exist for this user
	if err := si.rdb.CreateDefaultMailboxesWithRetry(ctx, user.UserID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", si.options.Email, "error", err)
		// Don't fail the dry run, as mailboxes might already exist
	}

	rows, err := si.db.Query(`
		SELECT key, size, domain, local_part, content_hash, last_modified
		FROM s3_objects 
		ORDER BY key
	`)
	if err != nil {
		return fmt.Errorf("failed to query S3 objects: %w", err)
	}
	defer rows.Close()

	var totalWouldImport, totalWouldSkip int64

	for rows.Next() {
		var key, domain, localPart, contentHash, lastModified string
		var size int64
		if err := rows.Scan(&key, &size, &domain, &localPart, &contentHash, &lastModified); err != nil {
			logger.Info("Failed to scan row", "error", err)
			continue
		}

		// Check if message already exists
		alreadyExists := false
		if !si.options.ForceReimport {
			// Check if any message with this content hash exists for this account
			var count int
			err = si.rdb.QueryRowWithRetry(ctx,
				"SELECT COUNT(*) FROM messages WHERE content_hash = $1 AND account_id = $2 AND expunged_at IS NULL",
				contentHash, accountID).Scan(&count)
			if err == nil && count > 0 {
				alreadyExists = true
			}
		}

		action := "IMPORT"
		reason := "new message"

		if alreadyExists {
			if si.options.ForceReimport {
				action = "REIMPORT"
				reason = "force reimport enabled"
			} else {
				action = "SKIP"
				reason = "already exists in database"
				totalWouldSkip++
			}
		}

		if action == "IMPORT" || action == "REIMPORT" {
			totalWouldImport++
		}

		// Format size
		sizeStr := formatBytesSize(size)

		fmt.Printf("  %s %s\n", action, filepath.Base(key))
		fmt.Printf("    Hash: %s | Size: %s | Date: %s\n",
			contentHash[:12]+"...", sizeStr, lastModified)
		fmt.Printf("    Action: %s (%s)\n", action, reason)
		fmt.Println()
	}

	// Overall summary
	fmt.Printf("\n=== DRY RUN: Overall Summary ===\n")
	fmt.Printf("User: %s\n", si.options.Email)
	fmt.Printf("Would import: %d messages\n", totalWouldImport)
	fmt.Printf("Would skip: %d messages\n", totalWouldSkip)
	fmt.Printf("Total S3 objects found: %d\n", atomic.LoadInt64(&si.totalObjects))

	fmt.Printf("\nRun without --dry-run to perform the actual import.\n")
	return nil
}

// importFromS3 processes S3 objects and imports messages into the database
func (si *S3Importer) importFromS3() error {
	if si.totalObjects == 0 {
		logger.Info("No S3 objects to import")
		return nil
	}

	logger.Info("Processing S3 objects", "count", si.totalObjects, "workers", si.options.Workers)

	rows, err := si.db.Query("SELECT key, size, domain, local_part, content_hash FROM s3_objects WHERE processed = FALSE")
	if err != nil {
		return fmt.Errorf("failed to query unprocessed S3 objects: %w", err)
	}
	defer rows.Close()

	var wg sync.WaitGroup
	jobs := make(chan S3ObjectInfo, 100) // Buffer for better performance

	// Start workers
	for w := 0; w < si.options.Workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for obj := range jobs {
				if err := si.importS3Object(obj); err != nil {
					logger.Info("Failed to import S3 object", "worker", workerID,
						"progress", si.getProgressPrefix(), "key", obj.Key, "error", err)
					atomic.AddInt64(&si.failedMessages, 1)
				}
				atomic.AddInt64(&si.processedObjects, 1)
			}
		}(w)
	}

	// Feed jobs to workers
	for rows.Next() {
		var key, domain, localPart, contentHash string
		var size int64
		if err := rows.Scan(&key, &size, &domain, &localPart, &contentHash); err != nil {
			logger.Info("Failed to scan row", "error", err)
			continue
		}

		jobs <- S3ObjectInfo{
			Key:  key,
			Size: size,
		}
	}

	close(jobs)
	wg.Wait()

	return nil
}

// importS3Object downloads and imports a single message from S3
func (si *S3Importer) importS3Object(obj S3ObjectInfo) error {
	// Parse the S3 key to extract content hash
	parts := strings.Split(obj.Key, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid S3 key format: %s", obj.Key)
	}

	contentHash := parts[2]

	ctx := context.Background()
	address, err := server.NewAddress(si.options.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := si.rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", si.options.Email, err, si.options.Email)
	}
	user := server.NewUser(address, accountID)

	// Proactively ensure default mailboxes exist for this user
	// This prevents "mailbox not found" errors during import
	if err := si.rdb.CreateDefaultMailboxesWithRetry(ctx, user.UserID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", si.options.Email, "error", err)
		// Don't fail the import, as mailboxes might already exist
	}

	// Check if message already exists
	if !si.options.ForceReimport {
		var count int
		err = si.rdb.QueryRowWithRetry(ctx,
			"SELECT COUNT(*) FROM messages WHERE content_hash = $1 AND account_id = $2 AND expunged_at IS NULL",
			contentHash, accountID).Scan(&count)
		if err == nil && count > 0 {
			logger.Info("Message already exists - skipping", "progress", si.getProgressPrefix(), "key", obj.Key)
			atomic.AddInt64(&si.skippedMessages, 1)
			si.markObjectProcessed(obj.Key, true, "already exists")
			return nil
		}
	}

	// Download message content from S3
	reader, err := si.s3.GetWithRetry(ctx, obj.Key)
	if err != nil {
		return fmt.Errorf("failed to download from S3: %w", err)
	}
	defer reader.Close()

	// Read content
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read S3 content: %w", err)
	}

	// Parse message
	messageContent, err := server.ParseMessage(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")

	if len(inReplyTo) == 0 {
		inReplyTo = nil
	}

	if sentDate.IsZero() {
		sentDate = time.Now()
	}

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(content))
	extractedPlaintext, err := helpers.ExtractPlaintextBody(messageContent)
	var actualPlaintextBody string
	if err == nil && extractedPlaintext != nil {
		actualPlaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	var rawHeadersText string
	headerEndIndex := bytes.Index(content, []byte("\r\n\r\n"))
	if headerEndIndex != -1 {
		rawHeadersText = string(content[:headerEndIndex])
	}

	// Import into INBOX by default (since we don't have mailbox information from S3)
	// Default mailboxes should already be created at this point
	mailbox, err := si.rdb.GetMailboxByNameWithRetry(ctx, user.UserID(), "INBOX")
	if err != nil {
		return fmt.Errorf("failed to get INBOX mailbox: %w", err)
	}

	// Insert message into database
	hostname, _ := os.Hostname()
	msgID, uid, err := si.rdb.InsertMessageWithRetry(ctx,
		&db.InsertMessageOptions{
			UserID:        user.UserID(),
			MailboxID:     mailbox.ID,
			S3Domain:      address.Domain(),
			S3Localpart:   address.LocalPart(),
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			MessageID:     messageID,
			Flags:         []imap.Flag{imap.Flag("\\Recent")}, // Mark as recent
			InternalDate:  sentDate,
			Size:          obj.Size,
			Subject:       subject,
			PlaintextBody: actualPlaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			BodyStructure: &bodyStructure,
			Recipients:    recipients,
			RawHeaders:    rawHeadersText,
		},
		db.PendingUpload{
			InstanceID:  hostname,
			ContentHash: contentHash,
			Size:        obj.Size,
			AccountID:   user.UserID(),
		})

	if err != nil {
		return fmt.Errorf("failed to insert message into database: %w", err)
	}

	// Since the content already exists in S3, mark the upload as complete
	err = si.rdb.CompleteS3UploadWithRetry(ctx, contentHash, user.UserID())
	if err != nil {
		return fmt.Errorf("failed to mark S3 upload as complete: %w", err)
	}

	atomic.AddInt64(&si.importedMessages, 1)
	logger.Info("Successfully imported message", "progress", si.getProgressPrefix(),
		"msg_id", msgID, "uid", uid, "user", address.FullAddress())

	si.markObjectProcessed(obj.Key, true, "imported successfully")

	// Add delay if configured
	if si.options.ImportDelay > 0 {
		time.Sleep(si.options.ImportDelay)
	}

	return nil
}

// markObjectProcessed updates the processing status of an S3 object in the database
func (si *S3Importer) markObjectProcessed(key string, success bool, errorMessage string) {
	_, err := si.db.Exec("UPDATE s3_objects SET processed = TRUE, success = ?, error_message = ? WHERE key = ?",
		success, errorMessage, key)
	if err != nil {
		logger.Info("Warning: Failed to mark object as processed", "error", err)
	}
}

// getProgressPrefix returns a progress prefix for log messages
func (si *S3Importer) getProgressPrefix() string {
	processed := atomic.LoadInt64(&si.processedObjects)
	imported := atomic.LoadInt64(&si.importedMessages)
	failed := atomic.LoadInt64(&si.failedMessages)
	skipped := atomic.LoadInt64(&si.skippedMessages)
	total := atomic.LoadInt64(&si.totalObjects)

	percentage := float64(processed) * 100.0 / float64(total)

	return fmt.Sprintf("[%d/%d %.1f%% | I:%d S:%d F:%d]",
		processed, total, percentage, imported, skipped, failed)
}

// printSummary prints a summary of the import process
func (si *S3Importer) printSummary() error {
	duration := time.Since(si.startTime)
	fmt.Printf("\n\nS3 Import Summary:\n")
	fmt.Printf("  Total S3 objects:     %d\n", si.totalObjects)
	fmt.Printf("  Processed:            %d\n", si.processedObjects)
	fmt.Printf("  Imported:             %d\n", si.importedMessages)
	fmt.Printf("  Skipped:              %d\n", si.skippedMessages)
	fmt.Printf("  Failed:               %d\n", si.failedMessages)
	fmt.Printf("  Duration:             %s\n", duration.Round(time.Second))
	if si.importedMessages > 0 {
		rate := float64(si.importedMessages) / duration.Seconds()
		fmt.Printf("  Import rate:          %.1f messages/sec\n", rate)
	}
	if si.lastContinuationToken != "" {
		fmt.Printf("  Last processed key:   %s\n", si.lastContinuationToken)
		fmt.Printf("  Resumption token:     %s\n", si.lastContinuationToken)
	}
	return nil
}

// formatBytesSize formats a byte count into human readable format
func formatBytesSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
