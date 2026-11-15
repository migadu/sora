package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/emersion/go-message/mail"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/pkg/sqlitefile"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
	_ "modernc.org/sqlite"
)

// S3ImporterOptions contains configuration options for the S3 importer
type S3ImporterOptions struct {
	Email             string // Email address to import messages for
	DryRun            bool
	BatchSize         int // Number of S3 objects to process in each batch
	MaxObjects        int // Maximum number of objects to process (0 = unlimited)
	ShowProgress      bool
	ForceReimport     bool          // Import into INBOX even when another mailbox of the account holds the message
	CleanupDB         bool          // Cleanup temporary database when done
	ImportDelay       time.Duration // Delay between imports to control rate
	ContinuationToken string        // S3 continuation token to resume from
	Workers           int           // Number of concurrent workers
	// InstanceID is the identity written to pending_uploads.instance_id, resolved by
	// config.Config.InstanceID so it matches what the server on this host writes. It is
	// a lease key: a row left behind under an id no running instance answers to is
	// reaped by the cleaner along with its message.
	InstanceID string
	// FTSRetention skips the search row for messages sent before this window (0 = index all).
	FTSRetention time.Duration
}

// s3ImportDB is the part of the database the S3 importer uses, satisfied by
// *resilient.ResilientDatabase.
type s3ImportDB interface {
	GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error)
	CreateDefaultMailboxesWithRetry(ctx context.Context, accountID int64) error
	QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row
	GetMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error)
	InsertMessageWithRetry(ctx context.Context, options *db.InsertMessageOptions, upload db.PendingUpload) (int64, int64, error)
	CompleteS3UploadWithRetry(ctx context.Context, hash string, accountID int64, writtenKeys []string) error
}

// S3Importer handles the S3 import process
type S3Importer struct {
	// ctx is the command's context, cancelled on SIGINT/SIGTERM: it stops the scan,
	// the dry run and the import.
	ctx     context.Context
	s3      *resilient.ResilientS3Storage
	rdb     s3ImportDB
	db      *sql.DB
	dbPath  string
	options S3ImporterOptions

	// user is the account the import is for. Run looks it up once (lookupAccount),
	// before it lists the bucket, and every step uses it from there.
	user *server.User

	totalObjects     int64
	processedObjects int64
	importedMessages int64
	skippedMessages  int64
	failedMessages   int64
	startTime        time.Time

	// Progress tracking
	lastContinuationToken string
}

// S3ObjectInfo represents an S3 object found during scanning. It carries no size:
// the listed size is the stored object's, which with S3 encryption on is the
// AES-256-GCM output and not the message; the message's size is its decrypted length.
type S3ObjectInfo struct {
	Key          string
	LastModified time.Time
	ETag         string
}

// s3ImportDBParams are the connection settings of the work database. importFromS3's
// workers mark their objects processed, each on a connection of its own, while the
// feeder reads keys: in WAL mode a read does not block a writer (on the rollback journal
// every UPDATE failed with SQLITE_BUSY while the feeder's read held its SHARED lock),
// and a worker that commits while another does waits up to 5 seconds for the lock.
const s3ImportDBParams = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// NewS3Importer creates a new S3Importer instance
func NewS3Importer(ctx context.Context, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, options S3ImporterOptions) (*S3Importer, error) {
	// importFromS3 runs on exactly this many workers: with none it would never drain its queue.
	if options.Workers < 1 {
		return nil, fmt.Errorf("workers must be at least 1, got %d", options.Workers)
	}
	// Wrap S3 storage with resilient patterns
	resilientS3 := resilient.NewResilientS3Storage(s3)
	// Create temporary SQLite database to track S3 objects. Every run gets a file of its
	// own, created exclusively and readable by its owner only (os.CreateTemp): importFromS3
	// imports every row in it into this run's account, so a run must never open another's.
	f, err := os.CreateTemp(os.TempDir(), "sora-s3-import-*.db")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary database: %w", err)
	}
	dbPath := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(dbPath)
		return nil, fmt.Errorf("failed to create temporary database: %w", err)
	}
	logger.Info("Using temporary database", "path", dbPath)

	dsn, err := sqlitefile.DSN(dbPath, s3ImportDBParams)
	if err != nil {
		os.Remove(dbPath)
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		os.Remove(dbPath)
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
		db.Close()
		os.Remove(dbPath)
		return nil, fmt.Errorf("failed to create s3_objects table: %w", err)
	}

	return &S3Importer{
		ctx:       ctx,
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

	// The account first: an import for an address without one would otherwise list
	// the whole prefix, then fail every object on a lookup of its own.
	if err := si.lookupAccount(); err != nil {
		return err
	}

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

// lookupAccount looks up the account the import is for and keeps it on the importer.
func (si *S3Importer) lookupAccount() error {
	address, err := server.NewAddress(si.options.Email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}
	accountID, err := si.rdb.GetAccountIDByAddressWithRetry(si.ctx, address.FullAddress())
	if err != nil {
		return accountLookupError(si.options.Email, err)
	}
	si.user = server.NewUser(address, accountID)
	return nil
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

	input := &s3.ListObjectsV2Input{
		Bucket:     aws.String(si.s3.GetStorage().BucketName),
		Prefix:     aws.String(s3Prefix),
		MaxKeys:    aws.Int32(1000), // Process in batches
		StartAfter: aws.String(si.options.ContinuationToken),
	}

	objectCount := 0
	batchCount := 0

	paginator := s3.NewListObjectsV2Paginator(si.s3.GetStorage().Client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(si.ctx)
		if err != nil {
			if ctxErr := si.ctx.Err(); ctxErr != nil {
				return fmt.Errorf("S3 scan interrupted: %w", ctxErr)
			}
			return fmt.Errorf("error listing S3 objects: %w", err)
		}

		for _, object := range page.Contents {
			key := aws.ToString(object.Key)
			size := aws.ToInt64(object.Size)
			lastModified := aws.ToTime(object.LastModified)
			etag := strings.Trim(aws.ToString(object.ETag), "\"")

			// Parse the S3 key to extract domain, local_part, and content_hash
			// Expected format: domain/local_part/content_hash
			parts := strings.Split(key, "/")
			if len(parts) != 3 {
				logger.Info("Skipping S3 object with unexpected key format", "key", key)
				continue
			}

			domain := parts[0]
			localPart := parts[1]
			contentHash := parts[2]

			// Validate that this matches our expected user
			expectedDomain := address.Domain()
			expectedLocalPart := address.LocalPart()
			if domain != expectedDomain || localPart != expectedLocalPart {
				logger.Info("Skipping S3 object for different user", "key", key,
					"expected_email", fmt.Sprintf("%s@%s", expectedLocalPart, expectedDomain))
				continue
			}

			// Validate content hash format (should be hex)
			if len(contentHash) != 64 { // SHA256 hex string length
				logger.Info("Skipping S3 object with invalid hash format", "key", key)
				continue
			}
			if _, err := hex.DecodeString(contentHash); err != nil {
				logger.Info("Skipping S3 object with non-hex hash", "key", key)
				continue
			}

			// Store object information in SQLite
			_, err := si.db.Exec(`
				INSERT OR IGNORE INTO s3_objects
				(key, size, last_modified, etag, domain, local_part, content_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				key, size, lastModified.Format(time.RFC3339),
				etag, domain, localPart, contentHash)
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
				return nil
			}

			batchCount++
			if batchCount >= si.options.BatchSize {
				// Store continuation token for resumable operations
				si.lastContinuationToken = key
				batchCount = 0
			}
		}
	}

	logger.Info("Completed S3 scan", "count", objectCount)
	return nil
}

// performDryRun analyzes what would be imported without making changes
func (si *S3Importer) performDryRun() error {
	fmt.Printf("\n=== DRY RUN: S3 Import Analysis ===\n\n")
	fmt.Printf("Analyzing S3 messages for user: %s\n\n", si.options.Email)

	ctx := si.ctx
	accountID := si.user.AccountID()
	// The import files every object in INBOX. An account without one holds nothing there
	// yet: the import creates it.
	var inboxID int64
	if inbox, err := si.rdb.GetMailboxByNameWithRetry(ctx, accountID, consts.MailboxInbox); err == nil {
		inboxID = inbox.ID
	} else if !errors.Is(err, consts.ErrMailboxNotFound) {
		return fmt.Errorf("dry run: failed to look up INBOX: %w", err)
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
		// An interrupt stops the report: the objects after it are not checked, and a
		// summary would claim they were.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("dry run interrupted: %w", err)
		}

		var key, domain, localPart, contentHash, lastModified string
		var size int64
		if err := rows.Scan(&key, &size, &domain, &localPart, &contentHash, &lastModified); err != nil {
			logger.Info("Failed to scan row", "error", err)
			continue
		}

		// Check if message already exists. A failed check answers nothing: the object
		// is not reported as new.
		inAccount, inInbox, err := si.existingCopies(ctx, accountID, inboxID, contentHash)
		if err != nil {
			return fmt.Errorf("dry run: failed to check whether %s is already imported: %w", key, err)
		}
		action, reason := si.importAction(inAccount, inInbox)
		if action == "SKIP" {
			totalWouldSkip++
		} else {
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
	if err := rows.Err(); err != nil {
		return fmt.Errorf("dry run: failed to read S3 objects: %w", err)
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

	var wg sync.WaitGroup
	jobs := make(chan S3ObjectInfo, 100) // Buffer for better performance

	// Start workers
	for w := 0; w < si.options.Workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for obj := range jobs {
				if si.ctx.Err() != nil {
					continue // interrupted: what the feeder queued is left for the next run
				}
				if err := si.importS3Object(obj); err != nil {
					if si.ctx.Err() != nil {
						// Stopped by the interrupt, not failed: like the objects still
						// queued, it is left for the next run.
						logger.Info("Import interrupted, S3 object left for the next run", "worker", workerID,
							"key", obj.Key, "error", err)
						continue
					}
					logger.Info("Failed to import S3 object", "worker", workerID,
						"progress", si.getProgressPrefix(), "key", obj.Key, "error", err)
					atomic.AddInt64(&si.failedMessages, 1)
					si.markObjectProcessed(obj.Key, false, err.Error())
				}
				atomic.AddInt64(&si.processedObjects, 1)
			}
		}(w)
	}

	// Feed jobs to workers a page of keys at a time, until the keys run out or the
	// import is interrupted. A query's read transaction lasts until its rows are
	// closed, and the feeder waits on the workers while it feeds them: a query left
	// open for the whole run would hold the snapshot that keeps the checkpointer from
	// ever resetting the WAL, which then grows with every worker's update. Each page is
	// read in full, and its rows closed, before it is fed.
	var feedErr error
feed:
	for afterID := int64(0); ; {
		if si.ctx.Err() != nil {
			break
		}
		var keys []string
		keys, afterID, feedErr = si.unprocessedKeys(afterID, feedPageSize)
		if feedErr != nil || len(keys) == 0 {
			break
		}
		for _, key := range keys {
			select {
			case jobs <- S3ObjectInfo{Key: key}:
			case <-si.ctx.Done():
				break feed
			}
		}
	}

	close(jobs)
	wg.Wait()

	if err := si.ctx.Err(); err != nil {
		return fmt.Errorf("import interrupted: %w", err)
	}
	if feedErr != nil {
		return fmt.Errorf("failed to query unprocessed S3 objects: %w", feedErr)
	}
	return nil
}

// feedPageSize is how many keys importFromS3 reads from the work database at a time.
const feedPageSize = 1000

// unprocessedKeys returns the keys of up to limit unprocessed objects with an id above
// afterID, in id order, and the id of the last one (afterID when there are none). It
// reads every row before it returns, so its read transaction is over by then.
func (si *S3Importer) unprocessedKeys(afterID int64, limit int) ([]string, int64, error) {
	rows, err := si.db.Query("SELECT id, key FROM s3_objects WHERE processed = FALSE AND id > ? ORDER BY id LIMIT ?",
		afterID, limit)
	if err != nil {
		return nil, afterID, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&afterID, &key); err != nil {
			return nil, afterID, err
		}
		keys = append(keys, key)
	}
	return keys, afterID, rows.Err()
}

// importS3Object downloads and imports a single message from S3
func (si *S3Importer) importS3Object(obj S3ObjectInfo) error {
	// Parse the S3 key to extract content hash
	parts := strings.Split(obj.Key, "/")
	if len(parts) != 3 {
		return fmt.Errorf("invalid S3 key format: %s", obj.Key)
	}

	contentHash := parts[2]

	ctx := si.ctx
	user := si.user

	// The message is filed under this user's prefix (S3Domain/S3Localpart and the key
	// CompleteS3Upload confirms), so the object must be the one under that prefix: an
	// object under any other is another user's mail.
	s3Key := helpers.NewS3Key(user.Domain(), user.LocalPart(), contentHash)
	if obj.Key != s3Key {
		return fmt.Errorf("S3 object %s is not under the prefix of %s", obj.Key, user.FullAddress())
	}

	// Proactively ensure default mailboxes exist for this user
	// This prevents "mailbox not found" errors during import
	if err := si.rdb.CreateDefaultMailboxesWithRetry(ctx, user.AccountID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", si.options.Email, "error", err)
		// Don't fail the import, as mailboxes might already exist
	}

	// Import into INBOX by default (since we don't have mailbox information from S3)
	// Default mailboxes should already be created at this point
	mailbox, err := si.rdb.GetMailboxByNameWithRetry(ctx, user.AccountID(), consts.MailboxInbox)
	if err != nil {
		return fmt.Errorf("failed to get INBOX mailbox: %w", err)
	}

	// Check if message already exists. A failed check is not a "no": importing anyway
	// would duplicate a message that is there.
	inAccount, inInbox, err := si.existingCopies(ctx, user.AccountID(), mailbox.ID, contentHash)
	if err != nil {
		return fmt.Errorf("failed to check whether the message is already imported: %w", err)
	}
	if action, reason := si.importAction(inAccount, inInbox); action == "SKIP" {
		si.skipExisting(obj.Key, reason)
		return nil
	}

	// Download message content from S3
	reader, err := si.s3.GetWithRetry(ctx, obj.Key)
	if err != nil {
		return fmt.Errorf("failed to download from S3: %w", err)
	}
	defer reader.Close()

	// Read content. This is the message as stored, decrypted when S3 encryption is
	// on, so its length is the message's size; the listed object size is not.
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read S3 content: %w", err)
	}
	size := int64(len(content))

	// Parse message
	messageContent, err := server.ParseMessage(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	mailHeader := mail.Header{Header: messageContent.Header}
	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := helpers.ParseDateHeader(mailHeader.Get("Date"))
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")
	references, _ := mailHeader.MsgIDList("References")

	if len(inReplyTo) == 0 {
		inReplyTo = nil
	}
	if len(references) == 0 {
		references = nil
	}

	// The Date: header is the INTERNALDATE too; a message without one that parses
	// arrives now and keeps a zero sentDate (db.InsertMessageOptions.SentDate).
	internalDate := sentDate
	if internalDate.IsZero() {
		internalDate = time.Now()
	}

	bodyStructure := helpers.ExtractBodyStructure(bytes.NewReader(content))

	// Validate body structure and use fallback if invalid (e.g., multipart with no children)
	if err := helpers.ValidateBodyStructure(&bodyStructure); err != nil {
		logger.Warn("Invalid body structure in S3 object, using fallback", "key", obj.Key, "error", err)
		fallback := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    uint32(len(content)),
			Text:    &imap.BodyStructureText{}, // body-fld-lines is mandatory for a text part
		}
		bodyStructure = fallback
	}

	extractedPlaintext, err := helpers.ExtractPlaintextBody(messageContent)
	var actualPlaintextBody string
	if err == nil && extractedPlaintext != nil {
		actualPlaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	// The insert and marking the body uploaded run to the end even if an interrupt
	// lands between or during them: cut there, the message would stay in
	// pending_uploads, waiting for an upload of a body that is already in S3. An
	// interrupt before the insert leaves the object for the next run.
	if err := ctx.Err(); err != nil {
		return err
	}
	writeCtx := context.WithoutCancel(ctx)

	// Insert message into database
	msgID, uid, err := si.rdb.InsertMessageWithRetry(writeCtx,
		&db.InsertMessageOptions{
			AccountID:     user.AccountID(),
			MailboxID:     mailbox.ID,
			S3Domain:      user.Domain(),
			S3Localpart:   user.LocalPart(),
			MailboxName:   mailbox.Name,
			ContentHash:   contentHash,
			MessageID:     messageID,
			InternalDate:  internalDate,
			Size:          size,
			Subject:       subject,
			PlaintextBody: actualPlaintextBody,
			SentDate:      sentDate,
			InReplyTo:     inReplyTo,
			References:    references,
			BodyStructure: &bodyStructure,
			Recipients:    recipients,
			FTSRetention:  si.options.FTSRetention,
		},
		db.PendingUpload{
			InstanceID:  si.options.InstanceID,
			ContentHash: contentHash,
			Size:        size,
			AccountID:   user.AccountID(),
		})

	if errors.Is(err, consts.ErrMessageExists) {
		// INBOX received the message since the check above.
		si.skipExisting(obj.Key, "already in INBOX")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to insert message into database: %w", err)
	}

	// Since the content already exists in S3, mark the upload as complete
	err = si.rdb.CompleteS3UploadWithRetry(writeCtx, contentHash, user.AccountID(), []string{s3Key})
	if err != nil {
		return fmt.Errorf("failed to mark S3 upload as complete: %w", err)
	}

	atomic.AddInt64(&si.importedMessages, 1)
	logger.Info("Successfully imported message", "progress", si.getProgressPrefix(),
		"msg_id", msgID, "uid", uid, "user", user.FullAddress())

	si.markObjectProcessed(obj.Key, true, "imported successfully")

	// Add delay if configured; an interrupt ends it
	if si.options.ImportDelay > 0 {
		select {
		case <-time.After(si.options.ImportDelay):
		case <-ctx.Done():
		}
	}

	return nil
}

// existingCopies counts the account's live messages with this content hash: in all of
// its mailboxes, and in INBOX (inboxID), the mailbox the import files every object in.
func (si *S3Importer) existingCopies(ctx context.Context, accountID, inboxID int64, contentHash string) (inAccount, inInbox int, err error) {
	err = si.rdb.QueryRowWithRetry(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE mailbox_id = $3)
		FROM messages
		WHERE content_hash = $1 AND account_id = $2 AND expunged_at IS NULL`,
		contentHash, accountID, inboxID).Scan(&inAccount, &inInbox)
	return inAccount, inInbox, err
}

// importAction is what the import does with an object whose message the account holds
// inAccount times, inInbox of them in INBOX: IMPORT or REIMPORT it into INBOX, or SKIP
// it. The dry run reports it, so it predicts what the import does. --force-reimport
// imports a message another mailbox holds, but not one INBOX already holds: that copy
// would be a duplicate in the mailbox it is imported into.
func (si *S3Importer) importAction(inAccount, inInbox int) (action, reason string) {
	switch {
	case inAccount == 0:
		return "IMPORT", "new message"
	case !si.options.ForceReimport:
		return "SKIP", "already exists in database"
	case inInbox > 0:
		return "SKIP", "already in INBOX"
	default:
		return "REIMPORT", "in another mailbox, force reimport enabled"
	}
}

// skipExisting counts an object whose message is already there as skipped.
func (si *S3Importer) skipExisting(key, reason string) {
	logger.Info("Message already exists - skipping", "progress", si.getProgressPrefix(), "key", key, "reason", reason)
	atomic.AddInt64(&si.skippedMessages, 1)
	si.markObjectProcessed(key, true, reason)
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
