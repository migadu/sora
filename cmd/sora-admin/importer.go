package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"

	"github.com/emersion/go-message/mail" // Import for mail.ReadMessage
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/sieveengine"
	_ "modernc.org/sqlite"
)

// ImporterOptions contains configuration options for the importer
type ImporterOptions struct {
	DryRun               bool
	StartDate            *time.Time
	EndDate              *time.Time
	MailboxFilter        []string
	PreserveFlags        bool
	ShowProgress         bool
	ForceReimport        bool
	CleanupDB            bool
	Dovecot              bool
	ImportDelay          time.Duration // Delay between imports to control rate
	SievePath            string        // Path to Sieve script file to import
	SieveExtensions      []string      // [sieve] enabled_extensions the script is validated against (empty = default set)
	PreserveUIDs         bool          // Preserve UIDs from dovecot-uidlist files
	TestMode             bool          // Skip S3 uploads for testing (messages stored in DB only)
	BatchSize            int           // Number of messages to process in each batch (default: 20)
	BatchTransactionMode bool          // Use single transaction per batch (faster but less resilient, default: false)
	Incremental          bool          // Use SQLite cache to skip already-imported messages (default: false = always read all)
	MaxMessageSize       int64         // Maximum message size to import (bytes, 0 = use default)
	PathsFile            string        // Path to a file containing a list of relative or absolute paths to import
	FTSRetention         time.Duration // Skip the search row for messages sent before this window (0 = index all)
}

// resilientDB defines the interface for database operations needed by the importer.
// This allows for mocking the database during testing.
type resilientDB interface {
	GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error)
	CreateDefaultMailboxesWithRetry(ctx context.Context, accountID int64) error
	GetOwnedMailboxIDByNameWithRetry(ctx context.Context, accountID int64, name string) (int64, error)
	CreateMailboxWithRetry(ctx context.Context, accountID int64, name string, parentID *int64) error
	SubscribeWithRetry(ctx context.Context, accountID int64, mailboxName string) error
	GetActiveScriptWithRetry(ctx context.Context, accountID int64) (*db.SieveScript, error)
	GetScriptByNameWithRetry(ctx context.Context, name string, accountID int64) (*db.SieveScript, error)
	UpdateScriptWithRetry(ctx context.Context, scriptID, accountID int64, name, content string) (*db.SieveScript, error)
	CreateScriptWithRetry(ctx context.Context, accountID int64, name, content string) (*db.SieveScript, error)
	SetScriptActiveWithRetry(ctx context.Context, scriptID, accountID int64, active bool) error
	QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row
	GetOrCreateMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error)
	InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error)
	InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error)
	DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, accountID, mailboxID int64, hash string) (int64, error)
	BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error)
	GetOperationalDatabase() *db.Database
}

// msgInfo represents a message to import (used for batching)
type msgInfo struct {
	path     string
	filename string
	hash     string
	size     int64
	mailbox  string
	// imported is the cache row's s3_uploaded mark: an earlier run imported the file
	// under hash (recoverOrphanedSQLiteState clears the mark when the account has no
	// live row with that hash).
	imported bool
}

// uploadedMsg represents a successfully uploaded message
type uploadedMsg struct {
	msg      msgInfo
	content  []byte
	metadata *messageMetadata
}

// messageMetadata holds parsed message metadata
type messageMetadata struct {
	domain               string
	localpart            string
	accountID            int64
	messageID            string
	subject              string
	plaintextBody        string
	sentDate             time.Time
	internalDate         time.Time // arrival time: maildir filename timestamp / file mtime
	inReplyTo            []string
	references           []string
	bodyStructure        *imap.BodyStructure
	recipients           []helpers.Recipient
	flags                []imap.Flag
	preservedUID         *uint32
	preservedUIDValidity *uint32
}

// Importer handles the maildir import process.
type failedImport struct {
	path   string
	reason string
}

type Importer struct {
	ctx         context.Context // Context for cancellation support
	maildirPath string
	email       string
	jobs        int
	sqliteDB    *sql.DB // SQLite database for caching (nil in non-incremental mode)
	dbPath      string  // Path to the SQLite database file
	rdb         resilientDB
	s3          objectStorage
	options     ImporterOptions

	totalMessages    int64
	importedMessages int64
	skippedMessages  int64
	failedMessages   int64
	startTime        time.Time

	failedPathsMutex sync.Mutex
	failedPaths      []failedImport

	// sieveOutcome is what became of --sieve-path, for the summary.
	sieveOutcome string

	// Dovecot keyword mapping: ID -> keyword name
	dovecotKeywords map[int]string
	// folderKeywords caches each folder's own dovecot-keywords map by folder directory
	// (see keywordsForMessagePath); dovecotKeywords above is the root (INBOX) one.
	folderKeywords   map[string]map[int]string
	folderKeywordsMu sync.Mutex

	// Dovecot UID lists: mailbox path -> UID list
	dovecotUIDLists map[string]*DovecotUIDList

	// Cache for mailbox lookups (for batching optimization)
	mailboxCache map[string]*db.DBMailbox
	cacheMu      sync.RWMutex

	// Batch size configuration
	batchSize int // default: 20
}

// NewImporter creates a new Importer instance.
func NewImporter(ctx context.Context, maildirPath, email string, jobs int, rdb *resilient.ResilientDatabase, s3 objectStorage, options ImporterOptions) (*Importer, error) {
	// Always create SQLite database in the maildir path to persist maildir state
	dbPath := filepath.Join(maildirPath, "sora-maildir.db")

	if options.Incremental {
		logger.Info("Using maildir database for incremental import", "path", dbPath)
	} else {
		logger.Info("Incremental mode disabled - will read all files (database still created for tracking)", "path", dbPath)
	}

	// Open SQLite with proper settings for concurrent access
	// WAL mode enables concurrent readers and writers
	// _busy_timeout=5000 means wait up to 5 seconds if database is locked
	sqliteDB, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Configure connection pool for better concurrency
	// SQLite works best with a single writer connection
	sqliteDB.SetMaxOpenConns(1)
	sqliteDB.SetMaxIdleConns(1)

	// Create the table for storing message information.
	// s3_uploaded tracks whether the message has been successfully uploaded to S3
	_, err = sqliteDB.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL,
			filename TEXT NOT NULL,
			hash TEXT NOT NULL,
			size INTEGER NOT NULL,
			mailbox TEXT NOT NULL,
			s3_uploaded INTEGER DEFAULT 0,
			s3_uploaded_at TIMESTAMP,
			UNIQUE(hash, mailbox),
			UNIQUE(filename, mailbox)
		);
		CREATE INDEX IF NOT EXISTS idx_mailbox ON messages(mailbox);
		CREATE INDEX IF NOT EXISTS idx_hash ON messages(hash);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create messages table: %w", err)
	}

	// Migrate existing databases: add s3_uploaded columns if they don't exist
	// Check if s3_uploaded column exists
	var columnExists bool
	err = sqliteDB.QueryRow(`
		SELECT COUNT(*) > 0
		FROM pragma_table_info('messages')
		WHERE name='s3_uploaded'
	`).Scan(&columnExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check for s3_uploaded column: %w", err)
	}

	if !columnExists {
		logger.Info("Migrating SQLite database: adding s3_uploaded columns")
		// DEFAULT 0 must match the fresh schema above: a column default added here is
		// permanent for this database file, and scanMaildir inserts newly discovered
		// files without naming s3_uploaded. A default of 1 would make every file found
		// by a later scan born "already uploaded", invisible to the import (which
		// selects WHERE s3_uploaded = 0) and to orphan recovery, which runs before the
		// scan. Pre-existing rows are marked below instead, once.
		// All three statements commit together. Splitting the column default from the
		// backfill means a crash between them is not resumable: the next run sees the
		// column present, skips this whole block, and every legacy row stays at the new
		// default of 0 forever - re-importing the entire maildir on every subsequent run.
		// SQLite runs DDL inside transactions, so one transaction covers the lot.
		migrationTx, err := sqliteDB.Begin()
		if err != nil {
			return nil, fmt.Errorf("failed to begin SQLite migration: %w", err)
		}
		defer migrationTx.Rollback()

		if _, err = migrationTx.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded INTEGER DEFAULT 0`); err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded column: %w", err)
		}

		if _, err = migrationTx.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded_at TIMESTAMP`); err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded_at column: %w", err)
		}

		// Assume the rows that already existed are on S3. recoverOrphanedSQLiteState
		// re-checks every one of them against PostgreSQL on this same run and resets
		// the ones that never landed, so a wrong assumption here self-corrects.
		if _, err = migrationTx.Exec(`UPDATE messages SET s3_uploaded = 1, s3_uploaded_at = CURRENT_TIMESTAMP`); err != nil {
			return nil, fmt.Errorf("failed to mark existing messages as uploaded: %w", err)
		}

		if err = migrationTx.Commit(); err != nil {
			return nil, fmt.Errorf("failed to commit SQLite migration: %w", err)
		}

		logger.Info("SQLite database migration completed successfully - all existing messages marked as uploaded")
	}

	// Create index after migration (idempotent operation)
	_, err = sqliteDB.Exec(`CREATE INDEX IF NOT EXISTS idx_s3_uploaded ON messages(s3_uploaded)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create s3_uploaded index: %w", err)
	}

	// Set batch size from options or use default
	batchSize := 20 // Default
	if options.BatchSize > 0 {
		batchSize = options.BatchSize
	}

	importer := &Importer{
		ctx:             ctx,
		maildirPath:     maildirPath,
		email:           email,
		jobs:            jobs,
		sqliteDB:        sqliteDB,
		dbPath:          dbPath,
		rdb:             rdb,
		s3:              s3,
		options:         options,
		startTime:       time.Now(),
		dovecotKeywords: make(map[int]string),
		folderKeywords:  make(map[string]map[int]string),
		dovecotUIDLists: make(map[string]*DovecotUIDList),
		mailboxCache:    make(map[string]*db.DBMailbox),
		batchSize:       batchSize,
	}

	// Parse Dovecot keywords if Dovecot mode is enabled
	if options.Dovecot {
		if err := importer.parseDovecotKeywords(); err != nil {
			logger.Info("Warning: Failed to parse dovecot-keywords", "error", err)
			// Don't fail creation for keyword parsing errors
		}
	}

	return importer, nil
}

// recordFailedPath safely records a file path and reason that failed to be imported.
func (i *Importer) recordFailedPath(path, reason string) {
	i.failedPathsMutex.Lock()
	defer i.failedPathsMutex.Unlock()
	i.failedPaths = append(i.failedPaths, failedImport{path: path, reason: reason})
}

// Close closes the importer and its resources. The maildir database file stays on
// disk: Run removes it for --cleanup-db, and only after an import that succeeded.
func (i *Importer) Close() error {
	if i.sqliteDB != nil {
		if err := i.sqliteDB.Close(); err != nil {
			return fmt.Errorf("failed to close maildir database: %w", err)
		}
	}
	return nil
}

// finish ends Run: it closes the maildir database and, with --cleanup-db, removes it
// if the run succeeded. The file records which messages are already imported, so after
// a failed, partly failed or interrupted run it is kept: it is what lets the re-run
// (--incremental) import only what is missing instead of the whole maildir again.
func (i *Importer) finish(runErr error) {
	if err := i.Close(); err != nil {
		logger.Warn("Failed to close maildir database", "path", i.dbPath, "error", err)
		return
	}
	switch {
	case !i.options.CleanupDB:
		logger.Info("Maildir database saved", "path", i.dbPath)
	case i.options.DryRun:
		// A dry run imports nothing and promises no changes, and the file may hold an
		// earlier run's record (previewing the retry of a partly failed run).
		logger.Info("Dry run, keeping the import database", "path", i.dbPath)
	case runErr != nil:
		logger.Warn("Import did not complete, keeping the import database for the next run", "path", i.dbPath, "error", runErr)
	default:
		logger.Info("Cleaning up import database", "path", i.dbPath)
		if err := os.Remove(i.dbPath); err != nil {
			logger.Warn("Failed to remove import database", "path", i.dbPath, "error", err)
		}
	}
}

// recoveryHashBatchSize is how many cached hashes are checked against
// PostgreSQL per round trip during orphan recovery.
const recoveryHashBatchSize = 500

// recoverOrphanedSQLiteState checks for messages marked as uploaded in SQLite
// but not actually present in PostgreSQL. This can happen if:
// 1. PostgreSQL commit failed after SQLite update (rare but possible)
// 2. Previous import was interrupted between SQLite update and PG commit
//
// Recovery: Reset s3_uploaded=0 for messages not found in PostgreSQL
func (i *Importer) recoverOrphanedSQLiteState() error {
	// Get account info
	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		// Account doesn't exist yet - nothing to recover
		if errors.Is(err, consts.ErrUserNotFound) {
			return nil
		}
		return fmt.Errorf("failed to get account: %w", err)
	}

	// Query SQLite for ALL messages marked as uploaded. Any row left marked
	// uploaded is skipped forever by incremental imports, so the check must not
	// be bounded. The cursor is drained before touching PostgreSQL because the
	// SQLite pool holds a single connection.
	rows, err := i.sqliteDB.Query("SELECT hash FROM messages WHERE s3_uploaded = 1")
	if err != nil {
		return fmt.Errorf("failed to query SQLite: %w", err)
	}

	var uploadedHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			continue
		}
		uploadedHashes = append(uploadedHashes, hash)
	}
	rows.Close() // CRITICAL: Close rows to release SQLite connection

	// Check existence in PostgreSQL in batches (one round trip per batch)
	var orphanedHashes []string
	for start := 0; start < len(uploadedHashes); start += recoveryHashBatchSize {
		end := start + recoveryHashBatchSize
		if end > len(uploadedHashes) {
			end = len(uploadedHashes)
		}
		chunk := uploadedHashes[start:end]

		var missing []string
		err = i.rdb.QueryRowWithRetry(i.ctx, `
			SELECT COALESCE(ARRAY_AGG(h), '{}')
			FROM UNNEST($2::text[]) AS h
			WHERE NOT EXISTS (
				SELECT 1 FROM messages
				WHERE account_id = $1 AND content_hash = h AND expunged_at IS NULL
			)`, accountID, chunk).Scan(&missing)

		if err != nil {
			logger.Warn("Failed to check message existence", "count", len(chunk), "error", err)
			continue
		}

		orphanedHashes = append(orphanedHashes, missing...)
	}

	if len(orphanedHashes) > 0 {
		logger.Info("Found orphaned SQLite state, resetting", "count", len(orphanedHashes))

		// Reset s3_uploaded for orphaned messages
		tx, err := i.sqliteDB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin recovery transaction: %w", err)
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare("UPDATE messages SET s3_uploaded = 0, s3_uploaded_at = NULL WHERE hash = ?")
		if err != nil {
			return fmt.Errorf("failed to prepare recovery statement: %w", err)
		}
		defer stmt.Close()

		for _, hash := range orphanedHashes {
			if _, err := stmt.Exec(hash); err != nil {
				logger.Warn("Failed to reset orphaned hash", "hash", shortHash(hash), "error", err)
			}
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit recovery transaction: %w", err)
		}

		logger.Info("Successfully recovered orphaned SQLite state", "recovered", len(orphanedHashes))
	}

	return nil
}

// Run starts the import process.
func (i *Importer) Run() (err error) {
	defer func() {
		if p := recover(); p != nil {
			// A run that panicked did not complete: err is still nil here.
			i.finish(fmt.Errorf("import aborted: %v", p))
			panic(p)
		}
		i.finish(err)
	}()

	// Recovery: Check for messages marked in SQLite but not in PostgreSQL
	// This can happen if PostgreSQL commit failed after SQLite update
	if err := i.recoverOrphanedSQLiteState(); err != nil {
		logger.Warn("Failed to recover orphaned SQLite state", "error", err)
		// Non-fatal - continue with import
	}

	// Process Dovecot subscriptions if Dovecot mode is enabled
	if i.options.Dovecot {
		if err := i.processSubscriptions(); err != nil {
			logger.Info("Warning: Failed to process subscriptions", "error", err)
			// Don't fail the import for subscription errors
		}
	}

	// Import Sieve script if provided
	if i.options.SievePath != "" {
		if err := i.importSieveScript(); err != nil {
			logger.Info("Warning: Failed to import Sieve script", "error", err)
		}
	}

	logger.Info("Scanning maildir...")
	if err := i.scanMaildir(); err != nil {
		return fmt.Errorf("failed to scan maildir: %w", err)
	}

	// Sync mailbox state (UIDVALIDITY) before starting import
	// This ensures that mailboxes have the correct UIDVALIDITY from Dovecot
	// even if the first imported message doesn't have a preserved UID.
	if i.options.PreserveUIDs {
		logger.Info("Syncing mailbox state (UIDVALIDITY)...")
		if err := i.syncMailboxState(); err != nil {
			// Log warning but continue - import might still work partially
			logger.Info("Warning: Failed to sync mailbox state", "error", err)
		}
	}

	// Count messages based on mode
	var totalCount, alreadyOnS3 int64
	if i.options.Incremental {
		// Incremental mode: count only NEW (not yet on S3) messages in SQLite database
		countErr := i.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 0").Scan(&totalCount)
		if countErr != nil {
			return fmt.Errorf("failed to count messages in database: %w", countErr)
		}

		// Also count messages already on S3 for logging
		i.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1").Scan(&alreadyOnS3)

		// Set totalMessages to the actual count in database
		atomic.StoreInt64(&i.totalMessages, totalCount)
		logger.Info("Found new messages to import (incremental mode)", "new", totalCount, "already_on_s3", alreadyOnS3)
	} else {
		// Non-incremental mode: count all scanned messages in SQLite (but we'll import all)
		countErr := i.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages").Scan(&totalCount)
		if countErr != nil {
			return fmt.Errorf("failed to count messages in database: %w", countErr)
		}

		// Set totalMessages to the actual count in database
		atomic.StoreInt64(&i.totalMessages, totalCount)
		logger.Info("Found messages to import (non-incremental mode - reading all)", "total", totalCount)
	}

	if i.options.DryRun {
		logger.Info("DRY RUN: Analyzing what would be imported...")
		err := i.performDryRun()
		i.printSieveOutcome()
		return err
	}

	// Only proceed with import if we have messages
	if totalCount == 0 {
		logger.Info("No messages to import")
		if i.failedMessages == 0 {
			i.printSieveOutcome()
			return nil
		}
		// Every message still to import failed in the scan (unreadable, empty, over
		// the size limit): the run did not import everything, so report it as any
		// other run with failed messages.
	} else {
		logger.Info("Starting import process", "count", totalCount)
		if err := i.importMessages(); err != nil {
			return fmt.Errorf("failed to import messages: %w", err)
		}
	}

	if err := i.printSummary(); err != nil {
		logger.Warn("Failed to print summary", "error", err)
	}

	if i.failedMessages > 0 {
		return fmt.Errorf("import completed with %d failed messages", i.failedMessages)
	}

	return nil
}

// processSubscriptions reads and processes the Dovecot subscriptions file
func (i *Importer) processSubscriptions() error {
	subscriptionsPath := filepath.Join(i.maildirPath, "subscriptions")

	// Check if subscriptions file exists
	if _, err := os.Stat(subscriptionsPath); os.IsNotExist(err) {
		logger.Info("No subscriptions file found - skipping subscription processing", "path", subscriptionsPath)
		return nil
	}

	logger.Info("Processing Dovecot subscriptions", "path", subscriptionsPath)

	// Read the subscriptions file
	content, err := os.ReadFile(subscriptionsPath)
	if err != nil {
		return fmt.Errorf("failed to read subscriptions file: %w", err)
	}

	folders := parseDovecotSubscriptions(string(content))
	if len(folders) == 0 {
		logger.Info("No folders found in subscriptions file")
		return nil
	}

	logger.Info("Found subscribed folders", "count", len(folders), "folders", folders)

	// Get user context for database operations
	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --email %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	// Ensure default mailboxes exist first
	if i.options.DryRun {
		logger.Info("DRY RUN: Would create any missing default mailboxes", "email", i.email)
	} else if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.AccountID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", i.email, "error", err)
		// Don't fail the subscription processing, as mailboxes might already exist
	}

	// Process each subscribed folder
	for _, subscribed := range folders {
		// Named as the folder import names a folder, so the subscription is to the
		// mailbox that folder's messages went to.
		folderName, err := importedFolderName(subscribed)
		if err != nil {
			logger.Warn("Skipping subscription", "name", subscribed, "error", err)
			continue
		}

		if i.options.DryRun {
			logger.Info("DRY RUN: Would subscribe to mailbox", "name", folderName)
			continue
		}

		// Subscriptions are name-based (migration 000046), so record the subscription
		// directly without materializing a mailbox. Dovecot permits subscriptions to
		// folders that don't exist; the previous get-or-create created phantom empty
		// mailboxes for those. Folders that DO exist are created by the folder-import
		// pass, so this only records the name.
		if err := i.rdb.SubscribeWithRetry(i.ctx, user.AccountID(), folderName); err != nil {
			logger.Info("Warning: Failed to subscribe to mailbox", "name", folderName, "error", err)
		} else {
			logger.Info("Successfully subscribed to mailbox", "name", folderName)
		}
	}

	return nil
}

// importSieveScript imports a Sieve script file for the user
func (i *Importer) importSieveScript() error {
	// Check if file exists (follow symlinks if present)
	if _, err := os.Stat(i.options.SievePath); os.IsNotExist(err) {
		logger.Info("Sieve script file does not exist - ignoring", "path", i.options.SievePath)
		return nil
	}

	// Read the script content
	scriptContent, err := os.ReadFile(i.options.SievePath)
	if err != nil {
		return fmt.Errorf("failed to read Sieve script file: %w", err)
	}

	// A script delivery cannot compile is skipped whole, so it must not become
	// the active script. It is still stored, under its own name so no working
	// script is overwritten, for the user to see and fix through ManageSieve,
	// and the mail import goes on.
	compileErr := sieveengine.ValidateScript(string(scriptContent), i.options.SieveExtensions)

	if i.options.DryRun {
		if compileErr != nil {
			i.sieveOutcome = fmt.Sprintf("would be stored but left INACTIVE: it does not compile: %v", compileErr)
			logger.Warn("DRY RUN: Sieve script does not compile; it would be stored but left inactive", "path", i.options.SievePath, "error", compileErr)
		} else {
			i.sieveOutcome = "would be imported and activated"
			logger.Info("DRY RUN: Would import and activate Sieve script", "path", i.options.SievePath)
		}
		return nil
	}

	logger.Info("Importing Sieve script", "path", i.options.SievePath)

	// Get user context for database operations
	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --email %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	scriptName := "imported"
	if compileErr != nil {
		scriptName = "imported-invalid"
	} else {
		// A script that compiles replaces the active one, if any, by name.
		existingScript, err := i.rdb.GetActiveScriptWithRetry(i.ctx, user.AccountID())
		if err != nil && err != consts.ErrDBNotFound {
			return fmt.Errorf("failed to check for existing active script: %w", err)
		}
		if existingScript != nil {
			logger.Info("User already has an active Sieve script - it will be replaced", "name", existingScript.Name)
			scriptName = existingScript.Name
		}
	}

	// Create or update the script
	var script *db.SieveScript
	existingByName, err := i.rdb.GetScriptByNameWithRetry(i.ctx, scriptName, user.AccountID())
	if compileErr != nil && err == nil {
		// An earlier run stored this name. If it compiles now, the user fixed it
		// since; it is theirs and is kept. If it is still broken, it is
		// deactivated before its content is replaced, so nothing between the
		// two steps can leave broken content active.
		if sieveengine.ValidateScript(existingByName.Script, i.options.SieveExtensions) == nil {
			i.sieveOutcome = fmt.Sprintf("not stored: %q from an earlier import was fixed by the user and is kept; the file still does not compile: %v", scriptName, compileErr)
			logger.Warn("Sieve script does not compile; an earlier import's script of that name was fixed by the user and is kept", "name", scriptName, "user", i.email, "error", compileErr)
			return nil
		}
		if existingByName.Active {
			if err := i.rdb.SetScriptActiveWithRetry(i.ctx, existingByName.ID, user.AccountID(), false); err != nil {
				return fmt.Errorf("failed to deactivate Sieve script: %w", err)
			}
		}
	}
	switch err {
	case nil:
		// Script with this name exists, update it
		script, err = i.rdb.UpdateScriptWithRetry(i.ctx, existingByName.ID, user.AccountID(), scriptName, string(scriptContent))
		if err != nil {
			return fmt.Errorf("failed to update existing Sieve script: %w", err)
		}
		logger.Info("Updated existing Sieve script", "name", scriptName)
	case consts.ErrDBNotFound:
		// Create new script
		script, err = i.rdb.CreateScriptWithRetry(i.ctx, user.AccountID(), scriptName, string(scriptContent))
		if err != nil {
			return fmt.Errorf("failed to create Sieve script: %w", err)
		}
		logger.Info("Created new Sieve script", "name", scriptName)
	default:
		return fmt.Errorf("failed to check for existing script by name: %w", err)
	}

	if compileErr != nil {
		// A new row is inactive; an existing one was deactivated above.
		i.sieveOutcome = fmt.Sprintf("stored as %q but left INACTIVE: it does not compile: %v", scriptName, compileErr)
		logger.Warn("Sieve script does not compile; stored but left inactive", "name", scriptName, "user", i.email, "error", compileErr)
		return nil
	}

	// Activate the script
	if err := i.rdb.SetScriptActiveWithRetry(i.ctx, script.ID, user.AccountID(), true); err != nil {
		return fmt.Errorf("failed to activate Sieve script: %w", err)
	}

	i.sieveOutcome = fmt.Sprintf("imported and activated as %q", scriptName)
	logger.Info("Successfully imported and activated Sieve script", "name", scriptName, "user", i.email)
	return nil
}

// parseDovecotKeywords reads and parses the Dovecot keywords file
func (i *Importer) parseDovecotKeywords() error {
	keywordsPath := filepath.Join(i.maildirPath, "dovecot-keywords")

	// Check if keywords file exists
	if _, err := os.Stat(keywordsPath); os.IsNotExist(err) {
		logger.Info("No dovecot-keywords file found - custom keywords will not be imported", "path", keywordsPath)
		return nil
	}

	logger.Info("Parsing Dovecot keywords", "path", keywordsPath)

	keywords, err := parseKeywordsFile(keywordsPath)
	if err != nil {
		return err
	}
	keywordCount := 0
	for id, keyword := range keywords {
		i.dovecotKeywords[id] = keyword
		keywordCount++
	}

	if keywordCount > 0 {
		logger.Info("Loaded Dovecot custom keywords", "count", keywordCount)
	}

	return nil
}

// performDryRun analyzes what would be imported without making changes
func (i *Importer) performDryRun() error {
	fmt.Printf("\n=== DRY RUN: Import Analysis ===\n\n")

	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --email %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	// Query the SQLite database for messages
	var query string
	if i.options.Incremental {
		// Incremental mode: only show messages not yet uploaded
		query = "SELECT path, filename, hash, size, mailbox FROM messages WHERE s3_uploaded = 0 ORDER BY mailbox, path"
	} else {
		// Non-incremental mode: show all messages
		query = "SELECT path, filename, hash, size, mailbox FROM messages ORDER BY mailbox, path"
	}

	rows, err := i.sqliteDB.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query messages from sqlite: %w", err)
	}
	defer rows.Close()

	var totalWouldImport, totalWouldSkip, totalToScan int64
	currentMailbox := ""
	var mailboxWouldImport, mailboxWouldSkip int

	for rows.Next() {
		var path, filename, hash, mailbox string
		var size int64
		if err := rows.Scan(&path, &filename, &hash, &size, &mailbox); err != nil {
			logger.Info("Failed to scan row", "error", err)
			continue
		}

		totalToScan++

		// Check if we're starting a new mailbox
		if mailbox != currentMailbox {
			// Print summary for previous mailbox
			if currentMailbox != "" {
				fmt.Printf("   Summary: %d would import, %d would skip\n\n", mailboxWouldImport, mailboxWouldSkip)
			}

			// Start new mailbox
			currentMailbox = mailbox
			mailboxWouldImport = 0
			mailboxWouldSkip = 0
			fmt.Printf("Mailbox: %s\n", mailbox)
		}

		// Check date filter if specified
		if i.shouldSkipMessage(path) {
			mailboxWouldSkip++
			totalWouldSkip++
			continue
		}

		// Check if message already exists in Sora, in the account's own mailbox of that
		// name: the import never writes into a same-named mailbox shared with the account.
		mailboxID, err := i.rdb.GetOwnedMailboxIDByNameWithRetry(i.ctx, user.AccountID(), mailbox)
		var alreadyExists bool
		if err == nil {
			if !i.options.ForceReimport {
				alreadyExists, err = i.isMessageAlreadyImported(hash, mailboxID)
				if err != nil {
					logger.Info("Error checking if message exists", "error", err)
				}
			}
		}

		action := "IMPORT"
		reason := "new message"

		if alreadyExists {
			if i.options.ForceReimport {
				action = "REIMPORT"
				reason = "force reimport enabled"
			} else {
				action = "SKIP"
				reason = "already exists in Sora"
				mailboxWouldSkip++
				totalWouldSkip++
				continue
			}
		}

		mailboxWouldImport++

		// Extract basic message info
		subject := "(unknown subject)"
		dateStr := "(unknown date)"

		// Try to extract subject and date from message file
		if info, err := os.Stat(path); err == nil {
			dateStr = info.ModTime().Format("2006-01-02 15:04")
		}

		// Try to get subject from message content (first few hundred bytes)
		if file, err := os.Open(path); err == nil {
			buffer := make([]byte, 1024)
			if n, err := file.Read(buffer); err == nil {
				content := string(buffer[:n])
				// Simple subject extraction
				if idx := strings.Index(strings.ToLower(content), "subject:"); idx != -1 {
					subjectLine := content[idx+8:]
					if endIdx := strings.Index(subjectLine, "\n"); endIdx != -1 {
						subject = strings.TrimSpace(subjectLine[:endIdx])
						if len(subject) > 50 {
							subject = subject[:47] + "..."
						}
					}
				}
			}
			file.Close()
		}

		if subject == "" || subject == "\r" {
			subject = "(no subject)"
		}

		// Show detailed message info
		fmt.Printf("   %s %s\n", action, filename)
		fmt.Printf("      Subject: %s\n", subject)
		fmt.Printf("      Date: %s | Size: %s | Hash: %s\n",
			dateStr,
			formatImportSize(size),
			shortHash(hash)+"...")
		fmt.Printf("      Action: %s: %s\n", action, reason)

		// Show flags if preserve-flags is enabled
		if i.options.PreserveFlags {
			flags := i.parseMaildirFlagsWith(filename, i.keywordsForMessagePath(path))
			if len(flags) > 0 {
				var flagNames []string
				for _, flag := range flags {
					flagNames = append(flagNames, string(flag))
				}
				fmt.Printf("      Flags: %v\n", flagNames)
			}
		}

		fmt.Println()
	}

	// Print summary for last mailbox
	if currentMailbox != "" {
		fmt.Printf("   Summary: %d would import, %d would skip\n\n", mailboxWouldImport, mailboxWouldSkip)
	}

	totalWouldImport = totalToScan - totalWouldSkip

	// Overall summary
	fmt.Printf("=== DRY RUN: Overall Summary ===\n")
	fmt.Printf("Would import: %d messages\n", totalWouldImport)
	fmt.Printf("Would skip: %d messages\n", totalWouldSkip)
	fmt.Printf("Total files to analyze: %d\n", totalToScan)

	if i.options.Dovecot {
		fmt.Printf("Would process Dovecot subscriptions and keywords\n")
	}

	fmt.Printf("\nRun without --dry-run to perform the actual import.\n")
	return nil
}

// formatImportSize formats a byte size into human readable format
func formatImportSize(bytes int64) string {
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

// printSieveOutcome says what became of --sieve-path, on every path that
// ends an import, not only the one that prints the full summary.
func (i *Importer) printSieveOutcome() {
	if i.sieveOutcome != "" {
		fmt.Printf("  Sieve script:      %s\n", i.sieveOutcome)
	}
}

// printSummary prints a summary of the import process.
func (i *Importer) printSummary() error {
	duration := time.Since(i.startTime)
	fmt.Printf("\n\nImport Summary:\n")
	fmt.Printf("  Total messages:    %d\n", i.totalMessages)
	fmt.Printf("  Imported:          %d\n", i.importedMessages)
	fmt.Printf("  Skipped:           %d\n", i.skippedMessages)
	fmt.Printf("  Failed:            %d\n", i.failedMessages)
	i.printSieveOutcome()
	fmt.Printf("  Duration:          %s\n", duration.Round(time.Second))
	if i.importedMessages > 0 {
		rate := float64(i.importedMessages) / duration.Seconds()
		fmt.Printf("  Import rate:       %.1f messages/sec\n", rate)
	}
	if i.options.Dovecot {
		fmt.Printf("\nNote: Dovecot subscriptions and keywords files processed if present.\n")
	}

	i.failedPathsMutex.Lock()
	defer i.failedPathsMutex.Unlock()
	if len(i.failedPaths) > 0 {
		fmt.Printf("\nFailed Messages (%d):\n", len(i.failedPaths))
		for _, fp := range i.failedPaths {
			fmt.Printf("  - %s (Reason: %s)\n", fp.path, fp.reason)
		}
		fmt.Printf("\nYou can retry these specific paths using the --paths-file flag.\n")
	}

	return nil
}

// hashFile returns the content hash (helpers.HashContent) and size of the message in a
// maildir file, decompressing it the way the upload does. It streams the file, so the
// scan never holds a whole message in memory.
func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	reader, _, err := maildirContentReader(file)
	if err != nil {
		return "", 0, err
	}

	hasher := helpers.NewContentHasher()
	size, err := io.Copy(hasher, reader)
	if err != nil {
		return "", 0, fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// legacyImportHash is the content hash sora-admin import used before it switched to
// helpers.HashContent: the hex SHA-256 of the message. Only a SQLite cache such a version
// wrote still holds it.
func legacyImportHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// resolveMailboxName determines the mailbox name from the maildir path
func (i *Importer) resolveMailboxName(path string) (string, error) {
	cleanPath := filepath.Clean(i.maildirPath)
	relPath, err := filepath.Rel(cleanPath, path)
	if err != nil {
		return "", fmt.Errorf("could not get relative path for %s: %w", path, err)
	}

	if relPath == "." {
		return "INBOX", nil
	}
	// Folders are named Maildir++ style (".Sent", ".Work.Projects") or without the
	// leading dot ("Sent"): drop the dot, then turn the maildir separator (.) into
	// the IMAP one (/).
	return importedFolderName(strings.ReplaceAll(strings.TrimPrefix(relPath, "."), ".", "/"))
}

// importedFolderName is the Sora mailbox name for a folder name read from a maildir,
// its levels already separated by '/': modified UTF-7 decoded (Dovecot's encoding of
// non-ASCII names), trimmed, and special folders mapped. A name with TAB, CR or LF is
// refused. Folders and the subscriptions file are both named through it, so a
// subscription names the mailbox the folder's messages went to.
func importedFolderName(name string) (string, error) {
	if decoded, err := helpers.DecodeModifiedUTF7(name); err != nil {
		logger.Warn("Failed to decode Modified UTF-7 mailbox name, using raw name", "name", name, "error", err)
	} else {
		name = decoded
	}
	if strings.ContainsAny(name, "\t\r\n") {
		return "", fmt.Errorf("invalid characters in mailbox name %q", name)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("empty mailbox name")
	}
	return specialFolderName(name), nil
}

// specialFolderName maps the names other mail systems give their special folders
// ("Sent Items", "Spam", ...) to Sora's.
func specialFolderName(name string) string {
	switch strings.ToLower(name) {
	case "sent", "sent items", "sent mail":
		return "Sent"
	case "drafts", "draft":
		return "Drafts"
	case "trash", "deleted", "deleted items":
		return "Trash"
	case "junk", "spam":
		return "Junk"
	case "archive", "archives":
		return "Archive"
	}
	return name
}

// parseMaildirFlagsWith extracts IMAP flags from a maildir filename. The a-z keyword
// letters in it are indexes into the dovecot-keywords file OF THAT FOLDER, and every
// folder has its own file and numbering, so keywords is keywordsForMessagePath's map
// for the message.
func (i *Importer) parseMaildirFlagsWith(filename string, keywords map[int]string) []imap.Flag {
	var flags []imap.Flag

	// Maildir flags are after the colon, e.g., "1234567890.M123P456.hostname:2,FS"
	if idx := strings.LastIndex(filename, ":2,"); idx != -1 && idx+3 < len(filename) {
		flagStr := filename[idx+3:]
		for _, char := range flagStr {
			switch char {
			case 'F':
				flags = append(flags, imap.FlagFlagged)
			case 'S':
				flags = append(flags, imap.FlagSeen)
			case 'R':
				flags = append(flags, imap.FlagAnswered)
			// Maildir info flags (cr.yp.to/proto/maildir.html, and what this tool's
			// exporter writes): D = Draft, T = Trashed (\Deleted). These were once
			// swapped, which turned every imported Dovecot draft into a \Deleted
			// message that the user's next EXPUNGE destroyed.
			case 'D':
				flags = append(flags, imap.FlagDraft)
			case 'T':
				flags = append(flags, imap.FlagDeleted)
			default:
				// Handle Dovecot custom keywords (a-z represent keyword IDs 0-25)
				if char >= 'a' && char <= 'z' {
					keywordID := int(char - 'a')
					if keywordName, exists := keywords[keywordID]; exists {
						// Add custom keyword as IMAP flag
						flags = append(flags, imap.Flag(keywordName))
					} else {
						logger.Info("Warning: Unknown keyword ID in filename", "id", keywordID, "char", string(char), "filename", filename)
					}
				}
			}
		}
	}

	// NOTE: Do NOT set \Recent on import.
	// Per RFC 3501, \Recent is session-specific and not a persistent flag.
	// Persisting it causes clients to treat all messages as new/recent after import,
	// which often triggers a full re-sync/redownload.
	return flags
}

// validateMessage performs basic validation on a message.
func (i *Importer) validateMessage(size int64) error {
	if size == 0 {
		return errors.New("empty message")
	}
	if i.options.MaxMessageSize > 0 && size > i.options.MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max: %d)", size, i.options.MaxMessageSize)
	}
	return nil
}

// isValidMaildirMessage checks if a filename looks like a valid maildir message.
func isValidMaildirMessage(filename string) bool {
	// Skip hidden files (metadata files typically start with .)
	if strings.HasPrefix(filename, ".") {
		return false
	}

	// If it's a regular file in cur/ or new/, it should be a message
	// Invalid files will be caught by the email parser later
	return true
}

// shouldImportMailbox checks if a mailbox should be imported based on filters.
func (i *Importer) shouldImportMailbox(mailboxName string) bool {
	if len(i.options.MailboxFilter) == 0 {
		return true
	}

	for _, filter := range i.options.MailboxFilter {
		if strings.EqualFold(mailboxName, filter) {
			return true
		}
		// Support wildcard matching
		if strings.HasSuffix(filter, "*") {
			prefix := strings.TrimSuffix(filter, "*")
			if strings.HasPrefix(strings.ToLower(mailboxName), strings.ToLower(prefix)) {
				return true
			}
		}
	}

	return false
}

// isMessageAlreadyImported checks if a message with the given hash already exists in the Sora database.
func (i *Importer) isMessageAlreadyImported(hash string, mailboxID int64) (bool, error) {
	var count int
	err := i.rdb.QueryRowWithRetry(i.ctx,
		"SELECT COUNT(*) FROM messages WHERE content_hash = $1 AND mailbox_id = $2 AND expunged_at IS NULL",
		hash, mailboxID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check if message exists: %w", err)
	}
	return count > 0, nil
}

// isMaildirFolder checks if a directory is a valid maildir folder.
func isMaildirFolder(path string) bool {
	// A maildir folder is one that holds messages: cur/ or new/. tmp/ is where a
	// writer stages files and is routinely absent from copies (rsync --exclude tmp,
	// backups); requiring it silently skipped whole folders of mail.
	_, errCur := os.Stat(filepath.Join(path, "cur"))
	_, errNew := os.Stat(filepath.Join(path, "new"))
	if os.IsNotExist(errCur) && os.IsNotExist(errNew) {
		return false
	}
	if _, errTmp := os.Stat(filepath.Join(path, "tmp")); os.IsNotExist(errTmp) {
		logger.Info("Maildir folder has no tmp/ directory; importing it anyway", "path", path)
	}
	return true
}

// fileToProcess is a struct to send file info to worker goroutines for processing.
type fileToProcess struct {
	path        string
	filename    string
	mailboxName string
}

// scanMaildir scans the maildir path and populates the SQLite database.
func (i *Importer) scanMaildir() error {
	// Ensure path is clean and safe
	cleanPath := filepath.Clean(i.maildirPath)

	// First, validate that the root path is a valid maildir
	if !isMaildirFolder(cleanPath) {
		// Check if there's a Maildir subdirectory (common mistake)
		possibleMaildir := filepath.Join(cleanPath, "Maildir")
		if isMaildirFolder(possibleMaildir) {
			return fmt.Errorf("path '%s' is not a valid maildir root.\nDid you mean to use '%s' instead?\nThe path should point directly to a maildir (containing cur/ or new/)", cleanPath, possibleMaildir)
		}

		// Check for other common maildir subdirectories
		entries, err := os.ReadDir(cleanPath)
		if err == nil {
			var suggestions []string
			for _, entry := range entries {
				if entry.IsDir() {
					subPath := filepath.Join(cleanPath, entry.Name())
					if isMaildirFolder(subPath) {
						suggestions = append(suggestions, subPath)
					}
				}
			}
			if len(suggestions) > 0 {
				return fmt.Errorf("path '%s' is not a valid maildir root.\nFound possible maildir(s): %s\nThe path should point directly to a maildir (containing cur/ or new/)", cleanPath, strings.Join(suggestions, ", "))
			}
		}

		return fmt.Errorf("path '%s' is not a valid maildir root (must contain cur/ or new/)", cleanPath)
	}

	// --- Parallel Processing Setup ---
	var wg sync.WaitGroup
	// This channel will be used by the producer (filepath.Walk) to send files to consumers (workers).
	filesToProcess := make(chan fileToProcess, i.jobs*10) // Buffered channel

	// Start worker goroutines
	for w := 0; w < i.jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range filesToProcess {
				// Use streaming hash function
				// Every file the scan drops is reported by path at the end: a message that
				// never reaches the cache is otherwise invisible to every later count.
				hash, size, err := hashFile(file.path)
				if err != nil {
					logger.Warn("Failed to hash file", "path", file.path, "error", err)
					i.recordFailedPath(file.path, fmt.Sprintf("read/hash error: %v", err))
					atomic.AddInt64(&i.failedMessages, 1)
					continue
				}

				// Validate message
				if err := i.validateMessage(size); err != nil {
					logger.Warn("Invalid message", "path", file.path, "error", err)
					i.recordFailedPath(file.path, fmt.Sprintf("invalid message: %v", err))
					atomic.AddInt64(&i.failedMessages, 1)
					continue
				}

				// Always store in SQLite database for tracking
				// Try to insert, relying on unique constraints to prevent duplicates
				// This operation is thread-safe with the "sqlite" driver.
				_, err = i.sqliteDB.Exec("INSERT OR IGNORE INTO messages (path, filename, hash, size, mailbox) VALUES (?, ?, ?, ?, ?)",
					file.path, file.filename, hash, size, file.mailboxName)
				if err != nil {
					logger.Warn("Failed to insert message into sqlite db", "path", file.path, "error", err)
					i.recordFailedPath(file.path, fmt.Sprintf("cache insert error: %v", err))
					atomic.AddInt64(&i.failedMessages, 1)
					continue
				}
			}
		}()
	}

	// --- Filesystem Walk (Producer) ---
	var walkErr error
	if i.options.PathsFile != "" {
		walkErr = i.processPathsFile(cleanPath, filesToProcess)
	} else {
		walkErr = filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
			select {
			case <-i.ctx.Done():
				return i.ctx.Err() // Stop walking if context is cancelled.
			default:
			}
			if err != nil {
				return err
			}

			// We are looking for directories that are maildir folders.
			if !info.IsDir() {
				return nil
			}

			// Security check: ensure path is within maildir. filepath.Rel rejects
			// sibling-prefix bypasses (e.g. /srv/maildir-evil vs /srv/maildir) that a
			// strings.HasPrefix check would allow.
			if rel, relErr := filepath.Rel(cleanPath, filepath.Clean(path)); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("path outside maildir: %s", path)
			}

			// Check if this directory is a maildir folder
			if !isMaildirFolder(path) {
				// This is not a maildir folder, continue walking.
				return nil
			}

			// Determine mailbox name
			relPath, err := filepath.Rel(cleanPath, path)
			if err != nil {
				return fmt.Errorf("could not get relative path for %s: %w", path, err)
			}

			mailboxName, err := i.resolveMailboxName(path)
			if err != nil {
				logger.Info("Warning: Skipping maildir folder", "path", relPath, "error", err)
				return nil
			}

			logger.Info("Processing maildir folder", "path", relPath, "mailbox", mailboxName, "has_delimiter", strings.Contains(mailboxName, "/"))

			// Check if this mailbox should be imported
			if !i.shouldImportMailbox(mailboxName) {
				logger.Info("Skipping mailbox (filtered)", "mailbox", mailboxName)
				return nil
			}

			// This is a maildir folder, process the messages within it.
			// Only scan 'cur' and 'new' directories (skip 'tmp' as it contains incomplete messages)
			for _, subDir := range []string{"cur", "new"} {
				messages, err := os.ReadDir(filepath.Join(path, subDir))
				if err != nil {
					logger.Info("Failed to read directory", "path", filepath.Join(path, subDir), "error", err)
					continue
				}

				for _, message := range messages {
					if message.IsDir() {
						continue
					}

					if isValidMaildirMessage(message.Name()) {
						filesToProcess <- fileToProcess{
							path:        filepath.Join(path, subDir, message.Name()),
							filename:    message.Name(),
							mailboxName: mailboxName,
						}
					}
				}
			}

			// Parse dovecot-uidlist if preserving UIDs
			if i.options.PreserveUIDs {
				uidList, err := ParseDovecotUIDList(path)
				if err != nil {
					logger.Info("Warning: Failed to parse dovecot-uidlist", "path", path, "error", err)
				} else if uidList != nil {
					i.dovecotUIDLists[path] = uidList
					logger.Info("Loaded dovecot-uidlist", "mailbox", mailboxName,
						"uidvalidity", uidList.UIDValidity, "next_uid", uidList.NextUID, "mappings", len(uidList.UIDMappings))
				}
			}

			// Do not skip the directory, so we can find nested maildir folders.
			return nil
		})
	}

	// Close the channel to signal workers that there are no more files.
	close(filesToProcess)

	// Wait for all workers to finish processing.
	wg.Wait()

	return walkErr
}

// syncMailboxState ensures mailboxes exist and have correct UIDVALIDITY
func (i *Importer) syncMailboxState() error {
	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}
	user := server.NewUser(address, accountID)

	for path, uidList := range i.dovecotUIDLists {
		if uidList == nil {
			continue
		}

		mailboxName, err := i.resolveMailboxName(path)
		if err != nil {
			logger.Info("Warning: Failed to resolve mailbox name for state sync", "path", path, "error", err)
			continue
		}

		if !i.shouldImportMailbox(mailboxName) {
			continue
		}

		// Get or create the mailbox. A dry run only looks it up, among the account's own
		// mailboxes as getOrCreateMailbox does: a same-named mailbox another owner shares
		// with the account is not the one the import would change.
		var mailboxID int64
		if i.options.DryRun {
			mailboxID, err = i.rdb.GetOwnedMailboxIDByNameWithRetry(i.ctx, user.AccountID(), mailboxName)
			if errors.Is(err, consts.ErrMailboxNotFound) {
				logger.Info("DRY RUN: Would create mailbox with the Dovecot UIDVALIDITY", "mailbox", mailboxName,
					"uidvalidity", uidList.UIDValidity)
				continue
			}
		} else {
			var mailbox *db.DBMailbox
			if mailbox, err = i.getOrCreateMailbox(i.ctx, user.AccountID(), mailboxName); err == nil {
				mailboxID = mailbox.ID
			}
		}
		if err != nil {
			logger.Info("Warning: Failed to get/create mailbox for state sync", "mailbox", mailboxName, "error", err)
			continue
		}

		// Update UIDVALIDITY if needed
		// We only update if the mailbox is empty OR if we're forcing it.
		// Since we can't easily check if it's empty here without extra queries,
		// and we want to enforce Dovecot state, we'll try to update it.
		//
		// Ideally, we should only update if empty. db.InsertMessageFromImporter handles this check safely.
		// But to prevent the "first message missing UID" issue, we'll do a check here.

		var currentUIDValidity uint32
		var hasMessages bool

		// Use the operational database for direct queries
		db := i.rdb.GetOperationalDatabase()

		// Check current state
		err = db.WritePool.QueryRow(i.ctx, `
			SELECT m.uid_validity, EXISTS(SELECT 1 FROM messages msg WHERE msg.mailbox_id = m.id AND msg.expunged_at IS NULL)
			FROM mailboxes m
			WHERE m.id = $1
		`, mailboxID).Scan(&currentUIDValidity, &hasMessages)

		if err != nil {
			logger.Info("Warning: Failed to check mailbox state", "mailbox", mailboxName, "error", err)
			continue
		}

		if currentUIDValidity == uidList.UIDValidity {
			// Already matches
			continue
		}

		if hasMessages {
			logger.Info("Warning: Mailbox not empty and UIDVALIDITY mismatch - cannot safely update",
				"mailbox", mailboxName, "current", currentUIDValidity, "dovecot", uidList.UIDValidity)
			// We do NOT force update here to avoid invalidating existing messages unexpectedly.
			// Users should use --clean-db or ensure mailboxes are empty if they want full UID preservation.
			continue
		}

		// Mailbox is empty, safe to update UIDVALIDITY and highest_uid
		// Set highest_uid = NextUID - 1 to match Dovecot's sequence exactly
		// This prevents UID gaps/collisions if some UIDs were not imported
		highestUID := int64(0)
		if uidList.NextUID > 0 {
			highestUID = int64(uidList.NextUID) - 1
		}

		if i.options.DryRun {
			logger.Info("DRY RUN: Would update UIDVALIDITY and highest_uid", "mailbox", mailboxName,
				"old_uidvalidity", currentUIDValidity, "new_uidvalidity", uidList.UIDValidity,
				"highest_uid", highestUID)
			continue
		}

		_, err = db.WritePool.Exec(i.ctx, `UPDATE mailboxes SET uid_validity = $2, highest_uid = $3 WHERE id = $1`,
			mailboxID, uidList.UIDValidity, highestUID)
		if err != nil {
			logger.Info("Warning: Failed to update UIDVALIDITY and highest_uid", "mailbox", mailboxName, "error", err)
		} else {
			logger.Info("Updated UIDVALIDITY and highest_uid", "mailbox", mailboxName,
				"old_uidvalidity", currentUIDValidity, "new_uidvalidity", uidList.UIDValidity,
				"highest_uid", highestUID)
		}
	}

	return nil
}

// findMovedFile attempts to find a file that has been renamed (e.g. flags changed)
// It looks for a file in the same directory with the same unique ID prefix.
func (i *Importer) findMovedFile(originalPath string) (string, bool) {
	dir := filepath.Dir(originalPath)
	filename := filepath.Base(originalPath)

	// Dovecot Maildir format: unique_id:2,flags
	// We want to match the unique_id part.
	// The separator is usually ":2,".
	parts := strings.SplitN(filename, ":2,", 2)
	if len(parts) != 2 {
		return "", false
	}
	prefix := parts[0] + ":2,"

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Look for a file that starts with the same prefix but has different flags
		if strings.HasPrefix(name, prefix) && name != filename {
			return filepath.Join(dir, name), true
		}
	}

	return "", false
}

// shouldSkipMessage applies date filters
func (i *Importer) shouldSkipMessage(path string) bool {
	if i.options.StartDate == nil && i.options.EndDate == nil {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	modTime := info.ModTime()
	if i.options.StartDate != nil && modTime.Before(*i.options.StartDate) {
		return true
	}
	if i.options.EndDate != nil && modTime.After(*i.options.EndDate) {
		return true
	}
	return false
}

// getOrCreateMailbox returns cached mailbox or fetches/creates it
func (i *Importer) getOrCreateMailbox(ctx context.Context, AccountID int64, name string) (*db.DBMailbox, error) {
	// First, check with a read lock for high concurrency
	i.cacheMu.RLock()
	mailbox, ok := i.mailboxCache[name]
	i.cacheMu.RUnlock()
	if ok {
		return mailbox, nil
	}

	// Not in cache, so acquire a write lock to fetch/create and update the cache
	i.cacheMu.Lock()
	defer i.cacheMu.Unlock()

	// Double-check, in case another goroutine created it while we were waiting for the lock
	if mailbox, ok := i.mailboxCache[name]; ok {
		return mailbox, nil
	}

	// Still not there, so we are responsible for creating it
	// This single call handles both getting and creating, avoiding a redundant lookup.
	mailbox, err := i.rdb.GetOrCreateMailboxByNameWithRetry(ctx, AccountID, name)

	if err == nil {
		i.mailboxCache[name] = mailbox // Cache the result
	}
	return mailbox, err
}

// maildirContentReader returns a reader over the message stored in a maildir file: the file
// itself, or its decompression when Dovecot's zlib plugin stored it gzip- or bzip2-
// compressed (mail_compression_save = gz / bz2). compressed reports which. The scan's hash
// and the upload both read through it, so they always see the same bytes.
func maildirContentReader(r io.Reader) (content io.Reader, compressed bool, err error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil && err != io.EOF {
		return nil, false, err
	}

	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, false, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return zr, true, nil
	case len(magic) == 4 && magic[0] == 'B' && magic[1] == 'Z' && magic[2] == 'h' && magic[3] >= '1' && magic[3] <= '9':
		// bzip2: "BZh" + block size digit.
		return bzip2.NewReader(br), true, nil
	// Compressions this tool cannot read must fail loudly: hashing and uploading the
	// compressed bytes as if they were the message would store garbage under a valid-
	// looking hash (Dovecot's zlib plugin also writes zstd and lz4).
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		return nil, false, fmt.Errorf("zstd-compressed maildir file is not supported; decompress it first")
	case len(magic) == 4 && magic[0] == 0x04 && magic[1] == 0x22 && magic[2] == 0x4d && magic[3] == 0x18:
		return nil, false, fmt.Errorf("lz4-compressed maildir file is not supported; decompress it first")
	}
	return br, false, nil
}

// decompressIfNeeded returns the message stored in a maildir file's content (see
// maildirContentReader): the content itself, or its decompression.
func decompressIfNeeded(content []byte) ([]byte, error) {
	reader, compressed, err := maildirContentReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	if !compressed {
		return content, nil
	}

	// Bound decompression to avoid a gzip or bzip2 bomb exhausting memory.
	const maxDecompressedSize = 256 << 20 // 256 MiB
	decompressed, err := io.ReadAll(io.LimitReader(reader, maxDecompressedSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress content: %w", err)
	}
	if len(decompressed) > maxDecompressedSize {
		return nil, fmt.Errorf("decompressed content exceeds %d bytes", maxDecompressedSize)
	}
	return decompressed, nil
}

// parseMessageMetadata extracts metadata from message content
func (i *Importer) parseMessageMetadata(content []byte, filename, path string) (*messageMetadata, error) {
	// Parse email
	messageContent, err := server.ParseMessage(bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	mailHeader := mail.Header{Header: messageContent.Header}

	subject, _ := mailHeader.Subject()
	messageID, _ := mailHeader.MessageID()
	sentDate, _ := mailHeader.Date()
	inReplyTo, _ := mailHeader.MsgIDList("In-Reply-To")
	references, _ := mailHeader.MsgIDList("References")

	if len(inReplyTo) == 0 {
		inReplyTo = nil
	}
	if len(references) == 0 {
		references = nil
	}

	// If the Date header is missing or invalid, fall back to the file's modification time.
	// This is a more accurate timestamp than time.Now().
	if sentDate.IsZero() {
		if info, statErr := os.Stat(path); statErr == nil {
			sentDate = info.ModTime()
		} else {
			// As a last resort, use the current time.
			sentDate = time.Now()
		}
	}

	bodyStructure := imapserver.ExtractBodyStructure(bytes.NewReader(content))

	// Validate body structure and use fallback if invalid (e.g., multipart with no children)
	if err := helpers.ValidateBodyStructure(&bodyStructure); err != nil {
		logger.Warn("Invalid body structure in message, using fallback", "file", filename, "error", err)
		fallback := &imap.BodyStructureSinglePart{
			Type:    "text",
			Subtype: "plain",
			Size:    uint32(len(content)),
			Text:    &imap.BodyStructureText{}, // body-fld-lines is mandatory for a text part
		}
		bodyStructure = fallback
	}

	extractedPlaintext, _ := helpers.ExtractPlaintextBody(messageContent)
	var plaintextBody string
	if extractedPlaintext != nil {
		plaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	// Flags
	var flags []imap.Flag
	if i.options.PreserveFlags {
		flags = i.parseMaildirFlagsWith(filename, i.keywordsForMessagePath(path))
	} else {
		// \Recent must not be persisted; return no flags by default.
		flags = nil
	}

	// Preserved UIDs
	var preservedUID *uint32
	var preservedUIDValidity *uint32
	if i.options.PreserveUIDs {
		maildirPath := filepath.Dir(filepath.Dir(path))
		if uidList, ok := i.dovecotUIDLists[maildirPath]; ok && uidList != nil {
			if uid, found := uidList.GetUIDForFile(filename); found {
				preservedUID = &uid
				preservedUIDValidity = &uidList.UIDValidity
			}
		}
	}

	// Get account info (cached at importer level)
	address, _ := server.NewAddress(i.email)

	return &messageMetadata{
		domain:               address.Domain(),
		localpart:            address.LocalPart(),
		accountID:            0, // Set in insertBatchToDB
		messageID:            messageID,
		subject:              subject,
		plaintextBody:        plaintextBody,
		sentDate:             sentDate,
		internalDate:         maildirInternalDate(filename, path, sentDate),
		inReplyTo:            inReplyTo,
		references:           references,
		bodyStructure:        &bodyStructure,
		recipients:           recipients,
		flags:                flags,
		preservedUID:         preservedUID,
		preservedUIDValidity: preservedUIDValidity,
	}, nil
}

// uploadBatchToS3 uploads messages to S3 in parallel using a worker pool
func (i *Importer) uploadBatchToS3(batch []msgInfo) []uploadedMsg {
	var (
		uploaded []uploadedMsg
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	// Use semaphore to limit concurrent uploads
	sem := make(chan struct{}, i.jobs) // Reuse jobs config

	for _, msg := range batch {
		wg.Add(1)
		sem <- struct{}{} // Acquire

		go func(msg msgInfo) {
			defer wg.Done()
			defer func() { <-sem }() // Release

			// Check for cancellation before starting work
			select {
			case <-i.ctx.Done():
				return
			default:
			}

			// Read file
			content, err := os.ReadFile(msg.path)
			if err != nil {
				// If file not found, it might have been renamed (e.g. flags changed)
				// Try to find it by unique ID prefix
				if os.IsNotExist(err) {
					if newPath, found := i.findMovedFile(msg.path); found {
						logger.Info("File moved, found at new path", "old", msg.path, "new", newPath)
						msg.path = newPath
						msg.filename = filepath.Base(newPath)
						content, err = os.ReadFile(newPath)
					}
				}

				if err != nil {
					logger.Warn("Failed to read file", "path", msg.path, "error", err)
					i.recordFailedPath(msg.path, fmt.Sprintf("read error: %v", err))
					atomic.AddInt64(&i.failedMessages, 1)
					return
				}
			}

			// Decompress if Dovecot stored the file compressed
			content, err = decompressIfNeeded(content)
			if err != nil {
				logger.Warn("Failed to decompress file", "path", msg.path, "error", err)
				i.recordFailedPath(msg.path, fmt.Sprintf("decompression error: %v", err))
				atomic.AddInt64(&i.failedMessages, 1)
				return
			}

			// The hash in the SQLite cache was computed at scan time — possibly by an
			// earlier run, since the scan keeps the first row for a (filename, mailbox).
			// The bytes about to be uploaded are what counts: they name the S3 key and
			// the content_hash of the database row. If the file changed in place under
			// the same name, uploading the new bytes under the old hash would overwrite
			// the object an existing row references, with no signal anywhere.
			//
			// One mismatch is not a change: a sora-admin from before the switch to
			// helpers.HashContent imported the unchanged file under the SHA-256 of its
			// content. That hash is kept, so the batch insert recognises the row the
			// earlier run inserted (its duplicate check is on message_id and content_hash)
			// instead of importing the message a second time under the new hash.
			if got := helpers.HashContent(content); got != msg.hash &&
				!(msg.imported && msg.hash == legacyImportHash(content)) {
				logger.Warn("File content changed since the scan; using its current hash",
					"path", msg.path, "scanned_hash", msg.hash, "current_hash", got)
				if _, uerr := i.sqliteDB.Exec("UPDATE messages SET hash = ?, size = ?, s3_uploaded = 0 WHERE path = ? AND mailbox = ?",
					got, len(content), msg.path, msg.mailbox); uerr != nil {
					logger.Warn("Failed to update the cached hash", "path", msg.path, "error", uerr)
					i.recordFailedPath(msg.path, fmt.Sprintf("content changed since scan and the cache could not be updated: %v", uerr))
					atomic.AddInt64(&i.failedMessages, 1)
					return
				}
				msg.hash = got
				msg.size = int64(len(content))
			}

			// Check for cancellation after I/O
			select {
			case <-i.ctx.Done():
				return
			default:
			}

			// Parse message
			metadata, err := i.parseMessageMetadata(content, msg.filename, msg.path)
			if err != nil {
				logger.Warn("Failed to parse message", "path", msg.path, "error", err)
				i.recordFailedPath(msg.path, fmt.Sprintf("parse error: %v", err))
				atomic.AddInt64(&i.failedMessages, 1)
				return
			}

			// Check for cancellation before S3 upload
			select {
			case <-i.ctx.Done():
				return
			default:
			}

			// Upload to S3 (FileBasedS3Mock now has proper locking for directory creation)
			if !i.options.TestMode && i.s3 != nil {
				s3Key := helpers.NewS3Key(metadata.domain, metadata.localpart, msg.hash)

				var s3Err error
				maxRetries := 3
				backoff := 500 * time.Millisecond
				for attempt := 1; attempt <= maxRetries; attempt++ {
					if attempt > 1 {
						time.Sleep(backoff)
						backoff *= 2
						logger.Info("Retrying S3 upload", "path", msg.path, "attempt", attempt)
					}
					s3Err = i.s3.Put(s3Key, bytes.NewReader(content), int64(len(content)))
					if s3Err == nil {
						break
					}
				}

				if s3Err != nil {
					logger.Warn("S3 upload failed after retries", "path", msg.path, "error", s3Err)
					i.recordFailedPath(msg.path, fmt.Sprintf("s3 upload error: %v", s3Err))
					atomic.AddInt64(&i.failedMessages, 1)
					return
				}
			}

			// Success - add to uploaded list
			mu.Lock()
			uploaded = append(uploaded, uploadedMsg{
				msg:      msg,
				content:  content,
				metadata: metadata,
			})
			mu.Unlock()
		}(msg)
	}

	wg.Wait()
	return uploaded
}

// insertBatchToDB inserts all uploaded messages in a batch
// It groups messages by mailbox and uses the highly-optimized InsertMessagesFromImporterBatchWithRetry
func (i *Importer) insertBatchToDB(uploaded []uploadedMsg) ([]markedMessage, error) {
	// Get user info once
	address, err := server.NewAddress(i.email)
	if err != nil {
		return nil, fmt.Errorf("invalid email address format: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}
	user := server.NewUser(address, accountID)

	var successHashes []markedMessage

	// Group messages by mailbox to take advantage of batch inserts
	type groupedMsg struct {
		opt  *db.InsertMessageOptions
		hash string
		path string
	}

	mailboxGroups := make(map[string][]groupedMsg)

	for _, up := range uploaded {
		// Get/create mailbox (cached)
		mailbox, err := i.getOrCreateMailbox(i.ctx, user.AccountID(), up.msg.mailbox)
		if err != nil {
			logger.Error("Failed to get or create mailbox", "mailbox", up.msg.mailbox, "error", err)
			i.recordFailedPath(up.msg.path, fmt.Sprintf("mailbox error: %v", err))
			atomic.AddInt64(&i.failedMessages, 1)
			continue
		}

		opt := &db.InsertMessageOptions{
			AccountID:            user.AccountID(),
			MailboxID:            mailbox.ID,
			S3Domain:             address.Domain(),
			S3Localpart:          address.LocalPart(),
			MailboxName:          mailbox.Name,
			ContentHash:          up.msg.hash,
			MessageID:            up.metadata.messageID,
			Flags:                up.metadata.flags,
			InternalDate:         up.metadata.internalDate,
			Size:                 int64(len(up.content)),
			Subject:              up.metadata.subject,
			PlaintextBody:        up.metadata.plaintextBody,
			SentDate:             up.metadata.sentDate,
			InReplyTo:            up.metadata.inReplyTo,
			References:           up.metadata.references,
			BodyStructure:        up.metadata.bodyStructure,
			Recipients:           up.metadata.recipients,
			PreservedUID:         up.metadata.preservedUID,
			PreservedUIDValidity: up.metadata.preservedUIDValidity,
			FTSRetention:         i.options.FTSRetention,
		}
		mailboxGroups[up.msg.mailbox] = append(mailboxGroups[up.msg.mailbox], groupedMsg{
			opt:  opt,
			hash: up.msg.hash,
			path: up.msg.path,
		})
	}

	const maxBatchSize = 500

	for mailboxName, group := range mailboxGroups {
		for idx := 0; idx < len(group); idx += maxBatchSize {
			end := idx + maxBatchSize
			if end > len(group) {
				end = len(group)
			}
			chunk := group[idx:end]

			opts := make([]*db.InsertMessageOptions, 0, len(chunk))
			for _, gm := range chunk {
				opts = append(opts, gm.opt)
			}

			_, _, insertedHashesBatch, err := i.rdb.InsertMessagesFromImporterBatchWithRetry(i.ctx, opts)
			if err != nil {
				{
					// The batch failed as a whole — a unique violation the dedup did not
					// catch, or one message that could not be prepared (the batch refuses
					// to drop it silently). Either way the batch says nothing about which
					// message is at fault, so fall back to inserting them one by one: the
					// per-message path reports each duplicate, UID conflict or failure
					// by path instead of writing off the chunk.
					logger.Info("Batch insert failed, falling back to individual inserts", "mailbox_id", opts[0].MailboxID, "chunk_size", len(chunk), "error", err)
					for _, gm := range chunk {
						_, _, indErr := i.rdb.InsertMessageFromImporterWithRetry(i.ctx, gm.opt)
						if indErr != nil {
							if errors.Is(indErr, consts.ErrUIDConflict) {
								// The preserved UID is already taken in the target mailbox: the
								// message was NOT stored. A "skip" would hide a lost message.
								logger.Error("Preserved UID already in use, message not imported", "path", gm.path, "hash", gm.hash)
								i.recordFailedPath(gm.path, "preserved UID already in use in the target mailbox (re-run without --preserve-uids to import it)")
								atomic.AddInt64(&i.failedMessages, 1)
								continue
							}
							if errors.Is(indErr, consts.ErrDBUniqueViolation) {
								atomic.AddInt64(&i.skippedMessages, 1)
								continue
							}
							logger.Error("DB insert failed for message", "hash", gm.hash, "error", indErr)
							i.recordFailedPath(gm.path, fmt.Sprintf("db insert error: %v", indErr))
							atomic.AddInt64(&i.failedMessages, 1)
							continue
						}
						successHashes = append(successHashes, markedMessage{hash: gm.hash, mailbox: mailboxName})
					}
					continue
				}
			}

			// Add successfully inserted hashes to successHashes, tagged with the mailbox
			// this group belongs to so the cache row for this copy is the one marked.
			for _, hash := range insertedHashesBatch {
				successHashes = append(successHashes, markedMessage{hash: hash, mailbox: mailboxName})
			}

			// Calculate skipped messages (deduplicated by the database)
			skipped := len(chunk) - len(insertedHashesBatch)
			if skipped > 0 {
				atomic.AddInt64(&i.skippedMessages, int64(skipped))
			}
		}
	}

	return successHashes, nil
}

// insertBatchToDBWithTransaction inserts all uploaded messages in a SINGLE transaction
// This is faster (20x) but less resilient - if one message fails, entire batch rolls back
func (i *Importer) insertBatchToDBWithTransaction(uploaded []uploadedMsg) ([]markedMessage, error) {
	// Get user info once
	address, err := server.NewAddress(i.email)
	if err != nil {
		return nil, fmt.Errorf("invalid email address format: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return nil, fmt.Errorf("account not found: %w", err)
	}
	user := server.NewUser(address, accountID)

	var successHashes []markedMessage

	// Begin a single transaction for the entire batch
	tx, err := i.rdb.BeginTxWithRetry(i.ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(context.Background())

	// Get the underlying database for direct access to InsertMessageFromImporter
	database := i.rdb.GetOperationalDatabase()

	// Track mailbox IDs for rollback compensation
	var successList []struct {
		hash      string
		mailboxID int64
	}

	// Process all messages in this single transaction
	for _, up := range uploaded {
		// Get/create mailbox (cached)
		mailbox, err := i.getOrCreateMailbox(i.ctx, user.AccountID(), up.msg.mailbox)
		if err != nil {
			return nil, fmt.Errorf("failed to get or create mailbox '%s': %w", up.msg.mailbox, err)
		}

		// Insert using the transaction handle (no retry wrapper - transaction handles atomicity)
		_, _, err = database.InsertMessageFromImporter(i.ctx, tx, &db.InsertMessageOptions{
			AccountID:            user.AccountID(),
			MailboxID:            mailbox.ID,
			S3Domain:             address.Domain(),
			S3Localpart:          address.LocalPart(),
			MailboxName:          mailbox.Name,
			ContentHash:          up.msg.hash,
			MessageID:            up.metadata.messageID,
			Flags:                up.metadata.flags,
			InternalDate:         up.metadata.internalDate,
			Size:                 int64(len(up.content)),
			Subject:              up.metadata.subject,
			PlaintextBody:        up.metadata.plaintextBody,
			SentDate:             up.metadata.sentDate,
			InReplyTo:            up.metadata.inReplyTo,
			References:           up.metadata.references,
			BodyStructure:        up.metadata.bodyStructure,
			Recipients:           up.metadata.recipients,
			PreservedUID:         up.metadata.preservedUID,
			PreservedUIDValidity: up.metadata.preservedUIDValidity,
			FTSRetention:         i.options.FTSRetention,
		})

		if err != nil {
			if errors.Is(err, consts.ErrUIDConflict) {
				// The preserved UID is already taken in the target mailbox: this message
				// was NOT stored. Report it as failed (never as a dedup skip) and go on
				// with the batch.
				logger.Error("Preserved UID already in use, message not imported", "path", up.msg.path, "hash", up.msg.hash)
				i.recordFailedPath(up.msg.path, "preserved UID already in use in the target mailbox (re-run without --preserve-uids to import it)")
				atomic.AddInt64(&i.failedMessages, 1)
				continue
			}
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				// Message already exists - skip but continue processing batch
				atomic.AddInt64(&i.skippedMessages, 1)
				continue
			}
			// Non-recoverable error - rollback entire batch (defer handles this)
			return nil, fmt.Errorf("failed to insert message (hash: %s): %w", up.msg.hash, err)
		}

		successList = append(successList, struct {
			hash      string
			mailboxID int64
		}{
			hash:      up.msg.hash,
			mailboxID: mailbox.ID,
		})
		successHashes = append(successHashes, markedMessage{hash: up.msg.hash, mailbox: up.msg.mailbox})
	}

	// Commit the PostgreSQL transaction first
	if err := tx.Commit(i.ctx); err != nil {
		return nil, fmt.Errorf("failed to commit batch transaction: %w", err)
	}

	// CRITICAL: Mark in SQLite AFTER PostgreSQL commit
	// If SQLite update fails, we have messages in PG but not marked in cache
	// This is safe: next run will try to re-import, S3 upload is idempotent,
	// and PG insert will return ErrDBUniqueViolation (we skip and continue)
	if err := i.markBatchInSQLite(successHashes); err != nil {
		// PostgreSQL already committed - we can't rollback
		// Log the error and try to delete from PostgreSQL to maintain consistency
		logger.Error("Failed to update SQLite cache after PG commit - attempting rollback compensation",
			"error", err, "batch_size", len(successHashes))

		// Attempt to delete the just-inserted messages from PostgreSQL
		accountID, accErr := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, i.email)
		if accErr != nil {
			logger.Error("CRITICAL: Failed to get account ID for rollback - messages orphaned in PostgreSQL",
				"error", accErr, "original_error", err, "batch_size", len(successHashes))
			return nil, fmt.Errorf("failed to update SQLite cache and cannot rollback (messages orphaned): %w", err)
		}

		if rollbackErr := i.rollbackBatchFromPostgreSQL(accountID, successList); rollbackErr != nil {
			// Both SQLite update AND compensation failed - messages are in PG only
			// Recovery mechanism will NOT fix this (it only resets SQLite orphans)
			logger.Error("CRITICAL: Rollback compensation failed - messages orphaned in PostgreSQL",
				"error", rollbackErr, "original_error", err, "batch_size", len(successHashes))
			return nil, fmt.Errorf("failed to update SQLite cache and rollback compensation failed (messages orphaned): %w", err)
		}

		// Compensation succeeded - messages removed from PostgreSQL
		logger.Info("Rollback compensation succeeded - batch reverted", "batch_size", len(successHashes))
		return nil, fmt.Errorf("failed to update SQLite cache (batch reverted): %w", err)
	}

	return successHashes, nil
}

// rollbackBatchFromPostgreSQL deletes messages from PostgreSQL by hash and mailbox
// Used for rollback compensation when SQLite update fails after PG commit
func (i *Importer) rollbackBatchFromPostgreSQL(accountID int64, successList []struct {
	hash      string
	mailboxID int64
}) error {
	if len(successList) == 0 {
		return nil
	}

	var deletedCount int64
	var failedCount int64

	for _, item := range successList {
		_, err := i.rdb.DeleteMessageByHashAndMailboxWithRetry(i.ctx, accountID, item.mailboxID, item.hash)
		if err != nil {
			if errors.Is(err, consts.ErrDBNotFound) {
				// Message already gone - that's fine
				continue
			}
			// Real error - log but continue trying others
			logger.Error("Failed to delete message during rollback compensation",
				"hash", shortHash(item.hash), "mailbox_id", item.mailboxID, "error", err)
			failedCount++
			continue
		}
		deletedCount++
	}

	if failedCount > 0 {
		return fmt.Errorf("rollback compensation partially failed: deleted %d, failed %d of %d messages",
			deletedCount, failedCount, len(successList))
	}

	logger.Info("Rollback compensation completed", "deleted", deletedCount, "attempted", len(successList))
	return nil
}

// markBatchInS QLite marks messages as uploaded in SQLite cache
// Called AFTER PostgreSQL commit in batch mode
// shortHash abbreviates a content hash for logging. It is length-safe: these strings
// reach the log from error paths, and a panic while reporting an error loses the error.
func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}

// markedMessage identifies one cached row to mark imported. The SQLite cache is keyed
// UNIQUE(hash, mailbox), so the mailbox is part of the identity: the same content can be
// filed in several mailboxes and each copy needs its own PostgreSQL row.
type markedMessage struct {
	hash    string
	mailbox string
}

func (i *Importer) markBatchInSQLite(marked []markedMessage) error {
	if len(marked) == 0 {
		return nil
	}

	logger.Info("Marking batch in SQLite", "count", len(marked))

	// Create a context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(i.ctx, 30*time.Second)
	defer cancel()

	// Use a channel to handle the transaction with timeout
	type result struct {
		err error
	}
	done := make(chan result, 1)

	go func() {
		tx, err := i.sqliteDB.Begin()
		if err != nil {
			done <- result{err: fmt.Errorf("failed to begin SQLite transaction: %w", err)}
			return
		}
		defer tx.Rollback()

		logger.Info("SQLite transaction started")

		// Scoped to (hash, mailbox): s3_uploaded is what an incremental import filters
		// on, so marking by hash alone would hide every other mailbox's copy of this
		// content from the next run even though it was never imported.
		stmt, err := tx.Prepare(`
			UPDATE messages
			SET s3_uploaded = 1, s3_uploaded_at = ?
			WHERE hash = ? AND mailbox = ?
		`)
		if err != nil {
			done <- result{err: fmt.Errorf("failed to prepare SQLite statement: %w", err)}
			return
		}
		defer stmt.Close()

		logger.Info("SQLite statement prepared, executing updates")

		now := time.Now()
		for idx, m := range marked {
			if _, err := stmt.Exec(now, m.hash, m.mailbox); err != nil {
				done <- result{err: fmt.Errorf("failed to update SQLite for hash %s in %s: %w",
					shortHash(m.hash), m.mailbox, err)}
				return
			}
			if (idx+1)%5 == 0 {
				logger.Info("SQLite update progress", "completed", idx+1, "total", len(marked))
			}
		}

		logger.Info("All SQLite updates executed, committing")

		if err := tx.Commit(); err != nil {
			done <- result{err: fmt.Errorf("failed to commit SQLite transaction: %w", err)}
			return
		}

		logger.Info("SQLite transaction committed successfully")
		done <- result{err: nil}
	}()

	// Wait for completion or timeout
	select {
	case res := <-done:
		return res.err
	case <-ctx.Done():
		return fmt.Errorf("SQLite transaction timed out after 30 seconds")
	}
}

// processBatch processes a batch of messages with sequential S3 uploads
// and transactional DB inserts
func (i *Importer) processBatch(batch []msgInfo) error {
	logger.Info("Processing batch", "size", len(batch),
		"progress", i.getProgressPrefix())

	// Phase 1: Sequential S3 uploads (no DB state modified yet)
	uploaded := i.uploadBatchToS3(batch)

	logger.Info("Upload phase complete", "uploaded", len(uploaded), "batch_size", len(batch))

	if len(uploaded) == 0 {
		logger.Warn("All S3 uploads in batch failed")
		atomic.AddInt64(&i.failedMessages, int64(len(batch)))
		return nil
	}

	logger.Info("Starting DB insert phase", "count", len(uploaded))

	// Phase 2: DB inserts (strategy depends on BatchTransactionMode flag)
	var successHashes []markedMessage
	var err error

	if i.options.BatchTransactionMode {
		// Fast path: Single transaction for entire batch (20x faster)
		// SQLite is updated BEFORE PostgreSQL commit (atomicity guaranteed)
		logger.Info("Using batch transaction mode")
		successHashes, err = i.insertBatchToDBWithTransaction(uploaded)
	} else {
		// Safe path: Individual transactions per message (more resilient)
		// Need to update SQLite after since each message commits individually
		logger.Info("Using individual transaction mode")
		successHashes, err = i.insertBatchToDB(uploaded)
		if err != nil {
			// insertBatchToDB fails only before it stores anything (address or
			// account lookup), so none of the batch was imported.
			logger.Error("DB inserts failed", "error", err)
			for _, up := range uploaded {
				i.recordFailedPath(up.msg.path, fmt.Sprintf("db insert error: %v", err))
			}
			atomic.AddInt64(&i.failedMessages, int64(len(uploaded)))
			return err
		}

		logger.Info("DB inserts complete, marking in SQLite", "count", len(successHashes))

		// Phase 3: Mark successful messages in SQLite cache
		// For safe mode, this happens AFTER individual commits
		if err := i.markBatchInSQLite(successHashes); err != nil {
			// FATAL: If SQLite update fails, messages will be re-imported
			logger.Error("Failed to update SQLite cache - messages may be re-imported on retry", "error", err)
			atomic.AddInt64(&i.failedMessages, int64(len(successHashes)))
			return fmt.Errorf("failed to update SQLite cache: %w", err)
		}

		logger.Info("SQLite marking complete")
	}

	if err != nil {
		logger.Error("Batch processing failed", "error", err)
		// Everything in uploaded that wasn't successfully inserted is already tracked if individual mode
		// Let's ensure BatchTransactionMode logs all if it aborted
		if i.options.BatchTransactionMode {
			for _, up := range uploaded {
				i.recordFailedPath(up.msg.path, fmt.Sprintf("batch transaction aborted: %v", err))
			}
			atomic.AddInt64(&i.failedMessages, int64(len(uploaded)))
		}
		return err
	}

	atomic.AddInt64(&i.importedMessages, int64(len(successHashes)))
	logger.Info("Batch complete", "imported", len(successHashes))
	return nil
}

// processPathsFile reads specific message paths from a file and sends them to the workers
func (i *Importer) processPathsFile(cleanPath string, filesToProcess chan<- fileToProcess) error {
	content, err := os.ReadFile(i.options.PathsFile)
	if err != nil {
		return fmt.Errorf("failed to read paths file: %w", err)
	}

	logger.Info("Processing specific paths from file", "file", i.options.PathsFile)
	lines := strings.Split(string(content), "\n")
	processedDirs := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var fullPath string
		if filepath.IsAbs(line) {
			fullPath = filepath.Clean(line)
		} else {
			fullPath = filepath.Join(cleanPath, line)
		}

		if rel, relErr := filepath.Rel(cleanPath, fullPath); relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			logger.Warn("Skipping path outside maildir", "path", line)
			continue
		}

		// Message paths are structured like dir/cur/msg_file or dir/new/msg_file
		// dir is the maildir folder root.
		dir := filepath.Dir(filepath.Dir(fullPath))

		if i.options.PreserveUIDs && !processedDirs[dir] {
			uidList, err := ParseDovecotUIDList(dir)
			if err == nil && uidList != nil {
				i.dovecotUIDLists[dir] = uidList
				logger.Info("Loaded dovecot-uidlist", "path", dir)
			}
			processedDirs[dir] = true
		}

		mailboxName, err := i.resolveMailboxName(dir)
		if err != nil {
			logger.Warn("Skipping path", "path", line, "error", err)
			continue
		}

		if !i.shouldImportMailbox(mailboxName) {
			continue
		}

		filename := filepath.Base(fullPath)
		if isValidMaildirMessage(filename) {
			filesToProcess <- fileToProcess{
				path:        fullPath,
				filename:    filename,
				mailboxName: mailboxName,
			}
		}
	}
	return nil
}

// importMessages reads from the SQLite database and imports messages into Sora using batching.
func (i *Importer) importMessages() error {
	if i.totalMessages == 0 {
		logger.Info("No messages to import")
		i.printSieveOutcome()
		return nil
	}

	// Initialize batch size
	if i.options.BatchSize == 0 {
		i.batchSize = 20 // Default
	} else {
		i.batchSize = i.options.BatchSize
	}

	// Initialize mailbox cache
	i.mailboxCache = make(map[string]*db.DBMailbox)

	// Read ALL messages into memory first, then close the cursor
	// This prevents holding the SQLite connection while processing batches
	var query string
	if i.options.Incremental {
		// Incremental mode: only load messages not yet uploaded
		query = `SELECT path, filename, hash, size, mailbox, COALESCE(s3_uploaded, 0) = 1 FROM messages WHERE s3_uploaded = 0 ORDER BY mailbox, path`
	} else {
		// Non-incremental mode: load all messages
		query = `SELECT path, filename, hash, size, mailbox, COALESCE(s3_uploaded, 0) = 1 FROM messages ORDER BY mailbox, path`
	}

	rows, err := i.sqliteDB.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query messages: %w", err)
	}

	var allMessages []msgInfo
	for rows.Next() {
		var msg msgInfo
		if err := rows.Scan(&msg.path, &msg.filename, &msg.hash,
			&msg.size, &msg.mailbox, &msg.imported); err != nil {
			logger.Info("Failed to scan row", "error", err)
			continue
		}

		// Apply filters
		if i.shouldSkipMessage(msg.path) {
			atomic.AddInt64(&i.skippedMessages, 1)
			continue
		}

		allMessages = append(allMessages, msg)
	}
	rows.Close() // CRITICAL: Close rows to release SQLite connection

	logger.Info("Loaded messages from SQLite", "count", len(allMessages))

	// Now process in batches without holding the SQLite connection
	batch := make([]msgInfo, 0, i.batchSize)

	for _, msg := range allMessages {
		// Check for cancellation
		select {
		case <-i.ctx.Done():
			logger.Info("Import cancelled by user")
			return i.ctx.Err()
		default:
		}

		batch = append(batch, msg)

		// Process when batch is full
		if len(batch) >= i.batchSize {
			if err := i.processBatch(batch); err != nil {
				logger.Warn("Batch processing had errors", "error", err)
			}
			batch = batch[:0] // Reset batch
		}
	}

	// Process remaining messages
	if len(batch) > 0 {
		if err := i.processBatch(batch); err != nil {
			logger.Warn("Final batch had errors", "error", err)
		}
	}

	// A cancellation during the final batch is not caught by the loop above, and the
	// uploads that see it return without counting a failure: such a run is not complete.
	if err := i.ctx.Err(); err != nil {
		logger.Info("Import cancelled by user")
		return err
	}

	return nil
}

// getProgressPrefix returns a progress prefix for log messages
func (i *Importer) getProgressPrefix() string {
	imported := atomic.LoadInt64(&i.importedMessages)
	failed := atomic.LoadInt64(&i.failedMessages)
	skipped := atomic.LoadInt64(&i.skippedMessages)
	total := atomic.LoadInt64(&i.totalMessages)

	processed := imported + failed + skipped
	percentage := float64(processed) * 100.0 / float64(total)

	return fmt.Sprintf("[%d/%d %.1f%%]", processed, total, percentage)
}

// parseKeywordsFile reads one dovecot-keywords file ("<index> <keyword>" per line,
// index 0-25 ↔ letters a-z in maildir filenames). Malformed lines are skipped.
func parseKeywordsFile(path string) (map[int]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read dovecot-keywords file: %w", err)
	}
	keywords := make(map[int]string)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			logger.Info("Warning: Skipping malformed dovecot-keywords line", "path", path, "line", line)
			continue
		}
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			logger.Info("Warning: Invalid keyword ID in line", "path", path, "line", line)
			continue
		}
		keywords[id] = parts[1]
	}
	return keywords, nil
}

// keywordsForMessagePath returns the keyword map that applies to a message file:
// Dovecot keeps a dovecot-keywords file PER FOLDER, each with its own index → name
// numbering, so the letters in a file under .Sent/cur/ mean whatever .Sent/dovecot-
// keywords says — not what the root file says. A folder without its own file, or
// whose file cannot be read, has no keywords: Dovecot clears the list when the file
// does not exist (maildir-keywords.c, maildir_keywords_sync), so the root map
// (INBOX's) names nothing outside the root.
// Results are cached per folder directory; safe for the parallel workers.
func (i *Importer) keywordsForMessagePath(path string) map[int]string {
	// path is <folder>/{cur,new}/<file>
	dir := filepath.Dir(filepath.Dir(path))
	i.folderKeywordsMu.Lock()
	defer i.folderKeywordsMu.Unlock()
	if kws, ok := i.folderKeywords[dir]; ok {
		return kws
	}
	keywordsPath := filepath.Join(dir, "dovecot-keywords")
	var kws map[int]string
	// Like the root (INBOX) file, read in NewImporter, a folder's file is read only
	// with --dovecot.
	if dir == filepath.Clean(i.maildirPath) {
		kws = i.dovecotKeywords
	} else if i.options.Dovecot {
		if _, err := os.Stat(keywordsPath); err == nil {
			parsed, perr := parseKeywordsFile(keywordsPath)
			if perr != nil {
				logger.Warn("Failed to read folder dovecot-keywords, importing its messages without keywords", "path", keywordsPath, "error", perr)
			} else {
				kws = parsed
				logger.Info("Loaded folder dovecot-keywords", "path", keywordsPath, "count", len(parsed))
			}
		}
	}
	i.folderKeywords[dir] = kws
	return kws
}

// maildirInternalDate is the IMAP INTERNALDATE for an imported maildir file: the time
// the message arrived, which maildir records as the leading Unix timestamp of the
// filename (what Dovecot and the exporter here write) and, failing that, as the file's
// modification time. The Date: header (sentDate) is the sender's clock, not arrival;
// using it as INTERNALDATE altered the arrival time of every imported message and
// re-stamped mtimes on export.
func maildirInternalDate(filename, path string, sentDate time.Time) time.Time {
	base := filepath.Base(filename)
	if dot := strings.IndexByte(base, '.'); dot > 0 {
		if secs, err := strconv.ParseInt(base[:dot], 10, 64); err == nil && secs > 0 {
			return time.Unix(secs, 0)
		}
	}
	if info, err := os.Stat(path); err == nil && !info.ModTime().IsZero() {
		return info.ModTime()
	}
	return sentDate
}
