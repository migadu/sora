package main

import (
	"bytes"
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

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/mail" // Import for mail.ReadMessage
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	_ "modernc.org/sqlite"
)

const (
	maxMessageSize = 100 * 1024 * 1024 // 100MB max message size
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
	PreserveUIDs         bool          // Preserve UIDs from dovecot-uidlist files
	FTSRetention         time.Duration // FTS retention period to skip old messages
	TestMode             bool          // Skip S3 uploads for testing (messages stored in DB only)
	BatchSize            int           // Number of messages to process in each batch (default: 20)
	BatchTransactionMode bool          // Use single transaction per batch (faster but less resilient, default: false)
}

// resilientDB defines the interface for database operations needed by the importer.
// This allows for mocking the database during testing.
type resilientDB interface {
	GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error)
	CreateDefaultMailboxesWithRetry(ctx context.Context, accountID int64) error
	GetMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error)
	CreateMailboxWithRetry(ctx context.Context, accountID int64, name string, parentID *int64) error
	SetMailboxSubscribedWithRetry(ctx context.Context, mailboxID, accountID int64, subscribed bool) error
	GetActiveScriptWithRetry(ctx context.Context, accountID int64) (*db.SieveScript, error)
	GetScriptByNameWithRetry(ctx context.Context, name string, accountID int64) (*db.SieveScript, error)
	UpdateScriptWithRetry(ctx context.Context, scriptID, accountID int64, name, content string) (*db.SieveScript, error)
	CreateScriptWithRetry(ctx context.Context, accountID int64, name, content string) (*db.SieveScript, error)
	SetScriptActiveWithRetry(ctx context.Context, scriptID, accountID int64, active bool) error
	QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row
	GetOrCreateMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error)
	InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error)
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
	inReplyTo            []string
	bodyStructure        *imap.BodyStructure
	recipients           []helpers.Recipient
	rawHeaders           string
	flags                []imap.Flag
	preservedUID         *uint32
	preservedUIDValidity *uint32
}

// Importer handles the maildir import process.
type Importer struct {
	ctx         context.Context // Context for cancellation support
	maildirPath string
	email       string
	jobs        int
	sqliteDB    *sql.DB // SQLite database for caching
	dbPath      string  // Path to the SQLite database file
	rdb         resilientDB
	s3          objectStorage
	options     ImporterOptions

	totalMessages    int64
	importedMessages int64
	skippedMessages  int64
	failedMessages   int64
	startTime        time.Time

	// Dovecot keyword mapping: ID -> keyword name
	dovecotKeywords map[int]string

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
	// Create SQLite database in the maildir path to persist maildir state
	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	logger.Info("Using maildir database", "path", dbPath)

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
		_, err = sqliteDB.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded INTEGER DEFAULT 1`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded column: %w", err)
		}

		_, err = sqliteDB.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded_at TIMESTAMP`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded_at column: %w", err)
		}

		// Mark all existing messages as uploaded (they were in old DB, so they're on S3)
		_, err = sqliteDB.Exec(`UPDATE messages SET s3_uploaded_at = CURRENT_TIMESTAMP WHERE s3_uploaded_at IS NULL`)
		if err != nil {
			return nil, fmt.Errorf("failed to mark existing messages as uploaded: %w", err)
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

// Close cleans up resources used by the importer.
func (i *Importer) Close() error {
	if i.sqliteDB != nil {
		if err := i.sqliteDB.Close(); err != nil {
			return fmt.Errorf("failed to close maildir database: %w", err)
		}
		if i.options.CleanupDB {
			logger.Info("Cleaning up import database", "path", i.dbPath)
			if err := os.Remove(i.dbPath); err != nil {
				return fmt.Errorf("failed to remove maildir database file: %w", err)
			}
		} else {
			logger.Info("Maildir database saved", "path", i.dbPath)
		}
	}
	return nil
}

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

	// Query SQLite for messages marked as uploaded
	rows, err := i.sqliteDB.Query("SELECT hash FROM messages WHERE s3_uploaded = 1 LIMIT 1000")
	if err != nil {
		return fmt.Errorf("failed to query SQLite: %w", err)
	}
	defer rows.Close()

	var orphanedHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			continue
		}

		// Check if this message exists in PostgreSQL
		var exists bool
		err = i.rdb.QueryRowWithRetry(i.ctx,
			"SELECT EXISTS(SELECT 1 FROM messages WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NULL)",
			accountID, hash).Scan(&exists)

		if err != nil {
			logger.Warn("Failed to check message existence", "hash", hash[:12], "error", err)
			continue
		}

		if !exists {
			orphanedHashes = append(orphanedHashes, hash)
		}
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
				logger.Warn("Failed to reset orphaned hash", "hash", hash[:12], "error", err)
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
func (i *Importer) Run() error {
	defer i.Close()

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

	// After scanning, count only NEW (not yet on S3) messages in SQLite database
	var totalCount, alreadyOnS3 int64
	countErr := i.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 0").Scan(&totalCount)
	if countErr != nil {
		return fmt.Errorf("failed to count messages in database: %w", countErr)
	}

	// Also count messages already on S3 for logging
	i.sqliteDB.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1").Scan(&alreadyOnS3)

	// Set totalMessages to the actual count in database
	atomic.StoreInt64(&i.totalMessages, totalCount)
	logger.Info("Found new messages to import", "new", totalCount, "already_on_s3", alreadyOnS3)

	if i.options.DryRun {
		logger.Info("DRY RUN: Analyzing what would be imported...")
		return i.performDryRun()
	}

	// Only proceed with import if we have messages
	if totalCount == 0 {
		logger.Info("No messages to import")
		return nil
	}

	logger.Info("Starting import process", "count", totalCount)
	if err := i.importMessages(); err != nil {
		return fmt.Errorf("failed to import messages: %w", err)
	}

	return i.printSummary()
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

	lines := strings.Split(string(content), "\n")

	// Parse Dovecot subscriptions format
	// First line should be version (e.g., "V\t2")
	if len(lines) == 0 {
		return fmt.Errorf("empty subscriptions file")
	}

	// Skip version line and empty lines, collect folder names
	var folders []string
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if i == 0 {
			// Skip version line (e.g., "V\t2")
			if strings.HasPrefix(line, "V\t") || strings.HasPrefix(line, "V ") {
				continue
			}
		}
		if line != "" && !strings.HasPrefix(line, "V") {
			// Handle tab-separated folder names on the same line
			// Some Dovecot versions may have multiple folders per line separated by tabs
			if strings.Contains(line, "\t") {
				// Split by tabs and add each non-empty part as a separate folder
				parts := strings.Split(line, "\t")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part != "" {
						folders = append(folders, part)
					}
				}
			} else {
				folders = append(folders, line)
			}
		}
	}

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
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	// Ensure default mailboxes exist first
	if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.AccountID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", i.email, "error", err)
		// Don't fail the subscription processing, as mailboxes might already exist
	}

	// Process each subscribed folder
	for _, folderName := range folders {

		// Check if mailbox exists, create if needed
		mailbox, err := i.rdb.GetMailboxByNameWithRetry(i.ctx, user.AccountID(), folderName)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				logger.Info("Creating missing mailbox", "name", folderName)
				if err := i.rdb.CreateMailboxWithRetry(i.ctx, user.AccountID(), folderName, nil); err != nil {
					logger.Info("Warning: Failed to create mailbox", "name", folderName, "error", err)
					continue
				}
				// Get the newly created mailbox
				mailbox, err = i.rdb.GetMailboxByNameWithRetry(i.ctx, user.AccountID(), folderName)
				if err != nil {
					logger.Info("Warning: Failed to get newly created mailbox", "name", folderName, "error", err)
					continue
				}
			} else {
				logger.Info("Warning: Failed to check mailbox", "name", folderName, "error", err)
				continue
			}
		}

		// Subscribe the user to the folder
		if err := i.rdb.SetMailboxSubscribedWithRetry(i.ctx, mailbox.ID, user.AccountID(), true); err != nil {
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

	if i.options.DryRun {
		logger.Info("DRY RUN: Would import Sieve script", "path", i.options.SievePath)
		return nil
	}

	logger.Info("Importing Sieve script", "path", i.options.SievePath)

	// Read the script content
	scriptContent, err := os.ReadFile(i.options.SievePath)
	if err != nil {
		return fmt.Errorf("failed to read Sieve script file: %w", err)
	}

	// Get user context for database operations
	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	// Check if user already has an active script
	existingScript, err := i.rdb.GetActiveScriptWithRetry(i.ctx, user.AccountID())
	if err != nil && err != consts.ErrDBNotFound {
		return fmt.Errorf("failed to check for existing active script: %w", err)
	}

	scriptName := "imported"
	if existingScript != nil {
		logger.Info("User already has an active Sieve script - it will be replaced", "name", existingScript.Name)
		scriptName = existingScript.Name
	}

	// Create or update the script
	var script *db.SieveScript
	existingByName, err := i.rdb.GetScriptByNameWithRetry(i.ctx, scriptName, user.AccountID())
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

	// Activate the script
	if err := i.rdb.SetScriptActiveWithRetry(i.ctx, script.ID, user.AccountID(), true); err != nil {
		return fmt.Errorf("failed to activate Sieve script: %w", err)
	}

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

	content, err := os.ReadFile(keywordsPath)
	if err != nil {
		return fmt.Errorf("failed to read dovecot-keywords file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	keywordCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse format: "ID keyword_name"
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			logger.Info("Warning: Skipping malformed dovecot-keywords line", "line", line)
			continue
		}

		// Parse the ID
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			logger.Info("Warning: Invalid keyword ID in line", "line", line)
			continue
		}

		keyword := parts[1]
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
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)

	// Proactively ensure default mailboxes exist for this user
	if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.AccountID()); err != nil {
		logger.Info("Warning: Failed to create default mailboxes", "email", i.email, "error", err)
		// Don't fail the dry run, as mailboxes might already exist
	}

	// Query the SQLite database for messages not yet on S3

	rows, err := i.sqliteDB.Query("SELECT path, filename, hash, size, mailbox FROM messages WHERE s3_uploaded = 0 ORDER BY mailbox, path")
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

		// Check if message already exists in Sora
		mailboxObj, err := i.rdb.GetMailboxByNameWithRetry(i.ctx, user.AccountID(), mailbox)
		var alreadyExists bool
		if err == nil {
			if !i.options.ForceReimport {
				alreadyExists, err = i.isMessageAlreadyImported(hash, mailboxObj.ID)
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
			hash[:12]+"...")
		fmt.Printf("      Action: %s: %s\n", action, reason)

		// Show flags if preserve-flags is enabled
		if i.options.PreserveFlags {
			flags := i.parseMaildirFlags(filename)
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

// printSummary prints a summary of the import process.
func (i *Importer) printSummary() error {
	duration := time.Since(i.startTime)
	fmt.Printf("\n\nImport Summary:\n")
	fmt.Printf("  Total messages:    %d\n", i.totalMessages)
	fmt.Printf("  Imported:          %d\n", i.importedMessages)
	fmt.Printf("  Skipped:           %d\n", i.skippedMessages)
	fmt.Printf("  Failed:            %d\n", i.failedMessages)
	fmt.Printf("  Duration:          %s\n", duration.Round(time.Second))
	if i.importedMessages > 0 {
		rate := float64(i.importedMessages) / duration.Seconds()
		fmt.Printf("  Import rate:       %.1f messages/sec\n", rate)
	}
	if i.options.Dovecot {
		fmt.Printf("\nNote: Dovecot subscriptions and keywords files processed if present.\n")
	}
	return nil
}

// hashFile calculates the SHA256 hash of a file without loading it entirely into memory.
func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hasher := sha256.New()
	size, err := io.Copy(hasher, file)
	if err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(hasher.Sum(nil)), size, nil
}

// HashContent calculates the SHA256 hash of the given content.
func HashContent(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// resolveMailboxName determines the mailbox name from the maildir path
func (i *Importer) resolveMailboxName(path string) (string, error) {
	cleanPath := filepath.Clean(i.maildirPath)
	relPath, err := filepath.Rel(cleanPath, path)
	if err != nil {
		return "", fmt.Errorf("could not get relative path for %s: %w", path, err)
	}

	var mailboxName string
	if relPath == "." {
		mailboxName = "INBOX"
	} else {
		// Remove leading dot if present
		cleanName := strings.TrimPrefix(relPath, ".")

		// Replace maildir separator (.) with IMAP separator (/)
		mailboxName = strings.ReplaceAll(cleanName, ".", "/")

		// Validate characters
		if strings.ContainsAny(mailboxName, "\t\r\n") {
			return "", fmt.Errorf("invalid characters in mailbox name")
		}

		mailboxName = strings.TrimSpace(mailboxName)

		// Handle special folder name mappings
		switch strings.ToLower(mailboxName) {
		case "sent", "sent items", "sent mail":
			mailboxName = "Sent"
		case "drafts", "draft":
			mailboxName = "Drafts"
		case "trash", "deleted", "deleted items":
			mailboxName = "Trash"
		case "junk", "spam":
			mailboxName = "Junk"
		case "archive", "archives":
			mailboxName = "Archive"
		}
	}
	return mailboxName, nil
}

// parseMaildirFlags extracts IMAP flags from a maildir filename.
func (i *Importer) parseMaildirFlags(filename string) []imap.Flag {
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
			case 'D':
				flags = append(flags, imap.FlagDeleted)
			case 'T':
				flags = append(flags, imap.FlagDraft)
			default:
				// Handle Dovecot custom keywords (a-z represent keyword IDs 0-25)
				if char >= 'a' && char <= 'z' {
					keywordID := int(char - 'a')
					if keywordName, exists := i.dovecotKeywords[keywordID]; exists {
						// Add custom keyword as IMAP flag
						flags = append(flags, imap.Flag(keywordName))
					} else {
						logger.Info("Warning: Unknown keyword ID in filename", "id", keywordID, "char", string(char), "filename", filename)
					}
				}
			}
		}
	}

	// Add \Recent flag to newly imported messages
	flags = append(flags, imap.Flag("\\Recent"))

	return flags
}

// validateMessage performs basic validation on a message.
func validateMessage(size int64) error {
	if size == 0 {
		return errors.New("empty message")
	}
	if size > maxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max: %d)", size, maxMessageSize)
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
	// Check if the directory contains 'cur', 'new', and 'tmp' subdirectories
	_, errCur := os.Stat(filepath.Join(path, "cur"))
	_, errNew := os.Stat(filepath.Join(path, "new"))
	_, errTmp := os.Stat(filepath.Join(path, "tmp"))

	return !os.IsNotExist(errCur) && !os.IsNotExist(errNew) && !os.IsNotExist(errTmp)
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
			return fmt.Errorf("path '%s' is not a valid maildir root.\nDid you mean to use '%s' instead?\nThe path should point directly to a maildir (containing cur/, new/, tmp/ directories)", cleanPath, possibleMaildir)
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
				return fmt.Errorf("path '%s' is not a valid maildir root.\nFound possible maildir(s): %s\nThe path should point directly to a maildir (containing cur/, new/, tmp/ directories)", cleanPath, strings.Join(suggestions, ", "))
			}
		}

		return fmt.Errorf("path '%s' is not a valid maildir root (must contain cur/, new/, and tmp/ directories)", cleanPath)
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
				hash, size, err := hashFile(file.path)
				if err != nil {
					logger.Info("Failed to hash file", "path", file.path, "error", err)
					continue
				}

				// Validate message
				if err := validateMessage(size); err != nil {
					logger.Info("Invalid message", "path", file.path, "error", err)
					atomic.AddInt64(&i.skippedMessages, 1)
					continue
				}

				// Try to insert, relying on unique constraints to prevent duplicates
				// This operation is thread-safe with the "sqlite" driver.
				_, err = i.sqliteDB.Exec("INSERT OR IGNORE INTO messages (path, filename, hash, size, mailbox) VALUES (?, ?, ?, ?, ?)",
					file.path, file.filename, hash, size, file.mailboxName)
				if err != nil {
					logger.Info("Failed to insert message into sqlite db", "error", err)
					continue
				}
			}
		}()
	}

	// --- Filesystem Walk (Producer) ---
	walkErr := filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
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

		// Security check: ensure path is within maildir
		if !strings.HasPrefix(filepath.Clean(path), cleanPath) {
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

		var mailboxName string
		if relPath == "." {
			mailboxName = "INBOX"
		} else {
			// Handle different maildir naming conventions
			// Common formats:
			// .Sent (Dovecot style)
			// Sent (Courier style)
			// .Sent.2024 (hierarchical)

			// Remove leading dot if present
			cleanName := strings.TrimPrefix(relPath, ".")

			// Replace maildir separator (.) with IMAP separator (/)
			// But avoid creating names that will cause UTF-7 encoding issues
			mailboxName = strings.ReplaceAll(cleanName, ".", "/")

			// Validate the mailbox name doesn't contain problematic characters
			// that will cause UTF-7 encoding issues when sent to IMAP clients
			if strings.ContainsAny(mailboxName, "\t\r\n") {
				logger.Info("Warning: Skipping mailbox with invalid characters", "mailbox", mailboxName)
				return nil
			}

			// Trim any leading or trailing spaces from the mailbox name
			mailboxName = strings.TrimSpace(mailboxName)

			// Handle special folder name mappings
			switch strings.ToLower(mailboxName) {
			case "sent", "sent items", "sent mail":
				mailboxName = "Sent"
			case "drafts", "draft":
				mailboxName = "Drafts"
			case "trash", "deleted", "deleted items":
				mailboxName = "Trash"
			case "junk", "spam":
				mailboxName = "Junk"
			case "archive", "archives":
				mailboxName = "Archive"
			}
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

		// Get or create the mailbox
		mailbox, err := i.getOrCreateMailbox(i.ctx, user.AccountID(), mailboxName)
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
		`, mailbox.ID).Scan(&currentUIDValidity, &hasMessages)

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

		_, err = db.WritePool.Exec(i.ctx, `UPDATE mailboxes SET uid_validity = $2, highest_uid = $3 WHERE id = $1`,
			mailbox.ID, uidList.UIDValidity, highestUID)
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

	if len(inReplyTo) == 0 {
		inReplyTo = nil
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

	extractedPlaintext, _ := helpers.ExtractPlaintextBody(messageContent)
	var plaintextBody string
	if extractedPlaintext != nil {
		plaintextBody = *extractedPlaintext
	}

	recipients := helpers.ExtractRecipients(messageContent.Header)

	var rawHeaders string
	if idx := bytes.Index(content, []byte("\r\n\r\n")); idx != -1 {
		rawHeaders = string(content[:idx])
	}

	// Flags
	var flags []imap.Flag
	if i.options.PreserveFlags {
		flags = i.parseMaildirFlags(filename)
	} else {
		flags = []imap.Flag{imap.Flag("\\Recent")}
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
		inReplyTo:            inReplyTo,
		bodyStructure:        &bodyStructure,
		recipients:           recipients,
		rawHeaders:           rawHeaders,
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
					return
				}
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
				if err := i.s3.Put(s3Key, bytes.NewReader(content), msg.size); err != nil {
					logger.Warn("S3 upload failed", "path", msg.path, "error", err)
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
// Note: Each message insert uses InsertMessageFromImporterWithRetry which has its own transaction
func (i *Importer) insertBatchToDB(uploaded []uploadedMsg) ([]string, error) {
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

	var successHashes []string

	// Process each message in the batch
	// Note: InsertMessageFromImporterWithRetry handles transactions and retries internally
	for _, up := range uploaded {
		// Get/create mailbox (cached)
		mailbox, err := i.getOrCreateMailbox(i.ctx, user.AccountID(), up.msg.mailbox)
		if err != nil {
			return nil, fmt.Errorf("failed to get or create mailbox '%s': %w", up.msg.mailbox, err)
		}

		// Insert into PostgreSQL with built-in transaction and retry
		_, _, err = i.rdb.InsertMessageFromImporterWithRetry(i.ctx, &db.InsertMessageOptions{
			AccountID:            user.AccountID(),
			MailboxID:            mailbox.ID,
			S3Domain:             address.Domain(),
			S3Localpart:          address.LocalPart(),
			MailboxName:          mailbox.Name,
			ContentHash:          up.msg.hash,
			MessageID:            up.metadata.messageID,
			Flags:                up.metadata.flags,
			InternalDate:         up.metadata.sentDate,
			Size:                 up.msg.size,
			Subject:              up.metadata.subject,
			PlaintextBody:        up.metadata.plaintextBody,
			SentDate:             up.metadata.sentDate,
			InReplyTo:            up.metadata.inReplyTo,
			BodyStructure:        up.metadata.bodyStructure,
			Recipients:           up.metadata.recipients,
			RawHeaders:           up.metadata.rawHeaders,
			PreservedUID:         up.metadata.preservedUID,
			PreservedUIDValidity: up.metadata.preservedUIDValidity,
			FTSRetention:         i.options.FTSRetention,
		})

		if err != nil {
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				// Message already exists - skip but continue processing batch
				atomic.AddInt64(&i.skippedMessages, 1)
				continue
			}
			// Non-recoverable error - fail entire batch
			return nil, fmt.Errorf("failed to insert message (hash: %s): %w", up.msg.hash, err)
		}

		successHashes = append(successHashes, up.msg.hash)
	}

	return successHashes, nil
}

// insertBatchToDBWithTransaction inserts all uploaded messages in a SINGLE transaction
// This is faster (20x) but less resilient - if one message fails, entire batch rolls back
func (i *Importer) insertBatchToDBWithTransaction(uploaded []uploadedMsg) ([]string, error) {
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

	var successHashes []string

	// Begin a single transaction for the entire batch
	tx, err := i.rdb.BeginTxWithRetry(i.ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(i.ctx)

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
			InternalDate:         up.metadata.sentDate,
			Size:                 up.msg.size,
			Subject:              up.metadata.subject,
			PlaintextBody:        up.metadata.plaintextBody,
			SentDate:             up.metadata.sentDate,
			InReplyTo:            up.metadata.inReplyTo,
			BodyStructure:        up.metadata.bodyStructure,
			Recipients:           up.metadata.recipients,
			RawHeaders:           up.metadata.rawHeaders,
			PreservedUID:         up.metadata.preservedUID,
			PreservedUIDValidity: up.metadata.preservedUIDValidity,
			FTSRetention:         i.options.FTSRetention,
		})

		if err != nil {
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
		successHashes = append(successHashes, up.msg.hash)
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
				"hash", item.hash[:12], "mailbox_id", item.mailboxID, "error", err)
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
func (i *Importer) markBatchInSQLite(hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}

	logger.Info("Marking batch in SQLite", "count", len(hashes))

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

		stmt, err := tx.Prepare(`
			UPDATE messages
			SET s3_uploaded = 1, s3_uploaded_at = ?
			WHERE hash = ?
		`)
		if err != nil {
			done <- result{err: fmt.Errorf("failed to prepare SQLite statement: %w", err)}
			return
		}
		defer stmt.Close()

		logger.Info("SQLite statement prepared, executing updates")

		now := time.Now()
		for idx, hash := range hashes {
			if _, err := stmt.Exec(now, hash); err != nil {
				done <- result{err: fmt.Errorf("failed to update SQLite for hash %s: %w", hash[:12], err)}
				return
			}
			if (idx+1)%5 == 0 {
				logger.Info("SQLite update progress", "completed", idx+1, "total", len(hashes))
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
	var successHashes []string
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
			logger.Error("DB inserts failed", "error", err)
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
		atomic.AddInt64(&i.failedMessages, int64(len(uploaded)))
		return err
	}

	atomic.AddInt64(&i.importedMessages, int64(len(successHashes)))
	logger.Info("Batch complete", "imported", len(successHashes))
	return nil
}

// importMessages reads from the SQLite database and imports messages into Sora using batching.
func (i *Importer) importMessages() error {
	if i.totalMessages == 0 {
		logger.Info("No messages to import")
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
	rows, err := i.sqliteDB.Query(`
		SELECT path, filename, hash, size, mailbox 
		FROM messages 
		WHERE s3_uploaded = 0 
		ORDER BY mailbox, path
	`)
	if err != nil {
		return fmt.Errorf("failed to query messages: %w", err)
	}

	var allMessages []msgInfo
	for rows.Next() {
		var msg msgInfo
		if err := rows.Scan(&msg.path, &msg.filename, &msg.hash,
			&msg.size, &msg.mailbox); err != nil {
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
