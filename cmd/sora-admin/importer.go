package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/migadu/sora/logger"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/mail"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
	_ "modernc.org/sqlite"
)

const (
	maxMessageSize = 100 * 1024 * 1024 // 100MB max message size
)

// ImporterOptions contains configuration options for the importer
type ImporterOptions struct {
	DryRun        bool
	StartDate     *time.Time
	EndDate       *time.Time
	MailboxFilter []string
	PreserveFlags bool
	ShowProgress  bool
	ForceReimport bool
	CleanupDB     bool
	Dovecot       bool
	ImportDelay   time.Duration // Delay between imports to control rate
	SievePath     string        // Path to Sieve script file to import
	PreserveUIDs  bool          // Preserve UIDs from dovecot-uidlist files
	FTSRetention  time.Duration // FTS retention period to skip old messages
	TestMode      bool          // Skip S3 uploads for testing (messages stored in DB only)
}

// Importer handles the maildir import process.
type Importer struct {
	ctx         context.Context // Context for cancellation support
	maildirPath string
	email       string
	jobs        int
	db          *sql.DB
	dbPath      string // Path to the SQLite database file
	rdb         *resilient.ResilientDatabase
	s3          *storage.S3Storage
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
}

// NewImporter creates a new Importer instance.
func NewImporter(ctx context.Context, maildirPath, email string, jobs int, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, options ImporterOptions) (*Importer, error) {
	// Create SQLite database in the maildir path to persist maildir state
	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	logger.Infof("Using maildir database: %s", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Create the table for storing message information.
	// s3_uploaded tracks whether the message has been successfully uploaded to S3
	_, err = db.Exec(`
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
	err = db.QueryRow(`
		SELECT COUNT(*) > 0
		FROM pragma_table_info('messages')
		WHERE name='s3_uploaded'
	`).Scan(&columnExists)
	if err != nil {
		return nil, fmt.Errorf("failed to check for s3_uploaded column: %w", err)
	}

	if !columnExists {
		logger.Info("Migrating SQLite database: adding s3_uploaded columns")
		_, err = db.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded INTEGER DEFAULT 1`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded column: %w", err)
		}

		_, err = db.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded_at TIMESTAMP`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded_at column: %w", err)
		}

		// Mark all existing messages as uploaded (they were in old DB, so they're on S3)
		_, err = db.Exec(`UPDATE messages SET s3_uploaded_at = CURRENT_TIMESTAMP WHERE s3_uploaded_at IS NULL`)
		if err != nil {
			return nil, fmt.Errorf("failed to mark existing messages as uploaded: %w", err)
		}

		logger.Info("SQLite database migration completed successfully - all existing messages marked as uploaded")
	}

	// Create index after migration (idempotent operation)
	_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_s3_uploaded ON messages(s3_uploaded)`)
	if err != nil {
		return nil, fmt.Errorf("failed to create s3_uploaded index: %w", err)
	}

	importer := &Importer{
		ctx:             ctx,
		maildirPath:     maildirPath,
		email:           email,
		jobs:            jobs,
		db:              db,
		dbPath:          dbPath,
		rdb:             rdb,
		s3:              s3,
		options:         options,
		startTime:       time.Now(),
		dovecotKeywords: make(map[int]string),
		dovecotUIDLists: make(map[string]*DovecotUIDList),
	}

	// Parse Dovecot keywords if Dovecot mode is enabled
	if options.Dovecot {
		if err := importer.parseDovecotKeywords(); err != nil {
			logger.Infof("Warning: Failed to parse dovecot-keywords: %v", err)
			// Don't fail creation for keyword parsing errors
		}
	}

	return importer, nil
}

// Close cleans up resources used by the importer.
func (i *Importer) Close() error {
	if i.db != nil {
		if err := i.db.Close(); err != nil {
			return fmt.Errorf("failed to close maildir database: %w", err)
		}
		if i.options.CleanupDB {
			logger.Infof("Cleaning up import database: %s", i.dbPath)
			if err := os.Remove(i.dbPath); err != nil {
				return fmt.Errorf("failed to remove maildir database file: %w", err)
			}
		} else {
			logger.Infof("Maildir database saved at: %s", i.dbPath)
		}
	}
	return nil
}

// Run starts the import process.
func (i *Importer) Run() error {
	defer i.Close()

	// Process Dovecot subscriptions if Dovecot mode is enabled
	if i.options.Dovecot {
		if err := i.processSubscriptions(); err != nil {
			logger.Infof("Warning: Failed to process subscriptions: %v", err)
			// Don't fail the import for subscription errors
		}
	}

	// Import Sieve script if provided
	if i.options.SievePath != "" {
		if err := i.importSieveScript(); err != nil {
			logger.Infof("Warning: Failed to import Sieve script: %v", err)
		}
	}

	logger.Info("Scanning maildir...")
	if err := i.scanMaildir(); err != nil {
		return fmt.Errorf("failed to scan maildir: %w", err)
	}

	// After scanning, count only NEW (not yet on S3) messages in SQLite database
	var totalCount, alreadyOnS3 int64
	countErr := i.db.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 0").Scan(&totalCount)
	if countErr != nil {
		return fmt.Errorf("failed to count messages in database: %w", countErr)
	}

	// Also count messages already on S3 for logging
	i.db.QueryRow("SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1").Scan(&alreadyOnS3)

	// Set totalMessages to the actual count in database
	atomic.StoreInt64(&i.totalMessages, totalCount)
	logger.Infof("Found %d new messages to import (%d already on S3)", totalCount, alreadyOnS3)

	if i.options.DryRun {
		logger.Info("DRY RUN: Analyzing what would be imported...")
		return i.performDryRun()
	}

	// Only proceed with import if we have messages
	if totalCount == 0 {
		logger.Info("No messages to import")
		return nil
	}

	logger.Infof("Starting import process for %d messages...", totalCount)
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
		logger.Infof("No subscriptions file found at %s, skipping subscription processing", subscriptionsPath)
		return nil
	}

	logger.Infof("Processing Dovecot subscriptions from: %s", subscriptionsPath)

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
		logger.Infof("No folders found in subscriptions file")
		return nil
	}

	logger.Infof("Found %d subscribed folders: %v", len(folders), folders)

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
	if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.UserID()); err != nil {
		logger.Infof("Warning: Failed to create default mailboxes for %s: %v", i.email, err)
		// Don't fail the subscription processing, as mailboxes might already exist
	}

	// Process each subscribed folder
	for _, folderName := range folders {

		// Check if mailbox exists, create if needed
		mailbox, err := i.rdb.GetMailboxByNameWithRetry(i.ctx, user.UserID(), folderName)
		if err != nil {
			if err == consts.ErrMailboxNotFound {
				logger.Infof("Creating missing mailbox: %s", folderName)
				if err := i.rdb.CreateMailboxWithRetry(i.ctx, user.UserID(), folderName, nil); err != nil {
					logger.Infof("Warning: Failed to create mailbox %s: %v", folderName, err)
					continue
				}
				// Get the newly created mailbox
				mailbox, err = i.rdb.GetMailboxByNameWithRetry(i.ctx, user.UserID(), folderName)
				if err != nil {
					logger.Infof("Warning: Failed to get newly created mailbox %s: %v", folderName, err)
					continue
				}
			} else {
				logger.Infof("Warning: Failed to check mailbox %s: %v", folderName, err)
				continue
			}
		}

		// Subscribe the user to the folder
		if err := i.rdb.SetMailboxSubscribedWithRetry(i.ctx, mailbox.ID, user.UserID(), true); err != nil {
			logger.Infof("Warning: Failed to subscribe to mailbox %s: %v", folderName, err)
		} else {
			logger.Infof("Successfully subscribed to mailbox: %s", folderName)
		}
	}

	return nil
}

// importSieveScript imports a Sieve script file for the user
func (i *Importer) importSieveScript() error {
	// Check if file exists (follow symlinks if present)
	if _, err := os.Stat(i.options.SievePath); os.IsNotExist(err) {
		logger.Infof("Sieve script file does not exist, ignoring: %s", i.options.SievePath)
		return nil
	}

	if i.options.DryRun {
		logger.Infof("DRY RUN: Would import Sieve script from: %s", i.options.SievePath)
		return nil
	}

	logger.Infof("Importing Sieve script from: %s", i.options.SievePath)

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
	existingScript, err := i.rdb.GetActiveScriptWithRetry(i.ctx, user.UserID())
	if err != nil && err != consts.ErrDBNotFound {
		return fmt.Errorf("failed to check for existing active script: %w", err)
	}

	scriptName := "imported"
	if existingScript != nil {
		logger.Infof("User already has an active Sieve script named '%s', it will be replaced", existingScript.Name)
		scriptName = existingScript.Name
	}

	// Create or update the script
	var script *db.SieveScript
	existingByName, err := i.rdb.GetScriptByNameWithRetry(i.ctx, scriptName, user.UserID())
	switch err {
	case nil:
		// Script with this name exists, update it
		script, err = i.rdb.UpdateScriptWithRetry(i.ctx, existingByName.ID, user.UserID(), scriptName, string(scriptContent))
		if err != nil {
			return fmt.Errorf("failed to update existing Sieve script: %w", err)
		}
		logger.Infof("Updated existing Sieve script '%s'", scriptName)
	case consts.ErrDBNotFound:
		// Create new script
		script, err = i.rdb.CreateScriptWithRetry(i.ctx, user.UserID(), scriptName, string(scriptContent))
		if err != nil {
			return fmt.Errorf("failed to create Sieve script: %w", err)
		}
		logger.Infof("Created new Sieve script '%s'", scriptName)
	default:
		return fmt.Errorf("failed to check for existing script by name: %w", err)
	}

	// Activate the script
	if err := i.rdb.SetScriptActiveWithRetry(i.ctx, script.ID, user.UserID(), true); err != nil {
		return fmt.Errorf("failed to activate Sieve script: %w", err)
	}

	logger.Infof("Successfully imported and activated Sieve script '%s' for user %s", scriptName, i.email)
	return nil
}

// parseDovecotKeywords reads and parses the Dovecot keywords file
func (i *Importer) parseDovecotKeywords() error {
	keywordsPath := filepath.Join(i.maildirPath, "dovecot-keywords")

	// Check if keywords file exists
	if _, err := os.Stat(keywordsPath); os.IsNotExist(err) {
		logger.Infof("No dovecot-keywords file found at %s, custom keywords will not be imported", keywordsPath)
		return nil
	}

	logger.Infof("Parsing Dovecot keywords from: %s", keywordsPath)

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
			logger.Infof("Warning: Skipping malformed dovecot-keywords line: %s", line)
			continue
		}

		// Parse the ID
		id, err := strconv.Atoi(parts[0])
		if err != nil {
			logger.Infof("Warning: Invalid keyword ID in line: %s", line)
			continue
		}

		keyword := parts[1]
		i.dovecotKeywords[id] = keyword
		keywordCount++
	}

	if keywordCount > 0 {
		logger.Infof("Loaded %d Dovecot custom keywords", keywordCount)
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
	if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.UserID()); err != nil {
		logger.Infof("Warning: Failed to create default mailboxes for %s: %v", i.email, err)
		// Don't fail the dry run, as mailboxes might already exist
	}

	// Query the SQLite database for messages not yet on S3

	rows, err := i.db.Query("SELECT path, filename, hash, size, mailbox FROM messages WHERE s3_uploaded = 0 ORDER BY mailbox, path")
	if err != nil {
		return fmt.Errorf("failed to query messages from sqlite: %w", err)
	}
	defer rows.Close()

	var totalWouldImport, totalWouldSkip int64
	currentMailbox := ""
	var mailboxWouldImport, mailboxWouldSkip int

	for rows.Next() {
		var path, filename, hash, mailbox string
		var size int64
		if err := rows.Scan(&path, &filename, &hash, &size, &mailbox); err != nil {
			logger.Infof("Failed to scan row: %v", err)
			continue
		}

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
		if i.options.StartDate != nil || i.options.EndDate != nil {
			info, err := os.Stat(path)
			if err == nil {
				modTime := info.ModTime()
				if i.options.StartDate != nil && modTime.Before(*i.options.StartDate) {
					mailboxWouldSkip++
					continue
				}
				if i.options.EndDate != nil && modTime.After(*i.options.EndDate) {
					mailboxWouldSkip++
					continue
				}
			}
		}

		// Check if message already exists in Sora
		mailboxObj, err := i.rdb.GetMailboxByNameWithRetry(i.ctx, user.UserID(), mailbox)
		var alreadyExists bool
		if err == nil {
			if !i.options.ForceReimport {
				alreadyExists, err = i.isMessageAlreadyImported(hash, mailboxObj.ID)
				if err != nil {
					logger.Infof("Error checking if message exists: %v", err)
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

	totalWouldImport = atomic.LoadInt64(&i.totalMessages) - totalWouldSkip
	totalWouldSkip = atomic.LoadInt64(&i.skippedMessages)

	// Overall summary
	fmt.Printf("=== DRY RUN: Overall Summary ===\n")
	fmt.Printf("Would import: %d messages\n", totalWouldImport)
	fmt.Printf("Would skip: %d messages\n", totalWouldSkip)
	fmt.Printf("Total files scanned: %d\n", atomic.LoadInt64(&i.totalMessages))

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
						logger.Infof("Warning: Unknown keyword ID %d (char %c) in filename: %s", keywordID, char, filename)
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

	return filepath.Walk(cleanPath, func(path string, info os.FileInfo, err error) error {
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
				logger.Infof("Warning: Skipping mailbox with invalid characters: %s", mailboxName)
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

		logger.Infof("Processing maildir folder: %s -> mailbox: '%s' (contains '/' delimiter: %v)", relPath, mailboxName, strings.Contains(mailboxName, "/"))

		// Check if this mailbox should be imported
		if !i.shouldImportMailbox(mailboxName) {
			logger.Infof("Skipping mailbox %s (filtered)", mailboxName)
			return nil
		}

		// This is a maildir folder, process the messages within it.
		// Only scan 'cur' and 'new' directories (skip 'tmp' as it contains incomplete messages)
		for _, subDir := range []string{"cur", "new"} {
			messages, err := os.ReadDir(filepath.Join(path, subDir))
			if err != nil {
				logger.Infof("Failed to read directory %s: %v", filepath.Join(path, subDir), err)
				continue
			}

			for _, message := range messages {
				if message.IsDir() {
					continue
				}

				filename := message.Name()

				// Only process files that look like maildir messages
				if !isValidMaildirMessage(filename) {
					continue
				}

				messagePath := filepath.Join(path, subDir, filename)

				// Use streaming hash function
				hash, size, err := hashFile(messagePath)
				if err != nil {
					logger.Infof("Failed to hash file %s: %v", messagePath, err)
					continue
				}

				// Validate message
				if err := validateMessage(size); err != nil {
					logger.Infof("Invalid message %s: %v", messagePath, err)
					atomic.AddInt64(&i.skippedMessages, 1)
					continue
				}

				// Try to insert, relying on unique constraints to prevent duplicates
				result, err := i.db.Exec("INSERT OR IGNORE INTO messages (path, filename, hash, size, mailbox) VALUES (?, ?, ?, ?, ?)",
					messagePath, filename, hash, size, mailboxName)
				if err != nil {
					logger.Infof("Failed to insert message into sqlite db: %v", err)
					continue
				}

				// Only count if the insert actually happened (not a duplicate)

				rowsAffected, err := result.RowsAffected()
				if err != nil {
					logger.Infof("Failed to get rows affected: %v", err)
					continue
				}
				if rowsAffected > 0 {
					atomic.AddInt64(&i.totalMessages, 1)
				} else {
					// Message already exists in SQLite, but still count it
					logger.Infof("Message already in SQLite database: %s", filename)
				}
			}
		}

		// Parse dovecot-uidlist if preserving UIDs
		if i.options.PreserveUIDs {
			uidList, err := ParseDovecotUIDList(path)
			if err != nil {
				logger.Infof("Warning: Failed to parse dovecot-uidlist in %s: %v", path, err)
			} else if uidList != nil {
				i.dovecotUIDLists[path] = uidList
				logger.Infof("Loaded dovecot-uidlist for %s: UIDVALIDITY=%d, NextUID=%d, %d mappings",
					mailboxName, uidList.UIDValidity, uidList.NextUID, len(uidList.UIDMappings))
			}
		}

		// Do not skip the directory, so we can find nested maildir folders.
		return nil
	})
}

// importMessages reads from the SQLite database and imports messages into Sora.
func (i *Importer) importMessages() error {
	// totalMessages is already set in Run() after scanning
	if i.totalMessages == 0 {
		logger.Info("No messages to import")
		return nil
	}

	logger.Infof("Processing %d messages from database", i.totalMessages)

	rows, err := i.db.Query("SELECT path, filename, hash, size, mailbox FROM messages WHERE s3_uploaded = 0 ORDER BY mailbox, path")
	if err != nil {
		return fmt.Errorf("failed to query messages from sqlite: %w", err)
	}
	defer rows.Close()

	var wg sync.WaitGroup
	jobs := make(chan struct {
		path     string
		filename string
		hash     string
		size     int64
		mailbox  string
	}, 100) // Buffer for better performance

	// No need for progress reporter - we'll prefix each log message

	// Start workers
	for w := 0; w < i.jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check for cancellation before processing each message
				select {
				case <-i.ctx.Done():
					logger.Info("Import worker cancelled by user")
					return
				default:
				}

				// Retry logic: try up to 3 times
				var err error
				for retry := 0; retry < 3; retry++ {
					err = i.importMessage(j.path, j.filename, j.hash, j.size, j.mailbox)
					if err == nil {
						break // Success
					}

					if retry < 2 { // Don't delay after last attempt
						logger.Infof("%s Import attempt %d/3 failed for %s: %v, retrying...", i.getProgressPrefix(), retry+1, j.path, err)
						time.Sleep(time.Duration(retry+1) * time.Second) // Exponential backoff
					}
				}

				if err != nil {
					logger.Infof("%s Failed to import message %s after 3 attempts: %v", i.getProgressPrefix(), j.path, err)
					atomic.AddInt64(&i.failedMessages, 1)
				}
			}
		}()
	}

	// Feed jobs to workers
	for rows.Next() {
		// Check for cancellation before processing each row
		select {
		case <-i.ctx.Done():
			logger.Info("Import cancelled by user, stopping job submission")
			close(jobs)
			wg.Wait()
			return i.ctx.Err()
		default:
		}

		var path, filename, hash, mailbox string
		var size int64
		if err := rows.Scan(&path, &filename, &hash, &size, &mailbox); err != nil {
			logger.Infof("Failed to scan row: %v", err)
			continue
		}

		// Check date filter if specified
		if i.options.StartDate != nil || i.options.EndDate != nil {
			// Quick check based on file modification time
			info, err := os.Stat(path)
			if err == nil {
				modTime := info.ModTime()
				if i.options.StartDate != nil && modTime.Before(*i.options.StartDate) {
					atomic.AddInt64(&i.skippedMessages, 1)
					continue
				}
				if i.options.EndDate != nil && modTime.After(*i.options.EndDate) {
					atomic.AddInt64(&i.skippedMessages, 1)
					continue
				}
			}
		}

		jobs <- struct {
			path     string
			filename string
			hash     string
			size     int64
			mailbox  string
		}{path: path, filename: filename, hash: hash, size: size, mailbox: mailbox}
	}

	close(jobs)
	wg.Wait()

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

func (i *Importer) importMessage(path, filename, hash string, size int64, mailboxName string) error {
	// Check if file still exists on disk
	if _, err := os.Stat(path); os.IsNotExist(err) {
		atomic.AddInt64(&i.skippedMessages, 1)
		logger.Infof("%s File no longer exists on disk, skipping: %s", i.getProgressPrefix(), path)
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	address, err := server.NewAddress(i.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := i.rdb.GetAccountIDByAddressWithRetry(i.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("account not found for %s: %w\nHint: Create the account first using: sora-admin accounts create --address %s --password <password>", i.email, err, i.email)
	}
	user := server.NewUser(address, accountID)
	logger.Infof("Processing for user: email=%s, accountID=%d, userID=%d", address.FullAddress(), accountID, user.UserID())

	// Proactively ensure default mailboxes exist for this user
	// This prevents "mailbox not found" errors during import
	if err := i.rdb.CreateDefaultMailboxesWithRetry(i.ctx, user.UserID()); err != nil {
		logger.Infof("Warning: Failed to create default mailboxes for %s: %v", i.email, err)
		// Don't fail the import, as mailboxes might already exist
	}

	mailbox, err := i.rdb.GetMailboxByNameWithRetry(i.ctx, user.UserID(), mailboxName)
	if err != nil {
		logger.Infof("Mailbox '%s' not found for user %d, creating it", mailboxName, user.UserID())
		// Create mailbox if it doesn't exist
		if err := i.rdb.CreateMailboxWithRetry(i.ctx, user.UserID(), mailboxName, nil); err != nil {
			return fmt.Errorf("failed to create mailbox '%s': %w", mailboxName, err)
		}
		mailbox, err = i.rdb.GetMailboxByNameWithRetry(i.ctx, user.UserID(), mailboxName)
		if err != nil {
			return fmt.Errorf("failed to get mailbox '%s' after creation: %w", mailboxName, err)
		}
		logger.Infof("Created mailbox '%s' with ID %d (database name: '%s')", mailboxName, mailbox.ID, mailbox.Name)
	} else {
		logger.Infof("Using existing mailbox '%s' with ID %d (database name: '%s')", mailboxName, mailbox.ID, mailbox.Name)
	}

	// Check if this message is already imported
	alreadyImported, err := i.isMessageAlreadyImported(hash, mailbox.ID)
	if err != nil {
		return fmt.Errorf("failed to check if message is already imported: %w", err)
	}

	if alreadyImported {
		if !i.options.ForceReimport {
			logger.Infof("%s Message already exists in DB, skipping: %s", i.getProgressPrefix(), path)
			atomic.AddInt64(&i.skippedMessages, 1)
			return nil
		}

		// ForceReimport is true: delete the existing message before proceeding.
		// This requires a `DeleteMessageByHashAndMailbox` method in the db package.
		deleted, err := i.rdb.DeleteMessageByHashAndMailboxWithRetry(i.ctx, user.UserID(), mailbox.ID, hash)
		if err != nil {
			return fmt.Errorf("failed to delete existing message for re-import: %w", err)
		}
		if deleted > 0 {
			logger.Infof("%s Deleted %d existing message(s) for re-import (hash: %s, mailbox: %s)", i.getProgressPrefix(), deleted, hash[:12], mailboxName)
		}
	}

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

	// Determine flags
	var flags []imap.Flag
	if i.options.PreserveFlags {
		flags = i.parseMaildirFlags(filename)
	} else {
		// Just add \Recent flag to newly imported messages
		flags = []imap.Flag{imap.Flag("\\Recent")}
	}

	// Look up preserved UID if enabled
	var preservedUID *uint32
	var preservedUIDValidity *uint32

	if i.options.PreserveUIDs {
		// Find the maildir path for this mailbox
		maildirPath := filepath.Dir(filepath.Dir(path)) // Go up from cur/new to maildir folder
		logger.Infof("DEBUG: Looking for UID preservation: path=%s, maildirPath=%s, filename=%s", path, maildirPath, filename)

		if uidList, ok := i.dovecotUIDLists[maildirPath]; ok && uidList != nil {
			logger.Infof("DEBUG: Found UID list for %s with %d mappings", maildirPath, len(uidList.UIDMappings))
			if uid, found := uidList.GetUIDForFile(filename); found {
				preservedUID = &uid
				preservedUIDValidity = &uidList.UIDValidity
				logger.Infof("Using preserved UID %d for %s (UIDVALIDITY=%d)", uid, filename, uidList.UIDValidity)
			} else {
				logger.Infof("No preserved UID found for %s in dovecot-uidlist (tried %d mappings)", filename, len(uidList.UIDMappings))
			}
		} else {
			logger.Infof("DEBUG: No UID list found for maildirPath=%s (available: %v)", maildirPath, func() []string {
				var keys []string
				for k := range i.dovecotUIDLists {
					keys = append(keys, k)
				}
				return keys
			}())
		}
	}

	// --- Robust Import Flow ---
	// Step 1: Upload content to S3 first (skip in test mode)
	if !i.options.TestMode && i.s3 != nil {
		s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), hash)
		s3Err := i.s3.Put(s3Key, bytes.NewReader(content), size)
		if s3Err != nil {
			// S3 upload failed. Don't insert into DB at all.
			return fmt.Errorf("failed to upload to S3: %w", s3Err)
		}
	}

	// Step 2: Insert the message in the database with uploaded=TRUE
	// Since we do synchronous S3 upload, use InsertMessageFromImporterWithRetry
	// which marks uploaded=TRUE immediately and does NOT add to pending_uploads queue
	if preservedUID != nil {
		logger.Infof("[IMPORTER] DEBUG: About to insert with preserved UID=%d", *preservedUID)
	}
	if preservedUIDValidity != nil {
		logger.Infof("[IMPORTER] DEBUG: About to insert with preserved UIDVALIDITY=%d", *preservedUIDValidity)
	}

	msgID, uid, err := i.rdb.InsertMessageFromImporterWithRetry(i.ctx,
		&db.InsertMessageOptions{
			UserID:               user.UserID(),
			MailboxID:            mailbox.ID,
			S3Domain:             address.Domain(),
			S3Localpart:          address.LocalPart(),
			MailboxName:          mailbox.Name,
			ContentHash:          hash,
			MessageID:            messageID,
			Flags:                flags,
			InternalDate:         sentDate,
			Size:                 size,
			Subject:              subject,
			PlaintextBody:        actualPlaintextBody,
			SentDate:             sentDate,
			InReplyTo:            inReplyTo,
			BodyStructure:        &bodyStructure,
			Recipients:           recipients,
			RawHeaders:           rawHeadersText,
			PreservedUID:         preservedUID,
			PreservedUIDValidity: preservedUIDValidity,
			FTSRetention:         i.options.FTSRetention,
		})

	if err != nil {
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			// This can happen if another process imported the message between our check and insert (race condition).
			// The S3 object exists (uploaded above), but that's okay - S3 is content-addressed.
			logger.Infof("%s Message already exists in DB (race condition?), skipping: %s", i.getProgressPrefix(), path)
			atomic.AddInt64(&i.skippedMessages, 1)
			return nil
		}
		// Database insert failed after successful S3 upload.
		// The S3 object will remain (orphaned), but can be cleaned up later.
		return fmt.Errorf("failed to insert message in database: %w", err)
	}

	// Mark message as uploaded to S3 in SQLite cache
	_, err = i.db.Exec("UPDATE messages SET s3_uploaded = 1, s3_uploaded_at = ? WHERE hash = ? AND mailbox = ?",
		time.Now(), hash, mailbox.Name)
	if err != nil {
		logger.Infof("Warning: Failed to mark message as uploaded in SQLite: %v", err)
		// Don't fail the import - message is already on S3
	}

	atomic.AddInt64(&i.importedMessages, 1)
	logger.Infof("%s Successfully imported message: msgID=%d, uid=%d, mailbox=%s", i.getProgressPrefix(), msgID, uid, mailbox.Name)

	// Add delay if configured to control rate
	if i.options.ImportDelay > 0 {
		time.Sleep(i.options.ImportDelay)
	}
	return nil
}
