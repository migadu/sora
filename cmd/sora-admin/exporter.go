package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
	_ "modernc.org/sqlite"
)

// ExporterOptions contains configuration options for the exporter
type ExporterOptions struct {
	DryRun         bool
	StartDate      *time.Time
	EndDate        *time.Time
	MailboxFilter  []string
	ShowProgress   bool
	Dovecot        bool
	OverwriteFlags bool          // Whether to overwrite flags on existing messages
	ExportDelay    time.Duration // Delay between exports to control rate
	ExportUIDList  bool          // Whether to export dovecot-uidlist files
}

// Exporter handles the maildir export process.
type Exporter struct {
	maildirPath string
	email       string
	jobs        int
	db          *sql.DB
	dbPath      string // Path to the SQLite database file
	soraDB      *db.Database
	s3          *storage.S3Storage
	options     ExporterOptions

	totalMessages    int64
	exportedMessages int64
	skippedMessages  int64
	failedMessages   int64
	startTime        time.Time
	mu               sync.Mutex

	// UID mappings per mailbox for dovecot-uidlist generation
	uidMappings map[string][]UIDFileMapping // mailbox name -> UID mappings
}

// NewExporter creates a new Exporter instance.
func NewExporter(maildirPath, email string, jobs int, soraDB *db.Database, s3 *storage.S3Storage, options ExporterOptions) (*Exporter, error) {
	// Ensure maildir path exists
	if err := os.MkdirAll(maildirPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create maildir path: %w", err)
	}

	// Use the shared SQLite database in the maildir path
	dbPath := filepath.Join(maildirPath, "sora-maildir.db")
	log.Printf("Using maildir database: %s", dbPath)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Create the same table structure as importer uses
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			path TEXT NOT NULL,
			filename TEXT NOT NULL,
			hash TEXT NOT NULL,
			size INTEGER NOT NULL,
			mailbox TEXT NOT NULL,
			UNIQUE(hash, mailbox),
			UNIQUE(filename, mailbox)
		);
		CREATE INDEX IF NOT EXISTS idx_mailbox ON messages(mailbox);
		CREATE INDEX IF NOT EXISTS idx_hash ON messages(hash);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create exported_messages table: %w", err)
	}

	exporter := &Exporter{
		maildirPath: maildirPath,
		email:       email,
		jobs:        jobs,
		db:          db,
		dbPath:      dbPath,
		soraDB:      soraDB,
		s3:          s3,
		options:     options,
		startTime:   time.Now(),
		uidMappings: make(map[string][]UIDFileMapping),
	}

	return exporter, nil
}

// Close cleans up resources used by the exporter.
func (exporter *Exporter) Close() error {
	if exporter.db != nil {
		exporter.db.Close()
		log.Printf("Maildir database saved at: %s", exporter.dbPath)
	}
	return nil
}

// Run starts the export process.
func (exporter *Exporter) Run() error {
	defer exporter.Close()

	ctx := context.Background()

	// Get user information
	address, err := server.NewAddress(exporter.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := exporter.soraDB.GetAccountIDByAddress(ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}
	user := server.NewUser(address, accountID)

	log.Printf("Exporting messages for user: %s (account ID: %d)", address.FullAddress(), accountID)

	// Get mailboxes to export
	mailboxes, err := exporter.getMailboxesToExport(ctx, user.UserID())
	if err != nil {
		return fmt.Errorf("failed to get mailboxes: %w", err)
	}

	if len(mailboxes) == 0 {
		log.Println("No mailboxes to export")
		return nil
	}

	log.Printf("Found %d mailboxes to export", len(mailboxes))

	if exporter.options.DryRun {
		log.Println("DRY RUN: Analyzing what would be exported...")
		return exporter.performDryRun(ctx, user.UserID(), mailboxes)
	}

	// Create mailbox directories
	for _, mbox := range mailboxes {
		if err := exporter.createMailboxDirectory(mbox.Name); err != nil {
			return fmt.Errorf("failed to create mailbox directory: %w", err)
		}
	}

	// Export messages from each mailbox
	for _, mbox := range mailboxes {
		log.Printf("Exporting mailbox: %s", mbox.Name)
		if err := exporter.exportMailbox(ctx, mbox); err != nil {
			log.Printf("Failed to export mailbox %s: %v", mbox.Name, err)
			// Continue with other mailboxes
		}
	}

	// Export Dovecot files if requested
	if exporter.options.Dovecot {
		if err := exporter.exportDovecotFiles(mailboxes); err != nil {
			log.Printf("Warning: Failed to export Dovecot files: %v", err)
		}
	}

	// Generate dovecot-uidlist files if requested
	if exporter.options.ExportUIDList {
		if err := exporter.generateDovecotUIDLists(mailboxes); err != nil {
			log.Printf("Warning: Failed to generate dovecot-uidlist files: %v", err)
		}
	}

	return exporter.printSummary()
}

// performDryRun analyzes what would be exported without making changes
func (exporter *Exporter) performDryRun(ctx context.Context, userID int64, mailboxes []*db.DBMailbox) error {
	fmt.Printf("\n=== DRY RUN: Export Analysis ===\n\n")
	fmt.Printf("User: %d\n", userID)

	var totalWouldExport, totalWouldSkip int64

	for _, mbox := range mailboxes {
		fmt.Printf("Mailbox: %s\n", mbox.Name)

		// Get mailbox summary
		summary, err := exporter.soraDB.GetMailboxSummary(ctx, mbox.ID)
		if err != nil {
			fmt.Printf("   Error getting summary: %v\n", err)
			continue
		}

		if summary.NumMessages == 0 {
			fmt.Printf("   No messages in this mailbox\n\n")
			continue
		}

		// Get all messages in the mailbox
		seqSet := imap.SeqSet{}
		seqSet.AddRange(1, 0) // 1:* means all messages
		messages, err := exporter.soraDB.GetMessagesByNumSet(ctx, mbox.ID, seqSet)
		if err != nil {
			fmt.Printf("   Error getting messages: %v\n", err)
			continue
		}

		var wouldExport, wouldSkip int

		for _, msg := range messages {
			// Apply date filter if specified
			if exporter.options.StartDate != nil && msg.InternalDate.Before(*exporter.options.StartDate) {
				wouldSkip++
				continue
			}
			if exporter.options.EndDate != nil && msg.InternalDate.After(*exporter.options.EndDate) {
				wouldSkip++
				continue
			}

			// Check if message would be exported or skipped
			alreadyExported, existingFilename, err := exporter.isMessageExported(msg.ContentHash, mbox.Name)
			if err != nil {
				fmt.Printf("   Error checking message UID %d: %v\n", msg.UID, err)
				continue
			}

			action := "EXPORT"
			reason := "new message"
			willSkip := false

			if alreadyExported {
				if exporter.options.OverwriteFlags {
					action = "UPDATE"
					reason = fmt.Sprintf("update flags (existing: %s)", existingFilename)
				} else {
					action = "SKIP"
					reason = fmt.Sprintf("already exported (%s)", existingFilename)
					willSkip = true
				}
			}

			if willSkip {
				wouldSkip++
			} else {
				wouldExport++
			}

			// Show detailed message info for all messages
			subject := msg.Subject
			if len(subject) > 50 {
				subject = subject[:47] + "..."
			}
			if subject == "" {
				subject = "(no subject)"
			}

			fmt.Printf("   %s UID %d: %s\n", action, msg.UID, subject)
			fmt.Printf("      Date: %s | Size: %s | Flags: %s\n",
				msg.InternalDate.Format("2006-01-02 15:04"),
				formatSize(msg.Size),
				exporter.buildMaildirFlags(&msg))
			fmt.Printf("      Action: %s: %s\n", action, reason)

			// Show first few custom flags if any
			if len(msg.CustomFlags) > 0 && len(msg.CustomFlags) <= 3 {
				fmt.Printf("      Custom flags: %v\n", msg.CustomFlags)
			} else if len(msg.CustomFlags) > 3 {
				fmt.Printf("      Custom flags: %v... (+%d more)\n", msg.CustomFlags[:3], len(msg.CustomFlags)-3)
			}

			fmt.Println()
		}

		fmt.Printf("   Summary: %d would export, %d would skip\n\n", wouldExport, wouldSkip)
		totalWouldExport += int64(wouldExport)
		totalWouldSkip += int64(wouldSkip)
	}

	// Overall summary
	fmt.Printf("=== DRY RUN: Overall Summary ===\n")
	fmt.Printf("Would export: %d messages\n", totalWouldExport)
	fmt.Printf("Would skip: %d messages\n", totalWouldSkip)
	fmt.Printf("Mailboxes: %d\n", len(mailboxes))

	if exporter.options.Dovecot {
		fmt.Printf("Would export Dovecot subscriptions file\n")
	}

	fmt.Printf("\nRun without --dry-run to perform the actual export.\n")
	return nil
}

// formatSize formats a byte size into human readable format
func formatSize(bytes int) string {
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

// getMailboxesToExport returns the list of mailboxes to export based on filters
func (exporter *Exporter) getMailboxesToExport(ctx context.Context, userID int64) ([]*db.DBMailbox, error) {
	// Get all mailboxes for the user
	allMailboxes, err := exporter.soraDB.GetMailboxes(ctx, userID, false)
	if err != nil {
		return nil, err
	}

	// Apply mailbox filter if specified
	if len(exporter.options.MailboxFilter) == 0 {
		return allMailboxes, nil
	}

	var filteredMailboxes []*db.DBMailbox
	for _, mbox := range allMailboxes {
		if exporter.shouldExportMailbox(mbox.Name) {
			filteredMailboxes = append(filteredMailboxes, mbox)
		}
	}

	return filteredMailboxes, nil
}

// shouldExportMailbox checks if a mailbox should be exported based on filters
func (exporter *Exporter) shouldExportMailbox(mailboxName string) bool {
	if len(exporter.options.MailboxFilter) == 0 {
		return true
	}

	for _, filter := range exporter.options.MailboxFilter {
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

// createMailboxDirectory creates the maildir structure for a mailbox
func (exporter *Exporter) createMailboxDirectory(mailboxName string) error {
	// Convert IMAP mailbox name to maildir path
	var dirName string
	if mailboxName == "INBOX" {
		dirName = exporter.maildirPath
	} else {
		// Convert IMAP separator (/) to filesystem-safe separator
		// Standard maildir uses folders without leading dots
		dirName = filepath.Join(exporter.maildirPath, mailboxName)
	}

	// Create cur, new, and tmp directories
	for _, subdir := range []string{"cur", "new", "tmp"} {
		path := filepath.Join(dirName, subdir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", path, err)
		}
	}

	return nil
}

// exportMailbox exports all messages from a mailbox
func (exporter *Exporter) exportMailbox(ctx context.Context, mailbox *db.DBMailbox) error {
	// Get mailbox summary
	summary, err := exporter.soraDB.GetMailboxSummary(ctx, mailbox.ID)
	if err != nil {
		return fmt.Errorf("failed to get mailbox summary: %w", err)
	}

	if summary.NumMessages == 0 {
		log.Printf("No messages in mailbox %s", mailbox.Name)
		return nil
	}

	log.Printf("Found %d messages in mailbox %s", summary.NumMessages, mailbox.Name)
	atomic.AddInt64(&exporter.totalMessages, int64(summary.NumMessages))

	// Get all messages in the mailbox using a full sequence set
	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, 0) // 1:* means all messages
	messages, err := exporter.soraDB.GetMessagesByNumSet(ctx, mailbox.ID, seqSet)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	// Process messages in parallel
	var wg sync.WaitGroup
	jobs := make(chan db.Message, 100)

	// No need for progress reporter - we'll prefix each log message

	// Start workers
	for w := 0; w < exporter.jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range jobs {
				// Retry logic: try up to 3 times
				var err error
				for retry := 0; retry < 3; retry++ {
					err = exporter.exportMessage(&msg, mailbox.Name)
					if err == nil {
						break // Success
					}

					if retry < 2 { // Don't delay after last attempt
						log.Printf("%s Export attempt %d/3 failed for UID %d: %v, retrying...", exporter.getProgressPrefix(), retry+1, msg.UID, err)
						time.Sleep(time.Duration(retry+1) * time.Second) // Exponential backoff
					}
				}

				if err != nil {
					log.Printf("%s Failed to export message UID %d after 3 attempts: %v", exporter.getProgressPrefix(), msg.UID, err)
					atomic.AddInt64(&exporter.failedMessages, 1)
				}
			}
		}()
	}

	// Feed jobs to workers
	for _, msg := range messages {
		// Apply date filter if specified
		if exporter.options.StartDate != nil && msg.InternalDate.Before(*exporter.options.StartDate) {
			atomic.AddInt64(&exporter.skippedMessages, 1)
			continue
		}
		if exporter.options.EndDate != nil && msg.InternalDate.After(*exporter.options.EndDate) {
			atomic.AddInt64(&exporter.skippedMessages, 1)
			continue
		}

		jobs <- msg
	}

	close(jobs)
	wg.Wait()

	return nil
}

// exportMessage exports a single message to maildir
func (exporter *Exporter) exportMessage(msg *db.Message, mailboxName string) error {
	// Check if message was already exported
	alreadyExported, existingFilename, err := exporter.isMessageExported(msg.ContentHash, mailboxName)
	if err != nil {
		return fmt.Errorf("failed to check if message was exported: %w", err)
	}

	if alreadyExported && !exporter.options.OverwriteFlags {
		atomic.AddInt64(&exporter.skippedMessages, 1)
		log.Printf("%s Message already exported (hash: %s), skipping", exporter.getProgressPrefix(), msg.ContentHash[:12])
		return nil
	}

	// Use the stored S3 key components from the message record to prevent issues
	// if the user's primary email has changed since the message was stored.
	if msg.S3Domain == "" || msg.S3Localpart == "" {
		return fmt.Errorf("message UID %d is missing S3 key information", msg.UID)
	}
	s3Key := helpers.NewS3Key(msg.S3Domain, msg.S3Localpart, msg.ContentHash)

	// Download message content from S3
	reader, err := exporter.s3.Get(s3Key)
	if err != nil {
		return fmt.Errorf("failed to download message from S3: %w", err)
	}
	defer reader.Close()

	// Read content into memory
	content, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read message content: %w", err)
	}

	// Generate maildir filename
	var filename string
	if existingFilename != "" {
		// Use existing filename from database (either for update or recreation)
		filename = existingFilename
		if alreadyExported {
			log.Printf("%s Updating existing file with new flags: %s", exporter.getProgressPrefix(), filename)
		} else {
			log.Printf("%s Recreating missing file with original filename: %s", exporter.getProgressPrefix(), filename)
		}
	} else {
		// Generate new filename
		filename = exporter.generateMaildirFilename(msg)
	}

	// Determine target directory
	var targetDir string
	if mailboxName == "INBOX" {
		targetDir = filepath.Join(exporter.maildirPath, "cur")
	} else {
		// Standard maildir uses folders without leading dots
		targetDir = filepath.Join(exporter.maildirPath, mailboxName, "cur")
	}

	targetPath := filepath.Join(targetDir, filename)

	// If updating flags on existing message, remove old file first
	if alreadyExported && exporter.options.OverwriteFlags && existingFilename != "" {
		oldPath := filepath.Join(targetDir, existingFilename)
		if oldPath != targetPath {
			os.Remove(oldPath)
		}
	}

	// Write message to file
	if err := os.WriteFile(targetPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	// Set file modification time to internal date
	if err := os.Chtimes(targetPath, msg.InternalDate, msg.InternalDate); err != nil {
		log.Printf("Warning: Failed to set file times: %v", err)
	}

	// Record export in database
	if err := exporter.recordExport(msg.ContentHash, mailboxName, filename, targetPath, int64(msg.Size)); err != nil {
		log.Printf("Warning: Failed to record export: %v", err)
	}

	atomic.AddInt64(&exporter.exportedMessages, 1)
	log.Printf("%s Successfully exported message: UID=%d, mailbox=%s, file=%s", exporter.getProgressPrefix(), msg.UID, mailboxName, filename)

	// Collect UID mapping for dovecot-uidlist generation if enabled
	if exporter.options.ExportUIDList {
		exporter.mu.Lock()
		// Extract base filename without flags for UID mapping
		baseFilename := filename
		if idx := strings.LastIndex(baseFilename, ":"); idx > 0 {
			baseFilename = baseFilename[:idx]
		}

		exporter.uidMappings[mailboxName] = append(exporter.uidMappings[mailboxName], UIDFileMapping{
			UID:      uint32(msg.UID),
			Filename: baseFilename,
		})
		exporter.mu.Unlock()
	}

	// Add delay if configured to control rate
	if exporter.options.ExportDelay > 0 {
		time.Sleep(exporter.options.ExportDelay)
	}
	return nil
}

// generateMaildirFilename generates a maildir-compatible filename for a message
func (exporter *Exporter) generateMaildirFilename(msg *db.Message) string {
	// Basic maildir filename format: timestamp.unique_id.hostname:2,flags
	timestamp := msg.InternalDate.Unix()
	uniqueID := fmt.Sprintf("M%dP%d", timestamp, msg.UID)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// Build flags string
	flagStr := exporter.buildMaildirFlags(msg)

	return fmt.Sprintf("%d.%s.%s:2,%s", timestamp, uniqueID, hostname, flagStr)
}

// buildMaildirFlags converts IMAP flags to maildir flag characters
func (exporter *Exporter) buildMaildirFlags(msg *db.Message) string {
	var flags []byte

	// Convert system flags from bitwise representation
	systemFlags := db.BitwiseToFlags(msg.BitwiseFlags)
	for _, flag := range systemFlags {
		switch flag {
		case imap.FlagDraft:
			flags = append(flags, 'D')
		case imap.FlagFlagged:
			flags = append(flags, 'F')
		case imap.FlagAnswered:
			flags = append(flags, 'R')
		case imap.FlagSeen:
			flags = append(flags, 'S')
		case imap.FlagDeleted:
			flags = append(flags, 'T')
			// Note: \Recent flag is not stored in maildir filenames
		}
	}

	// Sort flags alphabetically as per maildir spec
	for i := 0; i < len(flags)-1; i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i] > flags[j] {
				flags[i], flags[j] = flags[j], flags[i]
			}
		}
	}

	return string(flags)
}

// isMessageExported checks if a message already exists in the maildir
// Returns: (fileExists, filename, error)
// - fileExists: true if file exists on disk, false if needs to be created
// - filename: original filename from database (empty if not in database)
func (exporter *Exporter) isMessageExported(contentHash, mailbox string) (bool, string, error) {
	var filename, path string
	err := exporter.db.QueryRow(
		"SELECT filename, path FROM messages WHERE hash = ? AND mailbox = ?",
		contentHash, mailbox,
	).Scan(&filename, &path)

	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	// Check if the file still exists on disk
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("File in database but not on disk, will recreate with original filename: %s", filename)
		return false, filename, nil // Return the original filename for reuse
	}

	return true, filename, nil
}

// recordExport records that a message was exported
func (exporter *Exporter) recordExport(contentHash, mailbox, filename, path string, size int64) error {
	_, err := exporter.db.Exec(
		`INSERT OR REPLACE INTO messages (hash, mailbox, filename, path, size) 
		 VALUES (?, ?, ?, ?, ?)`,
		contentHash, mailbox, filename, path, size,
	)
	return err
}

// exportDovecotFiles exports Dovecot-specific metadata files
func (exporter *Exporter) exportDovecotFiles(mailboxes []*db.DBMailbox) error {
	// Export subscriptions file
	if err := exporter.exportSubscriptions(mailboxes); err != nil {
		return fmt.Errorf("failed to export subscriptions: %w", err)
	}

	log.Println("Exported Dovecot subscriptions file")
	return nil
}

// exportSubscriptions exports the Dovecot subscriptions file
func (exporter *Exporter) exportSubscriptions(mailboxes []*db.DBMailbox) error {
	subscriptionsPath := filepath.Join(exporter.maildirPath, "subscriptions")

	var lines []string
	lines = append(lines, "V\t2") // Dovecot v2 format

	// Add subscribed mailboxes
	for _, mbox := range mailboxes {
		if mbox.Subscribed {
			lines = append(lines, mbox.Name)
		}
	}

	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(subscriptionsPath, []byte(content), 0644)
}

// getProgressPrefix returns a progress prefix for log messages
func (exporter *Exporter) getProgressPrefix() string {
	exported := atomic.LoadInt64(&exporter.exportedMessages)
	failed := atomic.LoadInt64(&exporter.failedMessages)
	skipped := atomic.LoadInt64(&exporter.skippedMessages)
	total := atomic.LoadInt64(&exporter.totalMessages)

	processed := exported + failed + skipped
	percentage := float64(processed) * 100.0 / float64(total)

	return fmt.Sprintf("[%d/%d %.1f%%]", processed, total, percentage)
}

// printSummary prints a summary of the export process
func (exporter *Exporter) printSummary() error {
	duration := time.Since(exporter.startTime)
	fmt.Printf("\n\nExport Summary:\n")
	fmt.Printf("  Total messages:    %d\n", exporter.totalMessages)
	fmt.Printf("  Exported:          %d\n", exporter.exportedMessages)
	fmt.Printf("  Skipped:           %d\n", exporter.skippedMessages)
	fmt.Printf("  Failed:            %d\n", exporter.failedMessages)
	fmt.Printf("  Duration:          %s\n", duration.Round(time.Second))
	if exporter.exportedMessages > 0 {
		rate := float64(exporter.exportedMessages) / duration.Seconds()
		fmt.Printf("  Export rate:       %.1f messages/sec\n", rate)
	}
	if exporter.options.Dovecot {
		fmt.Printf("\nNote: Dovecot subscriptions file exported.\n")
	}
	if exporter.options.ExportUIDList {
		fmt.Printf("Note: Dovecot uidlist files generated.\n")
	}
	return nil
}

// generateDovecotUIDLists generates dovecot-uidlist files for all exported mailboxes
func (exporter *Exporter) generateDovecotUIDLists(mailboxes []*db.DBMailbox) error {
	log.Println("Generating dovecot-uidlist files...")

	exporter.mu.Lock()
	defer exporter.mu.Unlock()

	for mailboxName, mappings := range exporter.uidMappings {
		if len(mappings) == 0 {
			continue
		}

		// Find the mailbox to get its UIDVALIDITY
		var uidValidity uint32
		for _, mbox := range mailboxes {
			if mbox.Name == mailboxName {
				uidValidity = uint32(mbox.UIDValidity)
				break
			}
		}

		// If no UIDVALIDITY found, generate one based on current timestamp
		if uidValidity == 0 {
			uidValidity = uint32(time.Now().Unix())
			log.Printf("Warning: No UIDVALIDITY found for mailbox %s, using generated value: %d", mailboxName, uidValidity)
		}

		// Create DovecotUIDList from mappings
		uidList := CreateDovecotUIDListFromMessages(uidValidity, mappings)

		// Determine maildir path for this mailbox
		var maildirPath string
		if mailboxName == "INBOX" {
			maildirPath = exporter.maildirPath
		} else {
			maildirPath = filepath.Join(exporter.maildirPath, mailboxName)
		}

		// Write dovecot-uidlist file
		if err := WriteDovecotUIDList(maildirPath, uidList); err != nil {
			return fmt.Errorf("failed to write dovecot-uidlist for mailbox %s: %w", mailboxName, err)
		}

		log.Printf("Generated dovecot-uidlist for mailbox %s: %d messages, UIDVALIDITY=%d, NextUID=%d",
			mailboxName, len(mappings), uidValidity, uidList.NextUID)
	}

	return nil
}
