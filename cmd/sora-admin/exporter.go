package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	_ "modernc.org/sqlite"
)

// ExporterOptions contains configuration options for the exporter
type ExporterOptions struct {
	DryRun         bool
	StartDate      *time.Time
	EndDate        *time.Time
	MailboxFilter  []string
	Dovecot        bool
	OverwriteFlags bool          // Whether to overwrite flags on existing messages
	ExportDelay    time.Duration // Delay between exports to control rate
	ExportUIDList  bool          // Whether to export dovecot-uidlist files
}

// Exporter handles the maildir export process.
type Exporter struct {
	ctx             context.Context // Context for cancellation support
	maildirPath     string
	root            *os.Root // confines message/Dovecot contents and Maildir child directories; excludes the SQLite cache
	email           string
	jobs            int
	db              *sql.DB
	dbPath          string // Path to the SQLite database file
	privateCacheDir string // Dry-run snapshot, removed after closing its SQLite connection
	rdb             *resilient.ResilientDatabase
	s3              objectStorage
	options         ExporterOptions

	totalMessages    int64
	exportedMessages int64
	skippedMessages  int64
	failedMessages   int64
	failedMailboxes  int64
	startTime        time.Time
	mu               sync.Mutex

	// UID mappings per mailbox for dovecot-uidlist generation
	uidMappings map[string][]UIDFileMapping // mailbox name -> UID mappings

	// keywordIndex is each mailbox's custom-keyword numbering (keyword -> 0..25), the
	// content of the dovecot-keywords file written for that folder; filenames carry the
	// matching a-z letters (prepareKeywords / buildMaildirFlags).
	keywordIndex map[string]map[string]int
}

// exportRootOpened, when set, runs in NewExporter as soon as the root is open: a test
// replaces --maildir-path there, as the owner of the directory holding it can at any
// moment.
var exportRootOpened func()

// NewExporter creates a new Exporter instance.
func NewExporter(ctx context.Context, maildirPath, email string, jobs int, rdb *resilient.ResilientDatabase, s3 objectStorage, options ExporterOptions) (*Exporter, error) {
	// The export runs on exactly this many workers: with none it would write nothing.
	if jobs < 1 {
		return nil, fmt.Errorf("jobs must be at least 1, got %d", jobs)
	}
	// Preview never creates or migrates anything in the selected maildir. It reaches
	// the target as the export does, refusing the links the export refuses, and copies
	// the cache through the directory it checked (openExportCacheForDryRun). A target
	// that is missing holds no cache: every message is new.
	if options.DryRun {
		root, err := openExportPreviewRoot(maildirPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open maildir path: %w", err)
		}
		if root != nil && exportRootOpened != nil {
			exportRootOpened()
		}
		maildirPath = effectiveMaildirPath(maildirPath)
		dbPath := filepath.Join(maildirPath, maildirCacheName)
		var cache *sql.DB
		var privateDir string
		if root != nil {
			cache, privateDir, err = openExportCacheForDryRun(ctx, root)
			if err != nil || cache == nil {
				root.Close()
				root = nil
			}
			if err != nil {
				return nil, err
			}
		}
		return &Exporter{ctx: ctx, maildirPath: maildirPath, root: root, email: email,
			jobs: jobs, db: cache, dbPath: dbPath, privateCacheDir: privateDir, rdb: rdb, s3: s3,
			options: options, startTime: time.Now(), uidMappings: make(map[string][]UIDFileMapping),
			keywordIndex: make(map[string]map[string]int)}, nil
	}

	// Every message and metadata file is written through this root. It is opened, and
	// the directories missing on the way created, first: a directory that a link on the
	// path may not choose is refused before anything is created in it, the cache
	// included (openExportRoot).
	root, err := openExportRoot(maildirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open maildir path: %w", err)
	}
	var exporter *Exporter
	defer func() {
		if exporter == nil {
			root.Close()
		}
	}()
	if exportRootOpened != nil {
		exportRootOpened()
	}
	maildirPath = effectiveMaildirPath(maildirPath)

	// Use the shared SQLite database in the maildir path
	dbPath := filepath.Join(maildirPath, maildirCacheName)
	logger.Info("Using maildir database", "path", dbPath)

	// The cache is opened in the directory the walk checked, through root: the path
	// may lead elsewhere by now.
	db, err := openMaildirCache(root)
	if err != nil {
		return nil, err
	}

	// Create the same table structure as importer uses
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
		return nil, fmt.Errorf("failed to create exported_messages table: %w", err)
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
		// DEFAULT 0 must match the fresh schema above. This is the same database file the
		// importer uses, and a column default added here is permanent for it: a default of
		// 1 would make every file a later import scan discovers born "already uploaded"
		// and so invisible to that import. Pre-existing rows are marked below instead.
		_, err = db.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded INTEGER DEFAULT 0`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded column: %w", err)
		}

		_, err = db.Exec(`ALTER TABLE messages ADD COLUMN s3_uploaded_at TIMESTAMP`)
		if err != nil {
			return nil, fmt.Errorf("failed to add s3_uploaded_at column: %w", err)
		}

		// Mark all existing messages as uploaded (they were in old DB, so they're on S3)
		_, err = db.Exec(`UPDATE messages SET s3_uploaded = 1, s3_uploaded_at = CURRENT_TIMESTAMP`)
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

	exporter = &Exporter{
		ctx:          ctx,
		maildirPath:  maildirPath,
		root:         root,
		email:        email,
		jobs:         jobs,
		db:           db,
		dbPath:       dbPath,
		rdb:          rdb,
		s3:           s3,
		options:      options,
		startTime:    time.Now(),
		uidMappings:  make(map[string][]UIDFileMapping),
		keywordIndex: make(map[string]map[string]int),
	}

	return exporter, nil
}

// Close cleans up resources used by the exporter.
func (exporter *Exporter) Close() error {
	var closeErr error
	if exporter.db != nil {
		closeErr = errors.Join(closeErr, exporter.db.Close())
		if !exporter.options.DryRun {
			logger.Info("Maildir database saved", "path", exporter.dbPath)
		}
	}
	if exporter.root != nil {
		closeErr = errors.Join(closeErr, exporter.root.Close())
		exporter.root = nil
	}
	if exporter.privateCacheDir != "" {
		closeErr = errors.Join(closeErr, os.RemoveAll(exporter.privateCacheDir))
		exporter.privateCacheDir = ""
	}
	return closeErr
}

// Run starts the export process.
func (exporter *Exporter) Run() error {
	defer exporter.Close()

	// Get user information
	address, err := server.NewAddress(exporter.email)
	if err != nil {
		return fmt.Errorf("invalid email address: %w", err)
	}

	accountID, err := exporter.rdb.GetAccountIDByAddressWithRetry(exporter.ctx, address.FullAddress())
	if err != nil {
		return fmt.Errorf("failed to get account: %w", err)
	}
	user := server.NewUser(address, accountID)

	logger.Info("Exporting messages for user", "email", address.FullAddress(), "account_id", accountID)

	// Get mailboxes to export
	mailboxes, err := exporter.getMailboxesToExport(exporter.ctx, user.AccountID())
	if err != nil {
		return fmt.Errorf("failed to get mailboxes: %w", err)
	}

	if len(mailboxes) == 0 {
		logger.Info("No mailboxes to export")
		return nil
	}

	logger.Info("Found mailboxes to export", "count", len(mailboxes))

	if exporter.options.DryRun {
		logger.Info("DRY RUN: Analyzing what would be exported...")
		return exporter.performDryRun(exporter.ctx, user.AccountID(), mailboxes)
	}

	// Create mailbox directories
	for _, mbox := range mailboxes {
		if err := exporter.createMailboxDirectory(mbox.Name); err != nil {
			return fmt.Errorf("failed to create mailbox directory: %w", err)
		}
	}

	// Export messages from each mailbox
	for _, mbox := range mailboxes {
		logger.Info("Exporting mailbox", "name", mbox.Name)
		if err := exporter.exportMailbox(exporter.ctx, mbox); err != nil {
			logger.Warn("Failed to export mailbox", "name", mbox.Name, "error", err)
			atomic.AddInt64(&exporter.failedMailboxes, 1)
			// Continue with other mailboxes; the run still ends with an error.
		}
	}

	// Export Dovecot files if requested
	var dovecotErr, uidListErr error
	if exporter.options.Dovecot {
		if dovecotErr = exporter.exportDovecotFiles(accountID); dovecotErr != nil {
			logger.Warn("Failed to export Dovecot files", "error", dovecotErr)
		}
	}

	// Generate dovecot-uidlist files if requested
	if exporter.options.ExportUIDList {
		if uidListErr = exporter.generateDovecotUIDLists(mailboxes); uidListErr != nil {
			logger.Warn("Failed to generate dovecot-uidlist files", "error", uidListErr)
		}
	}

	if err := exporter.printSummary(dovecotErr, uidListErr); err != nil {
		return err
	}
	// An export that lost anything must not exit 0: an operator scripting a migration
	// reads the exit code, not the log. That includes the subscriptions and uidlist
	// files: an import of an export without them loses the subscriptions or the UIDs.
	filesErr := errors.Join(dovecotErr, uidListErr)
	failedMsgs := atomic.LoadInt64(&exporter.failedMessages)
	failedMboxes := atomic.LoadInt64(&exporter.failedMailboxes)
	if failedMsgs > 0 || failedMboxes > 0 {
		return errors.Join(fmt.Errorf("export incomplete: %d message(s) and %d mailbox(es) failed", failedMsgs, failedMboxes), filesErr)
	}
	return filesErr
}

// performDryRun analyzes what would be exported without making changes
func (exporter *Exporter) performDryRun(ctx context.Context, AccountID int64, mailboxes []*db.DBMailbox) error {
	fmt.Printf("\n=== DRY RUN: Export Analysis ===\n\n")
	fmt.Printf("User: %d\n", AccountID)

	var totalWouldExport, totalWouldSkip int64

	for _, mbox := range mailboxes {
		fmt.Printf("Mailbox: %s\n", mbox.Name)

		// Get mailbox summary
		summary, err := exporter.rdb.GetMailboxSummaryWithRetry(ctx, mbox.ID)
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
		messages, err := exporter.rdb.GetMessagesByNumSetWithRetry(ctx, mbox.ID, seqSet)
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
				exporter.buildMaildirFlags(&msg, mbox.Name))
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
func (exporter *Exporter) getMailboxesToExport(ctx context.Context, AccountID int64) ([]*db.DBMailbox, error) {
	// Get all mailboxes for the user
	allMailboxes, err := exporter.rdb.GetMailboxesWithRetry(ctx, AccountID, false)
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

// mailboxDirName resolves the maildir directory (the parent of cur/new/tmp) for an
// IMAP mailbox name to its name below the export directory, as exporter.root opens
// it, guaranteeing the name stays within the export root. A malicious or legacy
// mailbox name containing ".." path segments (e.g. "../../etc") would otherwise
// escape the export directory and write arbitrary files. This is defence-in-depth:
// mailbox creation, rename, and import already reject such names
// (helpers.MailboxNameHasTraversal), but the exporter must never trust a name
// already persisted in the database.
//
// Each level of the name is one directory (Dovecot's LAYOUT=fs), named by
// maildirFolderName so that the importer's resolveMailboxName reads it back.
func (exporter *Exporter) mailboxDirName(mailboxName string) (string, error) {
	if mailboxName == "INBOX" {
		return ".", nil
	}
	if helpers.MailboxNameHasTraversal(mailboxName) {
		return "", fmt.Errorf("mailbox %q resolves outside the export directory", mailboxName)
	}
	name := filepath.Clean(filepath.FromSlash(maildirFolderName(mailboxName)))
	if name == "." || !filepath.IsLocal(name) {
		return "", fmt.Errorf("mailbox %q resolves outside the export directory", mailboxName)
	}
	return name, nil
}

// maildirEscapeChar escapes a character in a folder's directory name as itself
// followed by the character's value in two hex digits: "v1.2" is written "v1\2e2".
// It is Dovecot's storage name escape character ('\', the 2.3 listescape plugin's
// default; mailbox_list_storage_escape_char in 2.4), whose
// mailbox_list_escape_name_params writes the same form.
const maildirEscapeChar = '\\'

// maildirFolderName is a mailbox's name on disk, its levels joined by '/', each named
// by maildirFolderLevel: Dovecot's storage name. The export names both the folder's
// directories and its entry in the subscriptions file so, as Dovecot names both by
// the storage name, and the importer reads both back through importedFolderName.
func maildirFolderName(mailboxName string) string {
	delim := string(consts.MailboxDelimiter)
	levels := strings.Split(mailboxName, delim)
	for i, level := range levels {
		levels[i] = maildirFolderLevel(level, i == 0)
	}
	return strings.Join(levels, delim)
}

// maildirFolderLevel is the directory name of one level of a mailbox name, top
// telling whether it is the first level, whose directory is in the export root. It is
// modified UTF-7, as Dovecot names folders on disk and as exportSubscriptions names
// them, so the importer does not decode an '&' or a literal "&...-" of the name.
// A level named after an entry of the directory that holds it (maildirDirectoryEntry)
// escapes its first character, keeping the byte's case, so the two do not collide:
// "cur" is \63ur and "subscriptions" \73ubscriptions. Dovecot escapes a level that
// would clash with a name of its own storage the same way (need_escape_dirstart in
// mailbox-list.c). A '.' is escaped because the importer reads it as the Maildir++
// hierarchy separator, and so is the escape character, so
// that unescapeMaildirLevel restores exactly the characters escaped here.
func maildirFolderLevel(level string, top bool) string {
	encoded := helpers.EncodeModifiedUTF7(level)
	if maildirDirectoryEntry(encoded, top) {
		return fmt.Sprintf(`\%02x%s`, encoded[0], encoded[1:])
	}
	if !strings.ContainsAny(encoded, ".\\") {
		return encoded
	}
	var b strings.Builder
	for i := 0; i < len(encoded); i++ {
		if c := encoded[i]; c == '.' || c == maildirEscapeChar {
			fmt.Fprintf(&b, "%c%02x", maildirEscapeChar, c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// maildirDirectoryEntry reports whether a level's directory name is an entry the
// export writes in the directory that holds it, top telling whether that is the
// export root: every mailbox directory holds a Maildir's cur/, new/ and tmp/ and the
// dovecot-uidlist and dovecot-keywords files, and the export root, INBOX's directory,
// also the subscriptions file. The names are compared without case for filesystems
// that ignore it. sora-maildir.db and its -wal and -shm files, also in the root, need
// no entry here: their '.' is escaped.
func maildirDirectoryEntry(name string, top bool) bool {
	switch strings.ToLower(name) {
	case "cur", "new", "tmp", "dovecot-uidlist", "dovecot-keywords":
		return true
	case "subscriptions":
		return top
	}
	return false
}

// createMailboxDirectory creates the maildir structure for a mailbox
func (exporter *Exporter) createMailboxDirectory(mailboxName string) error {
	// Convert IMAP mailbox name to a contained maildir path
	dirName, err := exporter.mailboxDirName(mailboxName)
	if err != nil {
		return err
	}

	// Create cur, new, and tmp directories. The root refuses a directory on the way
	// that links out of the export directory.
	for _, subdir := range []string{"cur", "new", "tmp"} {
		if err := exporter.root.MkdirAll(filepath.Join(dirName, subdir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", filepath.Join(exporter.maildirPath, dirName, subdir), err)
		}
	}

	return nil
}

// exportMailbox exports all messages from a mailbox
func (exporter *Exporter) exportMailbox(ctx context.Context, mailbox *db.DBMailbox) error {
	// Get mailbox summary
	summary, err := exporter.rdb.GetMailboxSummaryWithRetry(ctx, mailbox.ID)
	if err != nil {
		return fmt.Errorf("failed to get mailbox summary: %w", err)
	}

	// The summary's count is the cached mailbox_stats.message_count, which is known to
	// drift. It is only an estimate for progress reporting here: the messages are
	// listed live below, so a mailbox whose cached count is wrong (0 included) is
	// still exported in full.
	logger.Info("Exporting mailbox", "estimated_count", summary.NumMessages, "name", mailbox.Name)
	atomic.AddInt64(&exporter.totalMessages, int64(summary.NumMessages))

	// Get all messages in the mailbox using a full sequence set
	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, 0) // 1:* means all messages
	messages, err := exporter.rdb.GetMessagesByNumSetWithRetry(ctx, mailbox.ID, seqSet)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	// Custom keywords travel in the filenames as a-z letters that index this folder's
	// dovecot-keywords file, so the numbering must exist before any filename is built.
	if exporter.options.Dovecot {
		if err := exporter.prepareKeywords(mailbox.Name, messages); err != nil {
			return fmt.Errorf("failed to write dovecot-keywords: %w", err)
		}
	}

	// Process messages in parallel
	var wg sync.WaitGroup
	// Make channel buffer large enough to hold all messages to prevent deadlock
	// when workers are blocked on SQLite access
	bufferSize := len(messages)
	if bufferSize < 100 {
		bufferSize = 100 // Maintain minimum buffer
	}
	jobs := make(chan db.Message, bufferSize)

	// No need for progress reporter - we'll prefix each log message

	// Start workers
	for w := 0; w < exporter.jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range jobs {
				// Check for cancellation before processing each message
				select {
				case <-exporter.ctx.Done():
					logger.Info("Export worker cancelled by user")
					return
				default:
				}

				// Retry logic: try up to 3 times
				var err error
				for retry := 0; retry < 3; retry++ {
					err = exporter.exportMessage(&msg, mailbox.Name)
					if err == nil {
						break // Success
					}

					if retry < 2 { // Don't delay after last attempt
						logger.Info("Export attempt failed - retrying", "progress", exporter.getProgressPrefix(), "attempt", retry+1, "uid", msg.UID, "error", err)
						time.Sleep(time.Duration(retry+1) * time.Second) // Exponential backoff
					}
				}

				if err != nil {
					logger.Info("Failed to export message after 3 attempts", "progress", exporter.getProgressPrefix(), "uid", msg.UID, "error", err)
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

		// Use non-blocking send with context cancellation to prevent deadlock
		select {
		case <-exporter.ctx.Done():
			logger.Info("Export job submission cancelled by user")
			close(jobs)
			wg.Wait()
			return exporter.ctx.Err()
		case jobs <- msg:
			// Message sent successfully
		}
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
		logger.Info("Message already exported - skipping", "progress", exporter.getProgressPrefix(), "hash", msg.ContentHash[:12])
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
			logger.Info("Updating existing file with new flags", "progress", exporter.getProgressPrefix(), "filename", filename)
		} else {
			logger.Info("Recreating missing file with original filename", "progress", exporter.getProgressPrefix(), "filename", filename)
		}
	} else {
		// Generate new filename
		filename = exporter.generateMaildirFilename(msg, mailboxName)
	}

	// Determine target directory (containment-checked against the export root)
	mailboxDir, err := exporter.mailboxDirName(mailboxName)
	if err != nil {
		return err
	}
	targetDir := filepath.Join(mailboxDir, "cur")

	targetName := filepath.Join(targetDir, filename)

	// If updating flags on existing message, remove old file first
	if alreadyExported && exporter.options.OverwriteFlags && existingFilename != "" {
		oldName := filepath.Join(targetDir, existingFilename)
		if oldName != targetName {
			exporter.root.Remove(oldName)
		}
	}

	// Write the message the maildir way: into tmp/, fsync, then rename into place. A
	// crash or a full disk must never leave a truncated file where a maildir reader
	// (Dovecot, or a re-import) would take it for the message.
	if err := writeMaildirFile(exporter.root, targetName, content); err != nil {
		return fmt.Errorf("failed to write message file: %w", err)
	}

	// Set file modification time to internal date
	if err := exporter.root.Chtimes(targetName, msg.InternalDate, msg.InternalDate); err != nil {
		logger.Info("Warning: Failed to set file times", "error", err)
	}

	// Record export in database
	targetPath := filepath.Join(exporter.maildirPath, targetName)
	if err := exporter.recordExport(msg.ContentHash, mailboxName, filename, targetPath, int64(msg.Size)); err != nil {
		logger.Info("Warning: Failed to record export", "error", err)
	}

	atomic.AddInt64(&exporter.exportedMessages, 1)
	logger.Info("Successfully exported message", "progress", exporter.getProgressPrefix(), "uid", msg.UID, "mailbox", mailboxName, "file", filename)

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
func (exporter *Exporter) generateMaildirFilename(msg *db.Message, mailboxName string) string {
	// Basic maildir filename format: timestamp.unique_id.hostname:2,flags
	timestamp := msg.InternalDate.Unix()
	uniqueID := fmt.Sprintf("M%dP%d", timestamp, msg.UID)
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// Build flags string
	flagStr := exporter.buildMaildirFlags(msg, mailboxName)

	return fmt.Sprintf("%d.%s.%s:2,%s", timestamp, uniqueID, hostname, flagStr)
}

// buildMaildirFlags converts IMAP flags to maildir info characters: the system flags
// (D=Draft F=Flagged R=Answered S=Seen T=Trashed/\Deleted, as the importer reads them)
// plus one a-z letter per custom keyword, indexing the mailbox's dovecot-keywords
// numbering (prepareKeywords).
func (exporter *Exporter) buildMaildirFlags(msg *db.Message, mailboxName string) string {
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

	// Custom keywords: only those the folder's numbering knows (beyond 26 they were
	// dropped with a warning in prepareKeywords).
	exporter.mu.Lock()
	index := exporter.keywordIndex[mailboxName]
	exporter.mu.Unlock()
	for _, keyword := range msg.CustomFlags {
		if idx, ok := index[keyword]; ok {
			flags = append(flags, byte('a'+idx))
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
//
// The file is looked for in the directory this export writes the mailbox to
// (mailboxDir), not at the path recorded with it: an older version named some
// folders' directories differently (#1166), and a message left only in such a
// directory is not in the folder the importer reads the mailbox from.
func (exporter *Exporter) isMessageExported(contentHash, mailbox string) (bool, string, error) {
	if exporter.db == nil {
		return false, "", nil
	}

	var filename string
	err := exporter.db.QueryRow(
		"SELECT filename FROM messages WHERE hash = ? AND mailbox = ?",
		contentHash, mailbox,
	).Scan(&filename)

	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	dir, err := exporter.mailboxDirName(mailbox)
	if err != nil {
		return false, "", err
	}
	// Check if the file still exists on disk
	if _, err := exporter.root.Stat(filepath.Join(dir, "cur", filename)); os.IsNotExist(err) {
		logger.Info("File in database but not on disk - will recreate with original filename", "filename", filename)
		return false, filename, nil // Return the original filename for reuse
	}

	return true, filename, nil
}

// recordExport records that a message was exported and marks it as present on S3
func (exporter *Exporter) recordExport(contentHash, mailbox, filename, path string, size int64) error {
	_, err := exporter.db.Exec(
		`INSERT OR REPLACE INTO messages (hash, mailbox, filename, path, size, s3_uploaded, s3_uploaded_at)
		 VALUES (?, ?, ?, ?, ?, 1, ?)`,
		contentHash, mailbox, filename, path, size, time.Now(),
	)
	return err
}

// exportDovecotFiles exports Dovecot-specific metadata files
func (exporter *Exporter) exportDovecotFiles(accountID int64) error {
	// Export subscriptions file
	if err := exporter.exportSubscriptions(accountID); err != nil {
		return fmt.Errorf("failed to export subscriptions: %w", err)
	}

	logger.Info("Exported Dovecot subscriptions file")
	return nil
}

// exportSubscriptions exports the Dovecot subscriptions file
func (exporter *Exporter) exportSubscriptions(accountID int64) error {
	// Subscriptions are name-based and may reference folders that
	// no longer exist, so export ALL subscribed names — not just the subset that
	// still has a live mailbox — for a lossless Dovecot round-trip.
	names, err := exporter.rdb.GetSubscribedMailboxNamesWithRetry(exporter.ctx, accountID)
	if err != nil {
		return fmt.Errorf("failed to fetch subscriptions for export: %w", err)
	}

	// Dovecot's subscriptions file holds storage names (index_storage_set_subscribed
	// writes box->name), so each name is written as its folder's directories are named,
	// modified UTF-7 and escaped (maildirFolderName). The import reads both back through
	// importedFolderName, so a subscription names the mailbox its folder imports as.
	encoded := make([]string, len(names))
	for i, name := range names {
		encoded[i] = maildirFolderName(name)
	}

	return replaceFile(exporter.root, ".", "subscriptions", []byte(formatDovecotSubscriptions(encoded)))
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

// printSummary prints a summary of the export process. dovecotErr and uidListErr are
// the failures of the subscriptions file and of the dovecot-uidlist files, which the
// summary must not report as written.
func (exporter *Exporter) printSummary(dovecotErr, uidListErr error) error {
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
		if dovecotErr == nil {
			fmt.Printf("\nNote: Dovecot subscriptions file exported.\n")
		} else {
			fmt.Printf("\nNote: Dovecot subscriptions file NOT exported.\n")
		}
	}
	if exporter.options.ExportUIDList {
		if uidListErr == nil {
			fmt.Printf("Note: Dovecot uidlist files generated.\n")
		} else {
			fmt.Printf("Note: Some Dovecot uidlist files could NOT be written.\n")
		}
	}
	return nil
}

// generateDovecotUIDLists generates dovecot-uidlist files for all exported mailboxes.
// A mailbox whose file cannot be written does not cost the others theirs: every
// failure is returned, after all the others are written.
func (exporter *Exporter) generateDovecotUIDLists(mailboxes []*db.DBMailbox) error {
	logger.Info("Generating dovecot-uidlist files...")

	exporter.mu.Lock()
	defer exporter.mu.Unlock()

	var errs []error
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
			logger.Info("Warning: No UIDVALIDITY found - using generated value", "mailbox", mailboxName, "uidvalidity", uidValidity)
		}

		// Determine maildir directory for this mailbox (containment-checked)
		dir, err := exporter.mailboxDirName(mailboxName)
		if err != nil {
			logger.Info("Warning: Skipping dovecot-uidlist for unsafe mailbox name", "mailbox", mailboxName, "error", err)
			continue
		}

		// This run only recorded the messages it wrote. An earlier export of the same
		// maildir left a dovecot-uidlist naming everything it wrote then, and those files
		// are still here (they were skipped as already exported, not re-recorded).
		// Rewriting the file with only this run's delta would make Dovecot reassign
		// UIDs to every other message, so merge: keep the existing entries whose file
		// still exists, and let this run's entries win for the UIDs it wrote.
		mappings = mergeUIDMappings(exporter.root, dir, mappings)

		// Create DovecotUIDList from mappings
		uidList := CreateDovecotUIDListFromMessages(uidValidity, mappings)

		// Write dovecot-uidlist file
		if err := replaceFile(exporter.root, dir, filepath.Join(dir, "dovecot-uidlist"), formatDovecotUIDList(uidList)); err != nil {
			errs = append(errs, fmt.Errorf("failed to write dovecot-uidlist for mailbox %s: %w", mailboxName, err))
			continue
		}

		logger.Info("Generated dovecot-uidlist for mailbox", "mailbox", mailboxName,
			"messages", len(mappings), "uidvalidity", uidValidity, "next_uid", uidList.NextUID)
	}

	return errors.Join(errs...)
}

// writeMaildirFile stores content as the file name (below root, under a maildir's cur/
// or new/) the way maildir requires: written to the maildir's tmp/ directory, fsync'd,
// then renamed into place (replaceFile). A reader of the maildir (Dovecot, or a
// re-import) therefore never sees a partially written message, and a crash or a full
// disk leaves at most a stray file in tmp/, which maildir readers ignore.
func writeMaildirFile(root *os.Root, name string, content []byte) error {
	tmpDir := filepath.Join(filepath.Dir(filepath.Dir(name)), "tmp")
	if err := root.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create maildir tmp directory: %w", err)
	}
	return replaceFile(root, tmpDir, name, content)
}

// replaceFile stores content as the file name below root, the export directory: it
// writes a new file in tmpDir (a directory of the same filesystem), fsyncs it, renames
// it over name and fsyncs name's directory. The export may be given a directory its
// owner could write to, and it runs with privileges the owner lacks, so it never writes
// into a file already there: the new file is created with O_EXCL under a random name,
// so nothing at that name (a link included) is opened, and the rename replaces the
// entry at name, a symbolic or hard link to a file elsewhere included, instead of
// writing into the file it names. The root resolves every directory on the way, a link
// to one included, only within the export directory, and refuses one that leaves it.
// A reader of name sees the old file or the whole new one, never a partial one.
func replaceFile(root *os.Root, tmpDir, name string, content []byte) error {
	// The '.' keeps the name apart from every folder directory, whose levels have
	// theirs escaped (maildirFolderLevel).
	tmpName := filepath.Join(tmpDir, filepath.Base(name)+"."+rand.Text())
	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		if err = f.Sync(); err != nil {
			err = fmt.Errorf("failed to fsync %s: %w", tmpName, err)
		}
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(tmpName, name)
	}
	if err != nil {
		root.Remove(tmpName)
		return err
	}
	// Make the rename durable: fsync the directory that now holds the entry.
	if dir, err := openExportEntry(root, filepath.Dir(name), true); err == nil {
		_ = dir.Sync()
		dir.Close()
	}
	return nil
}

// openExportEntry opens name below root, the export directory, for reading, and only
// a regular file or, with dir, a directory. The export may be given a directory its
// owner could write to (replaceFile), so whatever it reads back there (a file an
// earlier run left, or a directory it created) may have been replaced by anything, a
// FIFO included, and opening a FIFO for reading blocks until something opens it for
// writing: the export would never finish.
//
// With dir, O_DIRECTORY makes the kernel reject anything that is not a directory with
// ENOTDIR before opening it, so neither a FIFO nor a device node is opened, and real
// directories open in normal blocking mode. Without dir, O_NONBLOCK prevents opening a
// FIFO from waiting for a writer; the open descriptor is checked with Stat so nothing
// can take its place afterwards, and O_NONBLOCK is cleared before returning so the
// regular file is read in blocking mode (as os.Open reads it). The root follows no link
// out of the export directory.
//
// The owner can also make the name a hard link, which the root cannot tell from the
// file's first name, to a file elsewhere on the same file system, one they cannot read
// where the system lets them link it (BSD and macOS do, as Linux does with
// fs.protected_hardlinks = 0). The files the export reads back are created by renaming
// a new file over the name, by the export (replaceFile) as by Dovecot, so they have one
// link: a regular file with more is refused.
func openExportEntry(root *os.Root, name string, dir bool) (*os.File, error) {
	if dir {
		f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) {
				return nil, fmt.Errorf("refusing %s in the export directory: it is not a directory: %w", name, err)
			}
			return nil, err
		}
		return f, nil
	}

	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("refusing %s in the export directory: it is not a regular file", name)
	}
	if links := info.Sys().(*syscall.Stat_t).Nlink; links > 1 {
		f.Close()
		return nil, fmt.Errorf("refusing %s in the export directory: it is a hard link (%d links)", name, links)
	}
	conn, err := f.SyscallConn()
	if err == nil {
		var setErr error
		if err = conn.Control(func(fd uintptr) { setErr = syscall.SetNonblock(int(fd), false) }); err == nil {
			err = setErr
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// maxMaildirKeywords is how many custom keywords a maildir folder can name: the info
// part of a filename has the 26 letters a-z for them (Dovecot's own limit).
const maxMaildirKeywords = 26

// prepareKeywords numbers the custom keywords used in a mailbox and writes the
// folder's dovecot-keywords file ("<index> <keyword>" per line), so the a-z letters
// buildMaildirFlags puts into filenames mean the same thing to Dovecot and to a
// re-import. Keywords are numbered in sorted order, deterministically, so repeated
// exports of the same mailbox produce the same file. An existing file's numbering is
// kept for the keywords it already names, so an incremental export does not renumber
// files written by an earlier run. An existing file that cannot be read (one that is
// not a regular file, or is larger than maxDovecotKeywordsSize) is named in a warning
// and replaced.
func (exporter *Exporter) prepareKeywords(mailboxName string, messages []db.Message) error {
	seen := make(map[string]struct{})
	for i := range messages {
		for _, kw := range messages[i].CustomFlags {
			seen[kw] = struct{}{}
		}
	}

	dir, err := exporter.mailboxDirName(mailboxName)
	if err != nil {
		return err
	}
	keywordsName := filepath.Join(dir, "dovecot-keywords")

	index := make(map[string]int)
	used := make(map[int]bool)
	unreadable := false
	open := func(name string) (*os.File, error) { return openExportEntry(exporter.root, name, false) }
	if existing, err := parseKeywordsFile(keywordsName, open); err == nil {
		for idx, kw := range existing {
			index[kw] = idx
			used[idx] = true
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		unreadable = true
		// A file that is there but is not read (a link, a FIFO, a file with more than
		// one link) is replaced without its numbering, so the letters of files an
		// earlier run wrote may name other keywords now.
		logger.Warn("Existing dovecot-keywords not read; it is replaced and its keyword numbering is not kept",
			"mailbox", mailboxName, "path", filepath.Join(exporter.root.Name(), keywordsName), "error", err)
	}

	names := make([]string, 0, len(seen))
	for kw := range seen {
		if _, known := index[kw]; !known {
			names = append(names, kw)
		}
	}
	sort.Strings(names)
	next := 0
	for _, kw := range names {
		for next < maxMaildirKeywords && used[next] {
			next++
		}
		if next >= maxMaildirKeywords {
			logger.Warn("Mailbox has more custom keywords than maildir can name; the rest are not exported",
				"mailbox", mailboxName, "limit", maxMaildirKeywords, "dropped", kw)
			continue
		}
		index[kw] = next
		used[next] = true
		next++
	}

	exporter.mu.Lock()
	exporter.keywordIndex[mailboxName] = index
	exporter.mu.Unlock()

	// A mailbox without keywords needs no file, but one that cannot be read is
	// replaced all the same (with an empty one), as the warning says.
	if len(index) == 0 && !unreadable {
		return nil
	}
	if err := exporter.root.MkdirAll(dir, 0755); err != nil {
		return err
	}
	byIndex := make([]string, maxMaildirKeywords)
	for kw, idx := range index {
		byIndex[idx] = kw
	}
	var b strings.Builder
	for idx, kw := range byIndex {
		if kw != "" {
			fmt.Fprintf(&b, "%d %s\n", idx, kw)
		}
	}
	return replaceFile(exporter.root, dir, keywordsName, []byte(b.String()))
}

// mergeUIDMappings merges this run's UID → filename mappings with the dovecot-uidlist
// already present in the maildir directory dir below root (if any). Entries from the
// existing file are kept when their file still exists in cur/ or new/ (matched on the
// base filename, ignoring the ":2,flags" info part) and no entry of this run uses the
// same UID or filename. The root reads no file through a link out of the export
// directory, and a dovecot-uidlist, cur/ or new/ of another kind is not read
// (openExportEntry).
func mergeUIDMappings(root *os.Root, dir string, current []UIDFileMapping) []UIDFileMapping {
	existing, err := parseDovecotUIDListFile(openExportEntry(root, filepath.Join(dir, "dovecot-uidlist"), false))
	if err != nil {
		// Dovecot then gives new UIDs to the files of earlier runs that the file listed.
		logger.Warn("Existing dovecot-uidlist not read; it is replaced without the entries of earlier runs",
			"path", filepath.Join(root.Name(), dir, "dovecot-uidlist"), "error", err)
		return current
	}
	if existing == nil || len(existing.UIDMappings) == 0 {
		return current
	}
	usedUID := make(map[uint32]bool, len(current))
	usedFile := make(map[string]bool, len(current))
	for _, m := range current {
		usedUID[m.UID] = true
		usedFile[m.Filename] = true
	}
	present := make(map[string]bool)
	for _, sub := range []string{"cur", "new"} {
		d, err := openExportEntry(root, filepath.Join(dir, sub), true)
		if err != nil {
			continue
		}
		entries, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if i := strings.LastIndex(name, ":"); i > 0 {
				name = name[:i]
			}
			present[name] = true
		}
	}
	merged := make([]UIDFileMapping, 0, len(current)+len(existing.UIDMappings))
	for filename, uid := range existing.UIDMappings {
		if usedUID[uid] || usedFile[filename] || !present[filename] {
			continue
		}
		merged = append(merged, UIDFileMapping{UID: uid, Filename: filename})
	}
	merged = append(merged, current...)
	sort.Slice(merged, func(a, b int) bool { return merged[a].UID < merged[b].UID })
	return merged
}
