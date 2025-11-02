package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Ensure mockResilientDatabase implements the resilientDB interface.
var _ resilientDB = (*mockResilientDatabase)(nil)

// mockResilientDatabase provides a mock implementation of the database interactions
// needed for testing the Importer.
type mockResilientDatabase struct {
	mu                    sync.Mutex
	mailboxes             map[string]*db.DBMailbox
	getMailboxByNameCalls int
	createMailboxCalls    int
	getOrCreateCalls      int

	// For simulating failures
	insertMessageShouldFail bool
	insertMessageError      error
}

func newMockResilientDatabase() *mockResilientDatabase {
	return &mockResilientDatabase{
		mailboxes: make(map[string]*db.DBMailbox),
	}
}

func (m *mockResilientDatabase) GetMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getMailboxByNameCalls++
	if mailbox, ok := m.mailboxes[name]; ok {
		return mailbox, nil
	}
	return nil, consts.ErrMailboxNotFound
}

func (m *mockResilientDatabase) CreateMailboxWithRetry(ctx context.Context, accountID int64, name string, parentID *int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.createMailboxCalls++
	if _, ok := m.mailboxes[name]; ok {
		return errors.New("mailbox already exists")
	}
	m.mailboxes[name] = &db.DBMailbox{ID: int64(len(m.mailboxes) + 1), AccountID: accountID, Name: name}
	return nil
}

// GetOrCreateMailboxByNameWithRetry is the new efficient mock method.
func (m *mockResilientDatabase) GetOrCreateMailboxByNameWithRetry(ctx context.Context, accountID int64, name string) (*db.DBMailbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getOrCreateCalls++

	// Try to get it first
	m.getMailboxByNameCalls++
	if mailbox, ok := m.mailboxes[name]; ok {
		return mailbox, nil
	}

	// Not found, so create it
	m.createMailboxCalls++
	newMailbox := &db.DBMailbox{ID: int64(len(m.mailboxes) + 1), AccountID: accountID, Name: name}
	m.mailboxes[name] = newMailbox
	return newMailbox, nil
}

// --- Unused methods for this test, but required by the interface ---

func (m *mockResilientDatabase) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	return 1, nil
}
func (m *mockResilientDatabase) CreateDefaultMailboxesWithRetry(ctx context.Context, accountID int64) error {
	return nil
}
func (m *mockResilientDatabase) SetMailboxSubscribedWithRetry(ctx context.Context, mailboxID, accountID int64, subscribed bool) error {
	return nil
}
func (m *mockResilientDatabase) GetActiveScriptWithRetry(ctx context.Context, accountID int64) (*db.SieveScript, error) {
	return nil, nil
}
func (m *mockResilientDatabase) GetScriptByNameWithRetry(ctx context.Context, name string, accountID int64) (*db.SieveScript, error) {
	return nil, nil
}
func (m *mockResilientDatabase) UpdateScriptWithRetry(ctx context.Context, scriptID, accountID int64, name, content string) (*db.SieveScript, error) {
	return nil, nil
}
func (m *mockResilientDatabase) CreateScriptWithRetry(ctx context.Context, accountID int64, name, content string) (*db.SieveScript, error) {
	return nil, nil
}
func (m *mockResilientDatabase) SetScriptActiveWithRetry(ctx context.Context, scriptID, accountID int64, active bool) error {
	return nil
}
func (m *mockResilientDatabase) QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row {
	// To satisfy the interface, we can return a mock row that does nothing.
	return &mockRow{}
}
func (m *mockResilientDatabase) InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error) {
	if m.insertMessageShouldFail {
		return 0, 0, m.insertMessageError
	}
	return 1, 1, nil
}
func (m *mockResilientDatabase) DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, accountID, mailboxID int64, hash string) (int64, error) {
	return 0, nil
}
func (m *mockResilientDatabase) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	// Return a mock transaction that does nothing
	return &mockTx{}, nil
}
func (m *mockResilientDatabase) GetOperationalDatabase() *db.Database {
	// For tests, we don't need the actual database
	return nil
}

func (m *mockResilientDatabase) resetCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getMailboxByNameCalls, m.createMailboxCalls, m.getOrCreateCalls = 0, 0, 0
}

func TestGetOrCreateMailbox(t *testing.T) {
	ctx := context.Background()
	const testAccountID int64 = 1

	t.Run("cache hit", func(t *testing.T) {
		mockRDB := newMockResilientDatabase()
		importer := &Importer{
			rdb:          mockRDB,
			mailboxCache: make(map[string]*db.DBMailbox),
		}

		// Pre-populate cache
		expectedMailbox := &db.DBMailbox{ID: 1, AccountID: testAccountID, Name: "INBOX"}
		importer.mailboxCache["INBOX"] = expectedMailbox

		mailbox, err := importer.getOrCreateMailbox(ctx, testAccountID, "INBOX")
		require.NoError(t, err)

		// Assertions
		assert.Equal(t, expectedMailbox, mailbox)
		assert.Equal(t, 0, mockRDB.getMailboxByNameCalls, "DB should not be called on cache hit")
		assert.Equal(t, 0, mockRDB.createMailboxCalls, "DB should not be called on cache hit")
	})

	t.Run("cache miss, db hit", func(t *testing.T) {
		mockRDB := newMockResilientDatabase()
		importer := &Importer{
			rdb:          mockRDB,
			mailboxCache: make(map[string]*db.DBMailbox),
		}

		// Pre-populate database
		expectedMailbox := &db.DBMailbox{ID: 1, AccountID: testAccountID, Name: "Sent"}
		mockRDB.mailboxes["Sent"] = expectedMailbox

		// First call (cache miss)
		mailbox, err := importer.getOrCreateMailbox(ctx, testAccountID, "Sent")
		require.NoError(t, err)

		// Assertions for first call
		assert.Equal(t, expectedMailbox, mailbox)
		assert.Equal(t, 1, mockRDB.getMailboxByNameCalls, "GetMailboxByName should be called once on cache miss")
		assert.Equal(t, 0, mockRDB.createMailboxCalls, "CreateMailbox should not be called if found in DB")
		assert.Contains(t, importer.mailboxCache, "Sent", "Mailbox should be added to cache")

		// Reset counters and make a second call (should be cache hit)
		mockRDB.resetCounters()
		mailbox, err = importer.getOrCreateMailbox(ctx, testAccountID, "Sent")
		require.NoError(t, err)

		// Assertions for second call
		assert.Equal(t, expectedMailbox, mailbox)
		assert.Equal(t, 0, mockRDB.getMailboxByNameCalls, "DB should not be called on subsequent cache hit")
		assert.Equal(t, 0, mockRDB.createMailboxCalls, "DB should not be called on subsequent cache hit")
	})

	t.Run("cache miss, db miss (creation)", func(t *testing.T) {
		mockRDB := newMockResilientDatabase()
		importer := &Importer{
			rdb:          mockRDB,
			mailboxCache: make(map[string]*db.DBMailbox),
		}

		// First call (cache and db miss)
		mailbox, err := importer.getOrCreateMailbox(ctx, testAccountID, "Archive")
		require.NoError(t, err)

		// Assertions for first call
		require.NotNil(t, mailbox)
		assert.Equal(t, "Archive", mailbox.Name)
		assert.Equal(t, 1, mockRDB.getMailboxByNameCalls, "GetMailboxByName should be called once")
		assert.Equal(t, 1, mockRDB.createMailboxCalls, "CreateMailbox should be called once on db miss")
		assert.Equal(t, 1, mockRDB.getOrCreateCalls, "GetOrCreate should be called once")
		assert.Contains(t, importer.mailboxCache, "Archive", "Mailbox should be added to cache after creation")

		// Reset counters and make a second call (should be cache hit)
		mockRDB.resetCounters()
		cachedMailbox, err := importer.getOrCreateMailbox(ctx, testAccountID, "Archive")
		require.NoError(t, err)

		// Assertions for second call
		assert.Equal(t, mailbox, cachedMailbox)
		assert.Equal(t, 0, mockRDB.getMailboxByNameCalls, "DB should not be called on subsequent cache hit")
		assert.Equal(t, 0, mockRDB.createMailboxCalls, "DB should not be called on subsequent cache hit")
	})

	t.Run("concurrent creation", func(t *testing.T) {
		mockRDB := newMockResilientDatabase()
		importer := &Importer{
			rdb:          mockRDB,
			mailboxCache: make(map[string]*db.DBMailbox),
		}

		var wg sync.WaitGroup
		numGoroutines := 20
		mailboxName := "Junk"

		// This function will be run by all goroutines
		worker := func() {
			defer wg.Done()
			mailbox, err := importer.getOrCreateMailbox(ctx, testAccountID, mailboxName)
			require.NoError(t, err)
			require.NotNil(t, mailbox)
			assert.Equal(t, mailboxName, mailbox.Name)
		}

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go worker()
		}
		wg.Wait()

		// Assertions
		// The new GetOrCreate method should only be called once due to the lock.
		assert.Equal(t, 1, mockRDB.getOrCreateCalls, "GetOrCreate should only be called once under concurrency")
		assert.Equal(t, 1, mockRDB.createMailboxCalls, "CreateMailbox should only be called once under concurrency")

		// Verify cache is populated
		cachedMailbox, ok := importer.mailboxCache[mailboxName]
		assert.True(t, ok, "Mailbox should be in cache after concurrent creation")
		assert.Equal(t, mailboxName, cachedMailbox.Name)

		// Verify subsequent calls are all cache hits
		mockRDB.resetCounters()
		_, err := importer.getOrCreateMailbox(ctx, testAccountID, mailboxName)
		require.NoError(t, err)
		assert.Equal(t, 0, mockRDB.getMailboxByNameCalls, "Subsequent calls should not hit the DB")
		assert.Equal(t, 0, mockRDB.createMailboxCalls, "Subsequent calls should not hit the DB")
	})
}

func TestProcessBatch_DBInsertFailure(t *testing.T) {
	// Note: Only testing safe mode with mocks, as fast mode uses real db.InsertMessageFromImporter
	// which requires full database setup. Fast mode is tested in integration tests.
	t.Run("safe mode (individual transactions)", func(t *testing.T) {
		ctx := context.Background()

		// --- Setup ---
		// 1. Create a temporary directory and a dummy message file
		tempDir := t.TempDir()
		msgPath := filepath.Join(tempDir, "test_message.eml")
		msgContent := []byte("From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nHello, world!")
		err := os.WriteFile(msgPath, msgContent, 0644)
		require.NoError(t, err)

		// 2. Create an in-memory SQLite DB for the importer
		sqliteDB, err := sql.Open("sqlite", ":memory:")
		require.NoError(t, err)
		defer sqliteDB.Close()

		// Create the schema
		_, err = sqliteDB.Exec(`
			CREATE TABLE messages (
				id INTEGER PRIMARY KEY, path TEXT, filename TEXT, hash TEXT, size INTEGER,
				mailbox TEXT, s3_uploaded INTEGER DEFAULT 0, s3_uploaded_at TIMESTAMP
			);
		`)
		require.NoError(t, err)

		// 3. Configure the mock database to fail on insert
		mockRDB := newMockResilientDatabase()
		mockRDB.insertMessageShouldFail = true
		mockRDB.insertMessageError = errors.New("simulated db connection error")

		// 4. Create the Importer instance
		importer := &Importer{
			ctx:      ctx,
			email:    "test@example.com",
			rdb:      mockRDB,
			sqliteDB: sqliteDB,
			options: ImporterOptions{
				TestMode:             true,  // Skip S3 uploads
				BatchTransactionMode: false, // Safe mode only for unit test
			},
			jobs:         1,
			mailboxCache: make(map[string]*db.DBMailbox),
		}

		// 5. Create a batch with one message
		msgHash := HashContent(msgContent)
		batch := []msgInfo{
			{
				path:     msgPath,
				filename: "test_message.eml",
				hash:     msgHash,
				size:     int64(len(msgContent)),
				mailbox:  "INBOX",
			},
		}

		// Insert the message into the SQLite DB as "not uploaded"
		_, err = sqliteDB.Exec(
			"INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, ?, ?, 0)",
			msgPath, "test_message.eml", msgHash, len(msgContent), "INBOX",
		)
		require.NoError(t, err)

		// --- Act ---
		processErr := importer.processBatch(batch)

		// --- Assert ---
		// 1. The function should return an error.
		require.Error(t, processErr, "processBatch should return an error on DB insert failure")
		assert.Contains(t, processErr.Error(), "simulated db connection error")

		// 2. The failed messages counter should be incremented.
		// The batch had 1 message, which was "uploaded" but failed to insert.
		assert.Equal(t, int64(1), importer.failedMessages, "failedMessages counter should be incremented")

		// 3. The imported messages counter should NOT be incremented.
		assert.Equal(t, int64(0), importer.importedMessages, "importedMessages counter should be zero")

		// 4. The message should NOT be marked as uploaded in the SQLite database.
		var s3Uploaded int
		err = sqliteDB.QueryRow("SELECT s3_uploaded FROM messages WHERE hash = ?", msgHash).Scan(&s3Uploaded)
		require.NoError(t, err, "should be able to query the message from SQLite")
		assert.Equal(t, 0, s3Uploaded, "s3_uploaded flag should remain 0 after a failed DB insert")
	})
}

// mockRow is a dummy implementation of pgx.Row to satisfy the interface.
type mockRow struct {
	mock.Mock
}

func (m *mockRow) Scan(dest ...any) error {
	// For tests that need this, we can set up expectations.
	// For now, returning an error is a safe default.
	return pgx.ErrNoRows
}

// mockTx is a dummy implementation of pgx.Tx to satisfy the interface.
type mockTx struct {
	mock.Mock
}

func (m *mockTx) Begin(ctx context.Context) (pgx.Tx, error) {
	return nil, errors.New("nested transactions not supported in mock")
}
func (m *mockTx) Commit(ctx context.Context) error {
	return nil
}
func (m *mockTx) Rollback(ctx context.Context) error {
	return nil
}
func (m *mockTx) CopyFrom(ctx context.Context, tableName pgx.Identifier, columnNames []string, rowSrc pgx.CopyFromSource) (int64, error) {
	return 0, errors.New("not implemented")
}
func (m *mockTx) SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults {
	return nil
}
func (m *mockTx) LargeObjects() pgx.LargeObjects {
	return pgx.LargeObjects{}
}
func (m *mockTx) Prepare(ctx context.Context, name, sql string) (*pgconn.StatementDescription, error) {
	return nil, errors.New("not implemented")
}
func (m *mockTx) Exec(ctx context.Context, sql string, arguments ...any) (commandTag pgconn.CommandTag, err error) {
	return pgconn.CommandTag{}, nil
}
func (m *mockTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}
func (m *mockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &mockRow{}
}
func (m *mockTx) Conn() *pgx.Conn {
	return nil
}

func TestParseMessageMetadata(t *testing.T) {
	// Dummy importer needed for the method receiver
	importer := &Importer{}

	t.Run("with valid date header", func(t *testing.T) {
		dateStr := "Tue, 15 Nov 1994 08:12:31 -0500"
		content := []byte("Date: " + dateStr + "\r\nSubject: Test\r\n\r\nBody")
		expectedDate, _ := time.Parse(time.RFC1123Z, dateStr)

		metadata, err := importer.parseMessageMetadata(content, "test.eml", "/dummy/path")
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.True(t, expectedDate.Equal(metadata.sentDate), "Date should be parsed from the header")
	})

	t.Run("with missing date header, fallback to file mod time", func(t *testing.T) {
		content := []byte("Subject: Test\r\n\r\nBody")

		// Create a temp file and set its modification time
		tempFile, err := os.CreateTemp(t.TempDir(), "test-*.eml")
		require.NoError(t, err)
		defer tempFile.Close()
		_, err = tempFile.Write(content)
		require.NoError(t, err)

		// Set a specific modification time
		expectedDate := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
		err = os.Chtimes(tempFile.Name(), expectedDate, expectedDate)
		require.NoError(t, err)

		metadata, err := importer.parseMessageMetadata(content, "test.eml", tempFile.Name())
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.True(t, expectedDate.Equal(metadata.sentDate), "Date should fall back to file modification time")
	})

	t.Run("with invalid date header, fallback to file mod time", func(t *testing.T) {
		content := []byte("Date: not-a-valid-date\r\nSubject: Test\r\n\r\nBody")

		tempFile, err := os.CreateTemp(t.TempDir(), "test-*.eml")
		require.NoError(t, err)
		defer tempFile.Close()
		_, err = tempFile.Write(content)
		require.NoError(t, err)

		expectedDate := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
		err = os.Chtimes(tempFile.Name(), expectedDate, expectedDate)
		require.NoError(t, err)

		metadata, err := importer.parseMessageMetadata(content, "test.eml", tempFile.Name())
		require.NoError(t, err)
		require.NotNil(t, metadata)

		assert.True(t, expectedDate.Equal(metadata.sentDate), "Date should fall back to file modification time on invalid header")
	})

	t.Run("with missing date and file stat error, fallback to time.Now", func(t *testing.T) {
		content := []byte("Subject: Test\r\n\r\nBody")
		before := time.Now()
		metadata, err := importer.parseMessageMetadata(content, "test.eml", "/non/existent/path/file.eml")
		after := time.Now()
		require.NoError(t, err)
		require.NotNil(t, metadata)

		// Check that the date is within the time window of the function call
		assert.True(t, !metadata.sentDate.Before(before) && !metadata.sentDate.After(after), "Date should fall back to time.Now()")
	})
}
