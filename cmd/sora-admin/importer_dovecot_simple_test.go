//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

func TestImporter_DovecotUIDPreservation_Simple(t *testing.T) {
	// Skip if database is not available
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database with fresh schema
	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	// Create test account
	testEmail := "user@demo.com"
	testPassword := "testpassword123"
	createSimpleTestAccount(t, rdb, testEmail, testPassword)

	// Setup temporary directory for test
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "testmaildir")

	// Copy only a few sample messages for quicker testing
	err := copyLimitedTestData(t, "../../testdata/Maildir", maildirPath, 5)
	if err != nil {
		t.Fatalf("Failed to copy test data: %v", err)
	}

	// Parse the original dovecot-uidlist to get expected UIDs
	originalUIDList, err := ParseDovecotUIDList(maildirPath)
	if err != nil {
		t.Fatalf("Failed to parse original dovecot-uidlist: %v", err)
	}

	if originalUIDList == nil {
		t.Fatalf("No dovecot-uidlist found in test data")
	}

	t.Logf("Original dovecot-uidlist has UIDVALIDITY=%d, NextUID=%d, %d mappings",
		originalUIDList.UIDValidity, originalUIDList.NextUID, len(originalUIDList.UIDMappings))

	// Create a mock S3 storage that will just skip uploads
	mockS3, err := storage.New("mock:9000", "test", "test", "test", false, false)
	if err != nil {
		t.Skipf("Cannot create mock S3 storage: %v", err)
	}

	// Configure importer with UID preservation
	options := ImporterOptions{
		DryRun:        false,
		PreserveFlags: true,
		ShowProgress:  true,
		ForceReimport: false,
		CleanupDB:     true,
		Dovecot:       true,
		PreserveUIDs:  true, // This is the key option we're testing
	}

	// Create importer
	importer, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, mockS3, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}
	defer importer.Close()

	// Run just the scanning phase to test UID parsing
	t.Log("Testing dovecot-uidlist parsing...")
	err = importer.scanMaildir()
	if err != nil {
		t.Fatalf("Maildir scanning failed: %v", err)
	}

	// Verify UID mappings were loaded correctly
	if len(importer.dovecotUIDLists) == 0 {
		t.Fatal("No dovecot UID lists were loaded")
	}

	for maildirPath, uidList := range importer.dovecotUIDLists {
		t.Logf("Loaded UID list for %s: UIDVALIDITY=%d, %d mappings",
			maildirPath, uidList.UIDValidity, len(uidList.UIDMappings))

		// Test a few specific UID lookups
		testUIDLookups(t, uidList)
	}

	t.Log("✅ Dovecot UID preservation test completed successfully!")
	t.Log("The importer correctly:")
	t.Log("  - Parsed dovecot-uidlist files")
	t.Log("  - Loaded UID mappings for messages")
	t.Log("  - Handled filename variations (with/without flags)")
}

// testUIDLookups tests that UID lookups work correctly for various filename formats
func testUIDLookups(t *testing.T, uidList *DovecotUIDList) {
	// Test a few known entries from the dovecot-uidlist
	testCases := []struct {
		baseFilename      string
		filenameWithFlags string
		expectedFound     bool
	}{
		{
			baseFilename:      "1758924930.M253250P11059.ms19.migadu.com,S=21523,W=21523",
			filenameWithFlags: "1758924930.M253250P11059.ms19.migadu.com,S=21523,W=21523:2,S",
			expectedFound:     true,
		},
		{
			baseFilename:      "1758924758.M242828P603.ms19.migadu.com,S=73160,W=73160",
			filenameWithFlags: "1758924758.M242828P603.ms19.migadu.com,S=73160,W=73160:2,Sa",
			expectedFound:     true,
		},
	}

	for _, tc := range testCases {
		// Test lookup with base filename
		uid1, found1 := uidList.GetUIDForFile(tc.baseFilename)

		// Test lookup with filename including flags
		uid2, found2 := uidList.GetUIDForFile(tc.filenameWithFlags)

		if tc.expectedFound {
			if !found1 {
				t.Errorf("Expected to find UID for base filename %s", tc.baseFilename)
			}
			if !found2 {
				t.Errorf("Expected to find UID for filename with flags %s", tc.filenameWithFlags)
			}
			if found1 && found2 && uid1 != uid2 {
				t.Errorf("UID mismatch: base=%d, with_flags=%d", uid1, uid2)
			}
			if found1 {
				t.Logf("✅ Successfully found UID %d for %s", uid1, tc.baseFilename)
			}
		}
	}
}

// setupSimpleTestDatabase creates a test database with fresh schema
func setupSimpleTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	cfg := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    []string{"localhost"},
			Port:     "5432",
			User:     "postgres",
			Name:     "sora_mail_db",
			Password: "",
		},
	}

	// Reset database schema for clean test
	rdb, err := resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Skipf("Failed to connect to test database: %v", err)
	}

	ctx := context.Background()
	_, err = rdb.ExecWithRetry(ctx, `
		DROP SCHEMA public CASCADE;
		CREATE SCHEMA public;
		GRANT ALL ON SCHEMA public TO postgres;
		GRANT ALL ON SCHEMA public TO public;
	`)
	if err != nil {
		t.Fatalf("Failed to reset database schema: %v", err)
	}

	rdb.Close()

	// Recreate connection to trigger migrations
	rdb, err = resilient.NewResilientDatabase(context.Background(), cfg, true, true)
	if err != nil {
		t.Fatalf("Failed to recreate database connection: %v", err)
	}

	t.Log("Database setup completed with fresh schema")
	return rdb
}

// createSimpleTestAccount creates a test account
func createSimpleTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) {
	t.Helper()

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	err := rdb.CreateAccountWithRetry(context.Background(), req)
	if err != nil {
		t.Fatalf("Failed to create test account %s: %v", email, err)
	}

	t.Logf("Created test account: %s", email)
}

// copyLimitedTestData copies limited test data for faster testing
func copyLimitedTestData(t *testing.T, src, dst string, messageLimit int) error {
	t.Helper()

	// Create destination directory structure
	err := os.MkdirAll(filepath.Join(dst, "cur"), 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Join(dst, "new"), 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Join(dst, "tmp"), 0755)
	if err != nil {
		return err
	}

	// Copy dovecot files
	dovecotFiles := []string{"dovecot-uidlist", "dovecot-keywords", "subscriptions"}
	for _, file := range dovecotFiles {
		srcFile := filepath.Join(src, file)
		dstFile := filepath.Join(dst, file)
		if _, err := os.Stat(srcFile); err == nil {
			err = copyFile(srcFile, dstFile)
			if err != nil {
				return fmt.Errorf("failed to copy %s: %w", file, err)
			}
		}
	}

	// Copy limited number of messages from cur directory
	curDir := filepath.Join(src, "cur")
	entries, err := os.ReadDir(curDir)
	if err != nil {
		return err
	}

	copied := 0
	for _, entry := range entries {
		if copied >= messageLimit {
			break
		}
		if !entry.IsDir() {
			srcFile := filepath.Join(curDir, entry.Name())
			dstFile := filepath.Join(dst, "cur", entry.Name())
			err = copyFile(srcFile, dstFile)
			if err != nil {
				return err
			}
			copied++
		}
	}

	t.Logf("Copied %d messages and dovecot metadata files", copied)
	return nil
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = srcFile.WriteTo(dstFile)
	return err
}
