//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
)

// Before it switched to helpers.HashContent (BLAKE3), sora-admin import named every body
// by its SHA-256, in the SQLite cache and in messages.content_hash. Re-running an import
// over a maildir such a version imported, with its sora-maildir.db, must not import every
// message a second time: the default (non-incremental) run reads every cached file, and
// the batch insert recognises an existing row only by its message_id and content_hash.
// A cached file that the earlier run never imported is not in PostgreSQL and takes the
// BLAKE3 hash like any new file.
func TestImporter_RerunOverPreBLAKE3Import(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupSimpleTestDatabase(t)
	defer rdb.Close()

	testEmail := "legacy-hash@example.com"
	createSimpleTestAccount(t, rdb, testEmail, "testpassword123")
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	pg := rdb.GetOperationalDatabase()

	maildirPath := filepath.Join(t.TempDir(), "testmaildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	message := func(n int) []byte {
		return []byte(fmt.Sprintf("Message-ID: <legacy-%d@example.com>\r\nSubject: m%d\r\n\r\nbody %d\r\n", n, n, n))
	}
	sha := func(b []byte) string {
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	for n := 1; n <= 3; n++ {
		if err := os.WriteFile(filepath.Join(maildirPath, "cur", fmt.Sprintf("m%d:2,S", n)), message(n), 0644); err != nil {
			t.Fatal(err)
		}
	}

	options := ImporterOptions{PreserveFlags: true, BatchSize: 10, TestMode: true}
	runImport := func() *Importer {
		t.Helper()
		imp, err := NewImporter(context.Background(), maildirPath, testEmail, 1, rdb, nil, options)
		if err != nil {
			t.Fatalf("NewImporter: %v", err)
		}
		defer imp.Close()
		if err := imp.Run(); err != nil {
			t.Fatalf("Run: %v", err)
		}
		return imp
	}
	if imp := runImport(); imp.importedMessages != 3 {
		t.Fatalf("first import: imported %d, want 3", imp.importedMessages)
	}

	// Turn the state into what a pre-BLAKE3 sora-admin leaves: SHA-256 in the cache and
	// in PostgreSQL. Then add a fourth file that such a run scanned but never imported.
	cache, err := sql.Open("sqlite", filepath.Join(maildirPath, "sora-maildir.db"))
	if err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		b := message(n)
		if _, err := cache.Exec("UPDATE messages SET hash = ? WHERE hash = ?", sha(b), helpers.HashContent(b)); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.WritePool.Exec(context.Background(),
			"UPDATE messages SET content_hash = $1 WHERE account_id = $2 AND content_hash = $3",
			sha(b), accountID, helpers.HashContent(b)); err != nil {
			t.Fatal(err)
		}
	}
	fourth := filepath.Join(maildirPath, "cur", "m4:2,S")
	if err := os.WriteFile(fourth, message(4), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Exec("INSERT INTO messages (path, filename, hash, size, mailbox, s3_uploaded) VALUES (?, ?, ?, ?, 'INBOX', 0)",
		fourth, filepath.Base(fourth), sha(message(4)), len(message(4))); err != nil {
		t.Fatal(err)
	}
	cache.Close()

	imp := runImport()
	if imp.importedMessages != 1 {
		t.Errorf("re-run imported %d messages, want 1 (only the never-imported fourth)", imp.importedMessages)
	}

	hashes := map[string]int{}
	rows, err := pg.ReadPool.Query(context.Background(),
		"SELECT content_hash FROM messages WHERE account_id = $1 AND expunged_at IS NULL", accountID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		hashes[h]++
	}
	rows.Close()
	if len(hashes) != 4 {
		t.Errorf("account has %d distinct hashes, want 4: %v", len(hashes), hashes)
	}
	for n := 1; n <= 3; n++ {
		if c := hashes[sha(message(n))]; c != 1 {
			t.Errorf("message %d: %d rows under its pre-BLAKE3 hash, want 1 (rows: %v)", n, c, hashes)
		}
	}
	if c := hashes[helpers.HashContent(message(4))]; c != 1 {
		t.Errorf("never-imported message: %d rows under its BLAKE3 hash, want 1 (rows: %v)", c, hashes)
	}
}
