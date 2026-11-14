//go:build integration

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// rerunMaildir writes a maildir with n messages, "Message 0" .. "Message n-1".
func rerunMaildir(t *testing.T, n int) string {
	t.Helper()
	maildir := filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for k := 0; k < n; k++ {
		content := fmt.Sprintf("Message-ID: <rerun-%d@example.com>\r\nSubject: Message %d\r\n\r\nBody %d\r\n", k, k, k)
		name := fmt.Sprintf("17000000%02d.M%dP1.host:2,S", k, k)
		if err := os.WriteFile(filepath.Join(maildir, "cur", name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return maildir
}

// runImport runs one import and returns the finished importer for its counters.
func runImport(t *testing.T, rdb *resilient.ResilientDatabase, maildir, email string, opts ImporterOptions) *Importer {
	t.Helper()
	importer, err := NewImporter(context.Background(), maildir, email, 1, rdb, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}
	return importer
}

func rerunAccount(t *testing.T, rdb *resilient.ResilientDatabase, email string) int64 {
	t.Helper()
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	return accountID
}

// liveSubjects returns the subjects of the account's messages that are not expunged.
func liveSubjects(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) []string {
	t.Helper()
	rows, err := rdb.GetOperationalDatabase().ReadPool.Query(context.Background(),
		`SELECT subject FROM messages WHERE account_id = $1 AND expunged_at IS NULL ORDER BY subject`, accountID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var subjects []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, s)
	}
	return subjects
}

// TestImporter_DuplicateSkipsAreMarkedImported: a message the database skips as
// already in the mailbox is done, like an inserted one. If its cache row is left
// unmarked, every --incremental run reads, uploads and skips it again. Here the
// cache is lost after a first import (--cleanup-db, or removed by hand), so the
// second run finds every message already there.
func TestImporter_DuplicateSkipsAreMarkedImported(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	for _, txMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch_transaction=%v", txMode), func(t *testing.T) {
			email := fmt.Sprintf("rerun-dup-%v@example.com", txMode)
			rerunAccount(t, rdb, email)
			maildir := rerunMaildir(t, 3)
			opts := ImporterOptions{Incremental: true, PreserveFlags: true, TestMode: true, BatchSize: 10, BatchTransactionMode: txMode}

			if first := runImport(t, rdb, maildir, email, opts); first.importedMessages != 3 {
				t.Fatalf("first import: imported %d, want 3", first.importedMessages)
			}
			for _, suffix := range []string{"", "-wal", "-shm"} {
				os.Remove(filepath.Join(maildir, "sora-maildir.db"+suffix))
			}

			second := runImport(t, rdb, maildir, email, opts)
			if second.importedMessages != 0 || second.skippedMessages != 3 {
				t.Fatalf("second import: imported %d, skipped %d; want 0 and 3", second.importedMessages, second.skippedMessages)
			}

			third := runImport(t, rdb, maildir, email, opts)
			if third.totalMessages != 0 || third.skippedMessages != 0 {
				t.Errorf("third import processed %d messages (skipped %d) again; want nothing left to import",
					third.totalMessages, third.skippedMessages)
			}
		})
	}
}

// TestImporter_IncrementalRunKeepsMessagesDeletedInSora: a message the user deleted in
// Sora after it was imported must not be imported again by the next --incremental run,
// whether it is still expunged or the cleaner has already removed it. The cache must
// still serve a maildir imported into another account.
func TestImporter_IncrementalRunKeepsMessagesDeletedInSora(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()
	opts := ImporterOptions{Incremental: true, PreserveFlags: true, TestMode: true, BatchSize: 10}

	for _, tc := range []struct {
		name   string
		delete string
	}{
		{"expunged", `UPDATE messages SET expunged_at = now() WHERE account_id = $1 AND subject = $2`},
		{"purged", `DELETE FROM messages WHERE account_id = $1 AND subject = $2`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := "rerun-" + tc.name + "@example.com"
			accountID := rerunAccount(t, rdb, email)
			maildir := rerunMaildir(t, 3)

			runImport(t, rdb, maildir, email, opts)
			if _, err := rdb.GetOperationalDatabase().WritePool.Exec(ctx, tc.delete, accountID, "Message 1"); err != nil {
				t.Fatal(err)
			}

			runImport(t, rdb, maildir, email, opts)
			if got := liveSubjects(t, rdb, accountID); slices.Contains(got, "Message 1") || len(got) != 2 {
				t.Errorf("after the second incremental run the account has %q; want Message 0 and Message 2 only", got)
			}
		})
	}

	// A cache written before the stamp existed has every row unstamped. The first run
	// after the upgrade checks them and stamps the ones it finds in the account, so from
	// then on a deletion in Sora is respected.
	t.Run("cache from before the stamp", func(t *testing.T) {
		const email = "rerun-legacy@example.com"
		accountID := rerunAccount(t, rdb, email)
		maildir := rerunMaildir(t, 3)

		runImport(t, rdb, maildir, email, opts)
		cache, err := sql.Open("sqlite", filepath.Join(maildir, "sora-maildir.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = cache.Exec(`UPDATE messages SET account_id = NULL`)
		cache.Close()
		if err != nil {
			t.Fatal(err)
		}

		runImport(t, rdb, maildir, email, opts) // the first run after the upgrade
		if _, err := rdb.GetOperationalDatabase().WritePool.Exec(ctx,
			`UPDATE messages SET expunged_at = now() WHERE account_id = $1 AND subject = $2`, accountID, "Message 1"); err != nil {
			t.Fatal(err)
		}

		runImport(t, rdb, maildir, email, opts)
		if got := liveSubjects(t, rdb, accountID); slices.Contains(got, "Message 1") || len(got) != 2 {
			t.Errorf("after the run following the upgrade the account has %q; want Message 0 and Message 2 only", got)
		}
	})

	t.Run("another account", func(t *testing.T) {
		first := rerunAccount(t, rdb, "rerun-first@example.com")
		second := rerunAccount(t, rdb, "rerun-second@example.com")
		maildir := rerunMaildir(t, 3)

		runImport(t, rdb, maildir, "rerun-first@example.com", opts)
		runImport(t, rdb, maildir, "rerun-second@example.com", opts)
		for _, accountID := range []int64{first, second} {
			if got := liveSubjects(t, rdb, accountID); len(got) != 3 {
				t.Errorf("account %d has %q; want all 3 messages", accountID, got)
			}
		}
	})
}

// TestImporter_Delay: --delay paces the import, each message waiting that long.
func TestImporter_Delay(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()

	const email = "rerun-delay@example.com"
	rerunAccount(t, rdb, email)
	maildir := rerunMaildir(t, 3)

	const delay = 400 * time.Millisecond
	start := time.Now()
	runImport(t, rdb, maildir, email, ImporterOptions{PreserveFlags: true, TestMode: true, BatchSize: 10, ImportDelay: delay})
	if elapsed := time.Since(start); elapsed < 3*delay {
		t.Errorf("import of 3 messages with a %s delay took %s; want at least %s", delay, elapsed, 3*delay)
	}
}
