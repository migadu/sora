//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestImporter_DryRunChangesNothing runs `import maildir --dry-run` against an
// account, plain, with --preserve-uids, and with --dovecot (which implies
// --preserve-uids), and checks that the account's mailboxes and subscriptions are
// exactly what they were: the dry run is documented as a preview "without making
// changes".
func TestImporter_DryRunChangesNothing(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		opts ImporterOptions
	}{
		{"plain", ImporterOptions{}},
		{"preserve-uids", ImporterOptions{PreserveUIDs: true}},
		{"dovecot", ImporterOptions{Dovecot: true, PreserveUIDs: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email := "dryrun-" + tc.name + "@example.com"
			createSimpleTestAccount(t, rdb, email, "testpassword123")
			address, err := server.NewAddress(email)
			if err != nil {
				t.Fatal(err)
			}
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
			if err != nil {
				t.Fatal(err)
			}

			// An existing empty mailbox whose UIDVALIDITY differs from the maildir's.
			if err := rdb.CreateMailboxWithRetry(ctx, accountID, "Archive", nil); err != nil {
				t.Fatal(err)
			}

			maildir := filepath.Join(t.TempDir(), "Maildir")
			createMaildirFolder(t, maildir)
			inbox := []testMessage{{uid: 1, filename: "1700000001.M1P1.host", flags: "S", subject: "inbox",
				from: "a@example.com", to: email, date: time.Now()}}
			createMessagesInMaildir(t, maildir, inbox)
			createDovecotUIDList(t, maildir, 1111, 2, inbox)
			for _, f := range []struct {
				dir         string
				uidValidity uint32
			}{{".Work", 2222}, {".Archive", 3333}} {
				path := filepath.Join(maildir, f.dir)
				createMaildirFolder(t, path)
				msgs := []testMessage{{uid: 7, filename: "1700000002.M2P2.host", flags: "S", subject: f.dir,
					from: "a@example.com", to: email, date: time.Now()}}
				createMessagesInMaildir(t, path, msgs)
				createDovecotUIDList(t, path, f.uidValidity, 8, msgs)
			}
			if err := os.WriteFile(filepath.Join(maildir, "subscriptions"), []byte("V\t2\n\nINBOX\nWork\nArchive\n"), 0o644); err != nil {
				t.Fatal(err)
			}

			before := accountMailboxState(t, rdb, accountID)

			opts := tc.opts
			opts.DryRun = true
			opts.TestMode = true
			opts.BatchSize = 10
			importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil, opts)
			if err != nil {
				t.Fatal(err)
			}
			if err := importer.Run(); err != nil {
				t.Fatalf("dry run: %v", err)
			}

			after := accountMailboxState(t, rdb, accountID)
			if fmt.Sprint(after) != fmt.Sprint(before) {
				t.Errorf("dry run changed the account\nbefore: %v\nafter:  %v", before, after)
			}
		})
	}
}

// accountMailboxState returns the account's mailboxes with their UIDVALIDITY and
// highest UID, and its subscriptions, as sorted lines.
func accountMailboxState(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) []string {
	t.Helper()
	ctx := context.Background()
	var state []string

	rows, err := rdb.GetOperationalDatabase().ReadPool.Query(ctx,
		`SELECT name, uid_validity, highest_uid FROM mailboxes WHERE account_id = $1`, accountID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		var uidValidity, highestUID int64
		if err := rows.Scan(&name, &uidValidity, &highestUID); err != nil {
			t.Fatal(err)
		}
		state = append(state, fmt.Sprintf("mailbox %s uidvalidity=%d highest_uid=%d", name, uidValidity, highestUID))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	subs, err := rdb.GetSubscribedMailboxNamesWithRetry(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subs {
		state = append(state, "subscribed "+s)
	}
	sort.Strings(state)
	return state
}

// TestS3Importer_DryRunChangesNothing is TestImporter_DryRunChangesNothing for
// `import s3 --dry-run`, whose analysis created the default mailboxes as well.
func TestS3Importer_DryRunChangesNothing(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "dryrun-s3@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	before := accountMailboxState(t, rdb, accountID)

	si, err := NewS3Importer(rdb, nil, S3ImporterOptions{Email: email, DryRun: true, CleanupDB: true})
	if err != nil {
		t.Fatal(err)
	}
	defer si.Close()
	// The analysis reads what the bucket scan recorded: one object stands for it.
	hash := strings.Repeat("ab", 32)
	if _, err := si.db.Exec(`INSERT INTO s3_objects (key, size, last_modified, etag, domain, local_part, content_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, "example.com/dryrun-s3/"+hash, 100, "2026-11-01T12:00:00Z", "etag",
		"example.com", "dryrun-s3", hash); err != nil {
		t.Fatal(err)
	}
	if err := si.performDryRun(); err != nil {
		t.Fatalf("dry run: %v", err)
	}

	after := accountMailboxState(t, rdb, accountID)
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Errorf("dry run changed the account\nbefore: %v\nafter:  %v", before, after)
	}
}
