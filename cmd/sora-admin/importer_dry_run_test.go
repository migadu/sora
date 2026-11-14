//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
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

// TestImporter_DryRunPreviewsTheImport checks that a --dovecot dry run reports what
// the import would do. The import resolves every folder among the account's own
// mailboxes, so a same-named mailbox another owner shares with the account is not
// the one it writes to: the dry run must not report that mailbox's UIDVALIDITY as
// the one it would change, nor skip a message because that mailbox holds it. It
// also says that the import would create the missing default mailboxes.
func TestImporter_DryRunPreviewsTheImport(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const ownerEmail, email, team = "owner@example.com", "user@example.com", "Shared/Team"
	createSimpleTestAccount(t, rdb, ownerEmail, "testpassword123")
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatal(err)
	}
	msg := testMessage{uid: 7, filename: "1700000003.M3P3.host", flags: "S", subject: "team",
		from: "a@example.com", to: "team@example.com", date: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)}

	// The owner's Shared/Team holds the message and is shared with the user.
	ownerMaildir := filepath.Join(t.TempDir(), "Maildir")
	createMaildirFolder(t, ownerMaildir)
	createMaildirFolder(t, filepath.Join(ownerMaildir, ".Shared.Team"))
	createMessagesInMaildir(t, filepath.Join(ownerMaildir, ".Shared.Team"), []testMessage{msg})
	ownerImport, err := NewImporter(ctx, ownerMaildir, ownerEmail, 1, rdb, nil, ImporterOptions{TestMode: true, BatchSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := ownerImport.Run(); err != nil {
		t.Fatalf("owner import: %v", err)
	}
	if _, err := rdb.GetOperationalDatabase().WritePool.Exec(ctx,
		`UPDATE mailboxes SET is_shared = TRUE, owner_domain = 'example.com' WHERE account_id = $1 AND name = $2`,
		ownerID, team); err != nil {
		t.Fatal(err)
	}
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, email, team, "lr"); err != nil {
		t.Fatal(err)
	}
	if shared, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, team); err != nil || shared.AccountID != ownerID {
		t.Fatalf("the user does not see the owner's %s: %+v, %v", team, shared, err)
	}

	// The user's maildir has a folder of the same name holding the same message.
	maildir := filepath.Join(t.TempDir(), "Maildir")
	createMaildirFolder(t, maildir)
	teamDir := filepath.Join(maildir, ".Shared.Team")
	createMaildirFolder(t, teamDir)
	createMessagesInMaildir(t, teamDir, []testMessage{msg})
	createDovecotUIDList(t, teamDir, 4444, 8, []testMessage{msg})
	if err := os.WriteFile(filepath.Join(maildir, "subscriptions"), []byte("V\t2\n\nINBOX\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	logs := common.CaptureLogs(t)
	importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil,
		ImporterOptions{DryRun: true, Dovecot: true, PreserveUIDs: true, TestMode: true, BatchSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	var runErr error
	report := captureImporterStdout(t, func() { runErr = importer.Run() })
	if runErr != nil {
		t.Fatalf("dry run: %v", runErr)
	}

	if !strings.Contains(report, "IMPORT "+msg.filename) {
		t.Errorf("the dry run does not report importing %s into the user's own %s:\n%s", msg.filename, team, report)
	}
	logs.WaitForLine(t, "DRY RUN: Would create mailbox with the Dovecot UIDVALIDITY", "mailbox="+team, "uidvalidity=4444")
	logs.WaitForLine(t, "DRY RUN: Would create any missing default mailboxes")

	// The import does what the dry run said: it creates the user's own Shared/Team
	// with the Dovecot UIDVALIDITY and imports the message into it.
	importer, err = NewImporter(ctx, maildir, email, 1, rdb, nil,
		ImporterOptions{Dovecot: true, PreserveUIDs: true, TestMode: true, BatchSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}
	ownID, err := rdb.GetOwnedMailboxIDByNameWithRetry(ctx, accountID, team)
	if err != nil {
		t.Fatalf("the import did not create the user's own %s: %v", team, err)
	}
	var uidValidity, messages int64
	if err := rdb.GetOperationalDatabase().ReadPool.QueryRow(ctx, `SELECT uid_validity,
		(SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL) FROM mailboxes WHERE id = $1`,
		ownID).Scan(&uidValidity, &messages); err != nil {
		t.Fatal(err)
	}
	if uidValidity != 4444 || messages != 1 {
		t.Errorf("the user's own %s has uidvalidity=%d and %d messages, want 4444 and 1", team, uidValidity, messages)
	}
}

// TestImporter_DovecotKeywordsPerFolder: the keyword letters in a maildir filename
// index the dovecot-keywords file of that message's folder, and a folder without one
// names none (Dovecot maildir-keywords.c clears the list on ENOENT). The dry-run
// listing must show each message's flags as the import stores them, and neither may
// read a folder's letters through INBOX's file at the maildir root.
func TestImporter_DovecotKeywordsPerFolder(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const email = "keywords@example.com"
	createSimpleTestAccount(t, rdb, email, "testpassword123")
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatal(err)
	}

	// Every message carries keyword letter a (index 0), which INBOX's file names
	// $Important, Work's file names Project, and Other has no file to name.
	maildir := filepath.Join(t.TempDir(), "Maildir")
	folders := []struct {
		dir, mailbox, keywords, filename string
		want                             []string
	}{
		{"", "INBOX", "0 $Important\n", "1700000001.M1P1.host", []string{`\Seen`, "$Important"}},
		{".Work", "Work", "0 Project\n", "1700000002.M2P2.host", []string{`\Seen`, "Project"}},
		{".Other", "Other", "", "1700000003.M3P3.host", []string{`\Seen`}},
	}
	for _, f := range folders {
		path := filepath.Join(maildir, f.dir)
		createMaildirFolder(t, path)
		createMessagesInMaildir(t, path, []testMessage{{uid: 1, filename: f.filename, flags: "Sa",
			subject: f.mailbox, from: "a@example.com", to: email, date: time.Now()}})
		if f.keywords != "" {
			if err := os.WriteFile(filepath.Join(path, "dovecot-keywords"), []byte(f.keywords), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	opts := ImporterOptions{Dovecot: true, PreserveFlags: true, TestMode: true, BatchSize: 10}
	dryRun := opts
	dryRun.DryRun = true
	importer, err := NewImporter(ctx, maildir, email, 1, rdb, nil, dryRun)
	if err != nil {
		t.Fatal(err)
	}
	var runErr error
	report := captureImporterStdout(t, func() { runErr = importer.Run() })
	if runErr != nil {
		t.Fatalf("dry run: %v", runErr)
	}
	for _, f := range folders {
		want := fmt.Sprintf("Flags: %v", f.want)
		_, entry, found := strings.Cut(report, "IMPORT "+f.filename)
		entry, _, _ = strings.Cut(entry, "\n\n")
		if !found || !strings.Contains(entry, want) {
			t.Errorf("the dry run does not list the %s message with %q:\n%s", f.mailbox, want, report)
		}
	}

	importer, err = NewImporter(ctx, maildir, email, 1, rdb, nil, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}
	for _, f := range folders {
		mailboxID, err := rdb.GetOwnedMailboxIDByNameWithRetry(ctx, accountID, f.mailbox)
		if err != nil {
			t.Fatalf("mailbox %s: %v", f.mailbox, err)
		}
		messages, err := rdb.ListMessagesWithRetry(ctx, mailboxID)
		if err != nil {
			t.Fatal(err)
		}
		if len(messages) != 1 {
			t.Fatalf("%s has %d messages, want 1", f.mailbox, len(messages))
		}
		if got, want := fmt.Sprint(messages[0].CustomFlags), fmt.Sprint(f.want[1:]); got != want {
			t.Errorf("the %s message was imported with keywords %s, want %s", f.mailbox, got, want)
		}
	}
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

// captureImporterStdout returns what f prints to standard output, where the dry run
// writes its report.
func captureImporterStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	stdout := os.Stdout
	os.Stdout = w
	func() {
		defer func() { os.Stdout = stdout }()
		f()
	}()
	w.Close()
	return <-out
}
