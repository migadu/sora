//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestExportImportFoldersNamedAfterDirectoryEntries: an account whose mailboxes are
// named after the files an export writes beside their directories exports with
// --dovecot and dovecot-uidlist files, exits 0, and imports into another account with
// every mailbox, subscription, keyword and UIDVALIDITY (#1225). Before, the folder
// "dovecot-keywords" took INBOX's keywords file's place, so the INBOX export failed,
// "subscriptions" took the subscriptions file's, and "dovecot-uidlist" INBOX's
// uidlist's.
func TestExportImportFoldersNamedAfterDirectoryEntries(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}
	ctx := context.Background()
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()
	s3Storage := createTestS3Storage(t)
	stamp := time.Now().UnixNano()
	sourceEmail := fmt.Sprintf("entries-source-%d@example.com", stamp)
	targetEmail := fmt.Sprintf("entries-target-%d@example.com", stamp)
	createCacheTestAccount(t, rdb, sourceEmail, "test-password")
	createCacheTestAccount(t, rdb, targetEmail, "test-password")

	// The source is a Dovecot Maildir++ maildir. Each folder holds one message with
	// keyword letter "a", which the folder's dovecot-keywords file names Junk.
	folders := map[string]string{
		"":                       "INBOX",
		".subscriptions":         "subscriptions",
		".dovecot-uidlist":       "dovecot-uidlist",
		".dovecot-keywords":      "dovecot-keywords",
		".Work":                  "Work",
		".Work.dovecot-uidlist":  "Work/dovecot-uidlist",
		".Work.dovecot-keywords": "Work/dovecot-keywords",
	}
	src := t.TempDir()
	now := time.Now()
	n := 0
	var want []string
	for dir, name := range folders {
		n++
		path := filepath.Join(src, dir)
		createMaildirFolder(t, path)
		createMessagesInMaildir(t, path, []testMessage{{
			uid: 1, filename: fmt.Sprintf("17000000%02d.M%dP%d.host", n, n, n), flags: "Sa",
			subject: name, from: "a@example.com", to: "b@example.com", date: now.Add(-time.Duration(n) * time.Hour),
		}})
		if err := os.WriteFile(filepath.Join(path, "dovecot-keywords"), []byte("0 Junk\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, name)
	}
	subscriptions := "V\t2\n\nsubscriptions\ndovecot-uidlist\ndovecot-keywords\nWork\nWork\tdovecot-uidlist\nWork\tdovecot-keywords\n"
	if err := os.WriteFile(filepath.Join(src, "subscriptions"), []byte(subscriptions), 0o644); err != nil {
		t.Fatal(err)
	}

	importInto := func(maildir, email string, opts ImporterOptions) {
		t.Helper()
		importer, err := NewImporter(ctx, maildir, email, 2, rdb, s3Storage, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer importer.Close()
		if err := importer.Run(); err != nil {
			t.Fatalf("import %s: %v", maildir, err)
		}
	}

	importInto(src, sourceEmail, ImporterOptions{Dovecot: true, PreserveFlags: true})
	sourceNames, sourceSubs := folderNamesAndSubscriptions(t, ctx, rdb, sourceEmail)
	for _, name := range want {
		if !slices.Contains(sourceNames, name) || (name != "INBOX" && !slices.Contains(sourceSubs, name)) {
			t.Fatalf("source import: mailbox or subscription %q missing; mailboxes %q, subscriptions %q", name, sourceNames, sourceSubs)
		}
	}

	exportDir := filepath.Join(t.TempDir(), "export")
	exporter, err := NewExporter(ctx, exportDir, sourceEmail, 2, rdb, s3Storage, ExporterOptions{Dovecot: true, ExportUIDList: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Run(); err != nil {
		t.Errorf("export: %v", err)
	}
	for _, file := range []string{"subscriptions", "dovecot-uidlist", "dovecot-keywords", "Work/dovecot-uidlist", "Work/dovecot-keywords"} {
		if info, err := os.Stat(filepath.Join(exportDir, file)); err != nil || !info.Mode().IsRegular() {
			t.Errorf("export: %s is not a file (%v)", file, err)
		}
	}

	importInto(exportDir, targetEmail, ImporterOptions{Dovecot: true, PreserveFlags: true, PreserveUIDs: true})
	targetNames, targetSubs := folderNamesAndSubscriptions(t, ctx, rdb, targetEmail)
	if !slices.Equal(sourceNames, targetNames) {
		t.Errorf("mailboxes after export and import:\n got %q\nwant %q", targetNames, sourceNames)
	}
	if !slices.Equal(sourceSubs, targetSubs) {
		t.Errorf("subscriptions after export and import:\n got %q\nwant %q", targetSubs, sourceSubs)
	}
	sourceID := accountIDOf(t, ctx, rdb, sourceEmail)
	targetID := accountIDOf(t, ctx, rdb, targetEmail)
	for _, name := range want {
		if got := keywordTestMessages(t, ctx, rdb, targetEmail, name)[name]; !slices.Equal(got, []string{"Junk"}) {
			t.Errorf("mailbox %q: message keywords after export and import %q, want [Junk]", name, got)
		}
		srcBox, err := rdb.GetMailboxByNameWithRetry(ctx, sourceID, name)
		if err != nil {
			t.Fatal(err)
		}
		dstBox, err := rdb.GetMailboxByNameWithRetry(ctx, targetID, name)
		if err != nil {
			t.Fatal(err)
		}
		if srcBox.UIDValidity != dstBox.UIDValidity {
			t.Errorf("mailbox %q: UIDVALIDITY after export and import %d, want %d (from its dovecot-uidlist)", name, dstBox.UIDValidity, srcBox.UIDValidity)
		}
	}
}

// TestExportFailsWhenADovecotFileCannotBeWritten: an export whose subscriptions file or
// a folder's dovecot-uidlist cannot be written exits non-zero, and the other folders
// still get their dovecot-uidlist (#1225). Before, both were logged as warnings and
// the export exited 0, and the first uidlist that failed ended the loop. Here the
// paths are taken by directories, as an export from before #1225 left a mailbox named
// "subscriptions" in the export root.
func TestExportFailsWhenADovecotFileCannotBeWritten(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}
	ctx := context.Background()
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()
	s3Storage := createTestS3Storage(t)
	email := fmt.Sprintf("entries-fail-%d@example.com", time.Now().UnixNano())
	createCacheTestAccount(t, rdb, email, "test-password")

	src := t.TempDir()
	now := time.Now()
	for i, dir := range []string{"", ".Sent"} {
		createMaildirFolder(t, filepath.Join(src, dir))
		createMessagesInMaildir(t, filepath.Join(src, dir), []testMessage{{
			uid: 1, filename: fmt.Sprintf("17000000%02d.M%dP%d.host", i, i, i), flags: "S",
			subject: "message " + dir, from: "a@example.com", to: "b@example.com", date: now.Add(-time.Duration(i+1) * time.Hour),
		}})
	}
	importer, err := NewImporter(ctx, src, email, 2, rdb, s3Storage, ImporterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}
	importer.Close()

	exportDir := filepath.Join(t.TempDir(), "export")
	for _, dir := range []string{"subscriptions/cur", "Sent/dovecot-uidlist"} {
		if err := os.MkdirAll(filepath.Join(exportDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exporter, err := NewExporter(ctx, exportDir, email, 2, rdb, s3Storage, ExporterOptions{Dovecot: true, ExportUIDList: true})
	if err != nil {
		t.Fatal(err)
	}
	err = exporter.Run()
	if err == nil {
		t.Fatal("export exited 0 although neither the subscriptions file nor Sent's dovecot-uidlist could be written")
	}
	for _, want := range []string{"subscriptions", "dovecot-uidlist for mailbox Sent"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("export error %q does not report %q", err, want)
		}
	}
	if uidList, err := ParseDovecotUIDList(exportDir); err != nil || uidList == nil || len(uidList.UIDMappings) != 1 {
		t.Errorf("INBOX dovecot-uidlist after Sent's failed: %+v (%v)", uidList, err)
	}
}

// accountIDOf returns the account ID of an address.
func accountIDOf(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, email string) int64 {
	t.Helper()
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatal(err)
	}
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	return id
}
