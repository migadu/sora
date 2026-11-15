//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestExportImportKeepsFolderNames: an account exported with --dovecot and imported
// into another account keeps its mailbox names and its subscriptions, and they still
// name the same mailboxes (#1166). Before, "v1.2" came back as "v1/2", "R&D25-Notes"
// as "R཮Notes" and "Literal &AOk-" as "Literal é", while the subscriptions file
// named the originals.
func TestExportImportKeepsFolderNames(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}
	ctx := context.Background()
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()
	s3Storage := createTestS3Storage(t)
	stamp := time.Now().UnixNano()
	sourceEmail := fmt.Sprintf("folders-source-%d@example.com", stamp)
	targetEmail := fmt.Sprintf("folders-target-%d@example.com", stamp)
	createCacheTestAccount(t, rdb, sourceEmail, "test-password")
	createCacheTestAccount(t, rdb, targetEmail, "test-password")

	// The source is a Dovecot Maildir++ maildir whose storage name escape character
	// is '\' (listescape), the only Maildir++ form of a '.' inside a level.
	folders := map[string]string{
		`.v1\2e2`:          "v1.2",
		".R&-D25-Notes":    "R&D25-Notes",
		".Literal &-AOk-":  "Literal &AOk-",
		".Donn&AOk-es.Q1":  "Données/Q1",
		`.Work.v1\2e2.Old`: "Work/v1.2/Old",
		`.a\5c2eb`:         `a\2eb`,
	}
	src := t.TempDir()
	createMaildirFolder(t, src)
	now := time.Now()
	n := 0
	var want []string
	for dir, name := range folders {
		n++
		createMaildirFolder(t, filepath.Join(src, dir))
		createMessagesInMaildir(t, filepath.Join(src, dir), []testMessage{{
			uid: 1, filename: fmt.Sprintf("17000000%02d.M%dP%d.host", n, n, n), flags: "S",
			subject: name, from: "a@example.com", to: "b@example.com", date: now.Add(-time.Duration(n) * time.Hour),
		}})
		want = append(want, name)
	}
	// Dovecot's subscriptions file holds the same storage names as the folders, levels
	// joined by TAB (index_storage_set_subscribed writes box->name).
	subscriptions := "V\t2\n\nv1\\2e2\nR&-D25-Notes\nLiteral &-AOk-\nDonn&AOk-es\tQ1\nWork\tv1\\2e2\tOld\na\\5c2eb\n"
	if err := os.WriteFile(filepath.Join(src, "subscriptions"), []byte(subscriptions), 0o644); err != nil {
		t.Fatal(err)
	}

	importInto := func(maildir, email string) {
		t.Helper()
		importer, err := NewImporter(ctx, maildir, email, 2, rdb, s3Storage, ImporterOptions{Dovecot: true, PreserveFlags: true})
		if err != nil {
			t.Fatal(err)
		}
		defer importer.Close()
		if err := importer.Run(); err != nil {
			t.Fatalf("import %s: %v", maildir, err)
		}
	}

	// Every subscription names a mailbox: the import subscribes each mailbox it
	// creates, so a subscription read under another name than its folder shows up as
	// one naming no mailbox.
	subscriptionsNameMailboxes := func(which string, names, subs []string) {
		t.Helper()
		for _, sub := range subs {
			if !slices.Contains(names, sub) {
				t.Errorf("%s: subscription %q names no mailbox; mailboxes %q", which, sub, names)
			}
		}
	}

	importInto(src, sourceEmail)
	sourceNames, sourceSubs := folderNamesAndSubscriptions(t, ctx, rdb, sourceEmail)
	for _, name := range want {
		if !slices.Contains(sourceNames, name) || !slices.Contains(sourceSubs, name) {
			t.Errorf("source import: mailbox or subscription %q missing; mailboxes %q, subscriptions %q", name, sourceNames, sourceSubs)
		}
	}
	subscriptionsNameMailboxes("source import", sourceNames, sourceSubs)

	exportDir := filepath.Join(t.TempDir(), "export")
	exporter, err := NewExporter(ctx, exportDir, sourceEmail, 2, rdb, s3Storage, ExporterOptions{Dovecot: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Run(); err != nil {
		t.Fatalf("export: %v", err)
	}

	importInto(exportDir, targetEmail)
	targetNames, targetSubs := folderNamesAndSubscriptions(t, ctx, rdb, targetEmail)
	if !slices.Equal(sourceNames, targetNames) {
		t.Errorf("mailboxes after export and import:\n got %q\nwant %q", targetNames, sourceNames)
	}
	if !slices.Equal(sourceSubs, targetSubs) {
		t.Errorf("subscriptions after export and import:\n got %q\nwant %q", targetSubs, sourceSubs)
	}
	subscriptionsNameMailboxes("export and import", targetNames, targetSubs)
}

// folderNamesAndSubscriptions returns an account's mailbox names and subscribed
// names, sorted.
func folderNamesAndSubscriptions(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, email string) (names, subscribed []string) {
	t.Helper()
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, mb := range mailboxes {
		names = append(names, mb.Name)
	}
	if subscribed, err = rdb.GetSubscribedMailboxNamesWithRetry(ctx, accountID); err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	slices.Sort(subscribed)
	return names, subscribed
}
