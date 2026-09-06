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

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// Custom keywords travel through maildir as a-z letters in the filename that index a
// dovecot-keywords file kept PER FOLDER, each with its own numbering. The importer must
// read each folder's file (not only the root one), and the exporter must write the
// files and the letters, so that import → export → import keeps every keyword.

func keywordTestMessages(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, email, mailbox string) map[string][]string {
	t.Helper()
	address, err := server.NewAddress(email)
	if err != nil {
		t.Fatal(err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatal(err)
	}
	mb, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailbox)
	if err != nil {
		t.Fatalf("mailbox %s: %v", mailbox, err)
	}
	var all imap.SeqSet
	all.AddRange(1, 0)
	msgs, err := rdb.GetMessagesByNumSetWithRetry(ctx, mb.ID, all)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]string)
	for _, m := range msgs {
		kws := append([]string(nil), m.CustomFlags...)
		sort.Strings(kws)
		out[m.Subject] = kws
	}
	return out
}

func TestDovecotKeywordsRoundTripPerFolder(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}
	ctx := context.Background()
	rdb := setupCacheTestDatabase(t)
	defer rdb.Close()
	s3Storage := createTestS3Storage(t)
	stamp := time.Now().UnixNano()
	sourceEmail := fmt.Sprintf("kw-source-%d@example.com", stamp)
	targetEmail := fmt.Sprintf("kw-target-%d@example.com", stamp)
	createCacheTestAccount(t, rdb, sourceEmail, "test-password")
	createCacheTestAccount(t, rdb, targetEmail, "test-password")

	// Source maildir: INBOX numbers keyword 0 = Junk; the .Sent folder numbers
	// keyword 0 = $Forwarded and 1 = Important. The letter "a" therefore means
	// different keywords in the two folders.
	src := t.TempDir()
	createMaildirFolder(t, src)
	createMaildirFolder(t, filepath.Join(src, ".Sent"))
	if err := os.WriteFile(filepath.Join(src, "dovecot-keywords"), []byte("0 Junk\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".Sent", "dovecot-keywords"), []byte("0 $Forwarded\n1 Important\n"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	createMessagesInMaildir(t, src, []testMessage{
		{uid: 1, filename: "1700000001.M1P1.host", flags: "Sa", subject: "inbox junk", from: "a@example.com", to: "b@example.com", date: now.Add(-2 * time.Hour)},
		{uid: 2, filename: "1700000002.M2P2.host", flags: "S", subject: "inbox plain", from: "a@example.com", to: "b@example.com", date: now.Add(-time.Hour)},
	})
	createMessagesInMaildir(t, filepath.Join(src, ".Sent"), []testMessage{
		{uid: 1, filename: "1700000003.M3P3.host", flags: "Sab", subject: "sent forwarded important", from: "b@example.com", to: "a@example.com", date: now.Add(-30 * time.Minute)},
	})

	importer, err := NewImporter(ctx, src, sourceEmail, 2, rdb, s3Storage, ImporterOptions{Dovecot: true, PreserveFlags: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("import: %v", err)
	}

	inbox := keywordTestMessages(t, ctx, rdb, sourceEmail, "INBOX")
	sent := keywordTestMessages(t, ctx, rdb, sourceEmail, "Sent")
	if got := inbox["inbox junk"]; strings.Join(got, ",") != "Junk" {
		t.Fatalf("INBOX message keywords after import: %v, want [Junk]", got)
	}
	if got := inbox["inbox plain"]; len(got) != 0 {
		t.Fatalf("plain INBOX message got keywords %v", got)
	}
	if got := sent["sent forwarded important"]; strings.Join(got, ",") != "$Forwarded,Important" {
		t.Fatalf("Sent message keywords after import: %v, want [$Forwarded Important] (per-folder numbering)", got)
	}

	// Export: each folder gets its own dovecot-keywords file and letters in filenames.
	exportDir := t.TempDir()
	exporter, err := NewExporter(ctx, exportDir, sourceEmail, 2, rdb, s3Storage, ExporterOptions{Dovecot: true, ExportUIDList: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Run(); err != nil {
		t.Fatalf("export: %v", err)
	}
	rootKw, err := os.ReadFile(filepath.Join(exportDir, "dovecot-keywords"))
	if err != nil || !strings.Contains(string(rootKw), "Junk") {
		t.Fatalf("root dovecot-keywords after export: %q (%v)", rootKw, err)
	}
	sentKw, err := os.ReadFile(filepath.Join(exportDir, "Sent", "dovecot-keywords"))
	if err != nil || !strings.Contains(string(sentKw), "$Forwarded") || !strings.Contains(string(sentKw), "Important") {
		t.Fatalf("Sent dovecot-keywords after export: %q (%v)", sentKw, err)
	}
	withLetters := 0
	for _, dir := range []string{filepath.Join(exportDir, "cur"), filepath.Join(exportDir, "Sent", "cur")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if i := strings.LastIndex(e.Name(), ":2,"); i >= 0 && strings.ContainsAny(e.Name()[i+3:], "abcdefghijklmnopqrstuvwxyz") {
				withLetters++
			}
		}
	}
	if withLetters != 2 {
		t.Fatalf("expected 2 exported files carrying keyword letters, found %d", withLetters)
	}

	// Re-import the export into a second account: keywords must come back identical.
	reimporter, err := NewImporter(ctx, exportDir, targetEmail, 2, rdb, s3Storage, ImporterOptions{Dovecot: true, PreserveFlags: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := reimporter.Run(); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	inbox2 := keywordTestMessages(t, ctx, rdb, targetEmail, "INBOX")
	sent2 := keywordTestMessages(t, ctx, rdb, targetEmail, "Sent")
	if got := inbox2["inbox junk"]; strings.Join(got, ",") != "Junk" {
		t.Fatalf("INBOX keywords after round trip: %v, want [Junk]", got)
	}
	if got := sent2["sent forwarded important"]; strings.Join(got, ",") != "$Forwarded,Important" {
		t.Fatalf("Sent keywords after round trip: %v, want [$Forwarded Important]", got)
	}
	_ = db.MaxCustomKeywordsPerMessage
}
