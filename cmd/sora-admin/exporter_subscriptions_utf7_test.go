//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// TestExporter_DovecotSubscriptionsModifiedUTF7RoundTrip verifies that
// `sora-admin export maildir --dovecot` writes Modified UTF-7 mailbox names in
// the Dovecot v2 `subscriptions` file (matching Dovecot's Maildir++ storage
// names and `Importer.processSubscriptions` -> `importedFolderName` ->
// `helpers.DecodeModifiedUTF7`), so `&` and non-ASCII names survive export and
// re-import without corruption.
func TestExporter_DovecotSubscriptionsModifiedUTF7RoundTrip(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	ctx := context.Background()

	const srcEmail = "subs-utf7-src@example.com"
	createSimpleTestAccount(t, rdb, srcEmail, "testpassword123")
	srcAddr, err := server.NewAddress(srcEmail)
	if err != nil {
		t.Fatal(err)
	}
	srcAccountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, srcAddr.FullAddress())
	if err != nil {
		t.Fatal(err)
	}

	subscribed := []string{
		"INBOX",
		"R&D",
		"R&D25-Notes",
		"Literal &AOk-",
		"Données/Q1",
		"Éléments envoyés",
		"日本語/2026",
		"Projects/\U0001f60a",
	}
	for _, name := range subscribed {
		if err := rdb.SubscribeWithRetry(ctx, srcAccountID, name); err != nil {
			t.Fatalf("subscribe %q: %v", name, err)
		}
	}

	maildir := filepath.Join(t.TempDir(), "Maildir")
	createMaildirFolder(t, maildir)
	exporter, err := NewExporter(ctx, maildir, srcEmail, 1, rdb, nil, ExporterOptions{Dovecot: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.exportSubscriptions(srcAccountID); err != nil {
		exporter.Close()
		t.Fatalf("exportSubscriptions: %v", err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(maildir, "subscriptions"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	if !strings.HasPrefix(content, dovecotSubscriptionsV2Header) {
		t.Fatalf("subscriptions file lacks Dovecot v2 header %q: %q", dovecotSubscriptionsV2Header, content)
	}

	body := strings.TrimSuffix(strings.TrimPrefix(content, dovecotSubscriptionsV2Header), "\n")
	gotLines := strings.Split(body, "\n")
	wantLines := []string{
		"INBOX",
		"R&-D",
		"R&-D25-Notes",
		"Literal &-AOk-",
		"Donn&AOk-es\tQ1",
		"&AMk-l&AOk-ments envoy&AOk-s",
		"&ZeVnLIqe-\t2026",
		"Projects\t&2D3eCg-",
	}
	for _, wantLine := range wantLines {
		if !slices.Contains(gotLines, wantLine) {
			t.Errorf("exported subscriptions missing Modified UTF-7 line %q; got lines: %q", wantLine, gotLines)
		}
	}

	// Re-import into a fresh account with --dovecot and verify lossless round-trip.
	const dstEmail = "subs-utf7-dst@example.com"
	createSimpleTestAccount(t, rdb, dstEmail, "testpassword123")
	dstAddr, err := server.NewAddress(dstEmail)
	if err != nil {
		t.Fatal(err)
	}
	dstAccountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, dstAddr.FullAddress())
	if err != nil {
		t.Fatal(err)
	}

	importer, err := NewImporter(ctx, maildir, dstEmail, 1, rdb, nil, ImporterOptions{
		Dovecot: true, PreserveUIDs: true, TestMode: true, BatchSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := importer.Run(); err != nil {
		t.Fatalf("re-import: %v", err)
	}

	reimported, err := rdb.GetSubscribedMailboxNamesWithRetry(ctx, dstAccountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range subscribed {
		if !slices.Contains(reimported, want) {
			t.Errorf("after round-trip: not subscribed to %q; got %q", want, reimported)
		}
	}
	for _, corrupted := range []string{"R\u0f6eNotes", "Literal é"} {
		if slices.Contains(reimported, corrupted) {
			t.Errorf("after round-trip: subscribed to corrupted name %q; got %q", corrupted, reimported)
		}
	}
}
