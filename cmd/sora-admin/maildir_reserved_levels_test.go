package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaildirReservedLevelsRoundTrip verifies that mailboxes with any hierarchy
// level named "cur", "new", or "tmp" — whether top-level ("cur", "new", "tmp"),
// nested under an existing parent ("Work/cur", "Work/new", "Work/tmp"), or nested
// under a non-existent parent ("Projects/new" without "Projects") — are exported
// to escaped directory names (\63ur, \6eew, \74mp) rather than colliding with a
// parent mailbox's Maildir cur/, new/, or tmp/ subdirectories.
func TestMaildirReservedLevelsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mailboxes []string
	}{
		{"lowercase", []string{"INBOX", "cur", "new", "tmp", "Work", "Work/cur", "Work/new", "Work/tmp", "Projects/new"}},
		{"case variants", []string{"INBOX", "Cur", "NEW", "Tmp", "Work", "Work/Cur", "Work/NEW", "Work/Tmp", "Projects/New"}},
	} {
		t.Run(tc.name, func(t *testing.T) { testMaildirReservedLevelsRoundTrip(t, tc.mailboxes) })
	}
}

func testMaildirReservedLevelsRoundTrip(t *testing.T, mailboxes []string) {
	root := t.TempDir()
	exporter, err := NewExporter(context.Background(), root, "user@example.com", 1, nil, nil, ExporterOptions{
		Dovecot:       true,
		ExportUIDList: true,
	})
	require.NoError(t, err)

	baseTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	for idx, mbox := range mailboxes {
		require.NoError(t, exporter.createMailboxDirectory(mbox), mbox)
		dir, err := exporter.mailboxDir(mbox)
		require.NoError(t, err, mbox)
		if mbox != "INBOX" {
			base := filepath.Base(dir)
			assert.NotContains(t, []string{"cur", "new", "tmp"}, strings.ToLower(base),
				"mailbox %q directory %q must not be named cur, new, or tmp", mbox, dir)
		}

		msg := db.Message{
			UID:          1,
			InternalDate: baseTime.Add(time.Duration(idx) * time.Minute),
			CustomFlags:  []string{"$Important"},
		}
		require.NoError(t, exporter.prepareKeywords(mbox, []db.Message{msg}), mbox)

		filename := exporter.generateMaildirFilename(&msg, mbox)
		rawMsg := fmt.Sprintf(
			"From: sender@example.com\r\nTo: user@example.com\r\nSubject: %s\r\nDate: Thu, 15 Jan 2026 10:%02d:00 +0000\r\nMessage-ID: <msg-%d@example.com>\r\n\r\nBody for %s\r\n",
			mbox, idx, idx+1, mbox,
		)
		require.NoError(t, writeMaildirFile(filepath.Join(dir, "cur", filename), []byte(rawMsg)), mbox)

		baseFilename := filename
		if colon := strings.LastIndex(baseFilename, ":"); colon > 0 {
			baseFilename = baseFilename[:colon]
		}
		uidList := CreateDovecotUIDListFromMessages(uint32(100+idx), []UIDFileMapping{
			{UID: 1, Filename: baseFilename},
		})
		require.NoError(t, WriteDovecotUIDList(dir, uidList), mbox)
	}
	require.NoError(t, exporter.Close())

	// Remove export tracking DB before simulating import into a fresh account (or let
	// scanMaildir populate fresh rows; exporter never called recordExport so messages
	// table is empty).
	assert.False(t, isMaildirFolder(filepath.Join(root, "Projects")),
		"intermediate directory Projects (for Projects/new without mailbox Projects) must not be misdetected as a Maildir folder")

	importer := newTestModeImporter(t, root, newMockResilientDatabase(), ImporterOptions{
		Dovecot:      true,
		PreserveUIDs: true,
	})
	require.NoError(t, importer.scanMaildir())

	rows, err := importer.sqliteDB.Query(`SELECT path, filename, mailbox FROM messages ORDER BY mailbox, filename`)
	require.NoError(t, err)
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var path, filename, mailbox string
		require.NoError(t, rows.Scan(&path, &filename, &mailbox))
		counts[mailbox]++

		content, err := os.ReadFile(path)
		require.NoError(t, err, "read %s (%s)", path, mailbox)
		meta, err := importer.parseMessageMetadata(content, filename, path)
		if assert.NoError(t, err, "queued file %q in mailbox %q must be a valid RFC822 message", filename, mailbox) && meta != nil {
			assert.Equal(t, mailbox, meta.subject, "message subject in mailbox %q", mailbox)
		}
	}
	require.NoError(t, rows.Err())

	assert.NotContains(t, counts, "Projects", "non-existent parent mailbox Projects must not be queued")
	wantCounts := make(map[string]int, len(mailboxes))
	for _, mbox := range mailboxes {
		wantCounts[mbox] = 1
	}
	assert.Equal(t, wantCounts, counts)

	// Subscriptions and literal backslash-escaped names round-trip without collision.
	roundTripNames := append([]string{}, mailboxes[1:]...) // non-INBOX folders
	roundTripNames = append(roundTripNames, `\63ur`, `\6eew`, `\74mp`, `Work/\63ur`, `\43ur`, `\4eEW`, `\54mp`)
	seenStorage := make(map[string]string, len(roundTripNames))
	for _, name := range roundTripNames {
		storage := maildirFolderName(name)
		if prev, exists := seenStorage[storage]; exists {
			t.Errorf("storage name collision: %q and %q both map to %q", prev, name, storage)
		}
		seenStorage[storage] = name

		subEntries := parseDovecotSubscriptions(formatDovecotSubscriptions([]string{storage}))
		require.Len(t, subEntries, 1, name)
		gotSub, err := importedFolderName(subEntries[0])
		require.NoError(t, err, name)
		assert.Equal(t, name, gotSub, "subscription round-trip for %q", name)

		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err, name)
		gotFolder, err := importer.resolveMailboxName(dir)
		require.NoError(t, err, name)
		assert.Equal(t, name, gotFolder, "directory round-trip for %q", name)
	}
}
