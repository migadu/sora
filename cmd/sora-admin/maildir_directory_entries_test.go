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

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMaildirFolderNameEscapesDirectoryEntries: a level named after a file the export
// writes in the directory that holds the level's own directory escapes its first
// character (#1225). Every mailbox directory holds dovecot-uidlist and
// dovecot-keywords; the export root, INBOX's directory, also holds subscriptions.
// sora-maildir.db is not affected: its '.' is escaped.
func TestMaildirFolderNameEscapesDirectoryEntries(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"subscriptions", `\73ubscriptions`},
		{"dovecot-uidlist", `\64ovecot-uidlist`},
		{"dovecot-keywords", `\64ovecot-keywords`},
		{"Subscriptions", `\53ubscriptions`},
		{"DOVECOT-UIDLIST", `\44OVECOT-UIDLIST`},
		{"Dovecot-Keywords", `\44ovecot-Keywords`},
		{"subscriptions/Work", `\73ubscriptions/Work`},
		{"Work/dovecot-uidlist", `Work/\64ovecot-uidlist`},
		{"Work/Dovecot-Keywords", `Work/\44ovecot-Keywords`},
		// Only the export root holds a subscriptions file.
		{"Work/subscriptions", "Work/subscriptions"},
		{"sora-maildir.db", `sora-maildir\2edb`},
		{"sora-maildir.db-wal", `sora-maildir\2edb-wal`},
		{"subscriptions2", "subscriptions2"},
		{"dovecot-uidlist-old", "dovecot-uidlist-old"},
	} {
		assert.Equal(t, tc.want, maildirFolderName(tc.name), "storage name of %q", tc.name)
	}
}

// TestExportFoldersNamedAfterDirectoryEntries: mailboxes named after the files an
// export writes beside their directories ("subscriptions", "dovecot-uidlist",
// "dovecot-keywords", at the top level and below a folder) get directories that leave
// room for those files, and an import reads every folder, uidlist, keywords file and
// subscription back (#1225). Before, the directory took the file's name, so the file
// could not be written.
func TestExportFoldersNamedAfterDirectoryEntries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mailboxes []string
	}{
		{"lowercase", []string{"INBOX", "subscriptions", "dovecot-uidlist", "dovecot-keywords", "Work", "Work/dovecot-uidlist", "Work/dovecot-keywords", "Work/subscriptions"}},
		{"case variants", []string{"INBOX", "Subscriptions", "DOVECOT-UIDLIST", "Dovecot-Keywords", "Work", "Work/Dovecot-Uidlist", "Work/DOVECOT-KEYWORDS"}},
	} {
		t.Run(tc.name, func(t *testing.T) { testExportFoldersNamedAfterDirectoryEntries(t, tc.mailboxes) })
	}
}

func testExportFoldersNamedAfterDirectoryEntries(t *testing.T, mailboxes []string) {
	root := t.TempDir()
	exporter, err := NewExporter(context.Background(), root, "user@example.com", 1, nil, nil, ExporterOptions{
		Dovecot:       true,
		ExportUIDList: true,
	})
	require.NoError(t, err)

	// As Run does: every mailbox's directory first, then each mailbox's files.
	for _, mbox := range mailboxes {
		require.NoError(t, exporter.createMailboxDirectory(mbox), mbox)
	}
	baseTime := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	for idx, mbox := range mailboxes {
		dir, err := exporter.mailboxDir(mbox)
		require.NoError(t, err, mbox)
		msg := db.Message{
			UID:          1,
			InternalDate: baseTime.Add(time.Duration(idx) * time.Minute),
			CustomFlags:  []string{"$Important"},
		}
		if !assert.NoError(t, exporter.prepareKeywords(mbox, []db.Message{msg}), "keywords of %q", mbox) {
			continue
		}
		filename := exporter.generateMaildirFilename(&msg, mbox)
		rawMsg := fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: %s\r\nMessage-ID: <msg-%d@example.com>\r\n\r\nBody\r\n", mbox, idx)
		require.NoError(t, writeMaildirFile(filepath.Join(dir, "cur", filename), []byte(rawMsg)), mbox)
		uidList := CreateDovecotUIDListFromMessages(uint32(100+idx), []UIDFileMapping{
			{UID: 1, Filename: filename[:strings.LastIndex(filename, ":")]},
		})
		assert.NoError(t, WriteDovecotUIDList(dir, uidList), "dovecot-uidlist of %q", mbox)
	}
	// The subscriptions file, as exportSubscriptions writes it.
	subscribed := make([]string, 0, len(mailboxes))
	for _, mbox := range mailboxes[1:] {
		subscribed = append(subscribed, maildirFolderName(mbox))
	}
	assert.NoError(t, os.WriteFile(filepath.Join(root, "subscriptions"), []byte(formatDovecotSubscriptions(subscribed)), 0644),
		"subscriptions file")
	require.NoError(t, exporter.Close())

	importer := newTestModeImporter(t, root, newMockResilientDatabase(), ImporterOptions{
		Dovecot:      true,
		PreserveUIDs: true,
	})
	require.NoError(t, importer.scanMaildir())

	rows, err := importer.sqliteDB.Query(`SELECT path, filename, mailbox FROM messages`)
	require.NoError(t, err)
	defer rows.Close()
	counts := make(map[string]int)
	for rows.Next() {
		var path, filename, mailbox string
		require.NoError(t, rows.Scan(&path, &filename, &mailbox))
		counts[mailbox]++
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		meta, err := importer.parseMessageMetadata(content, filename, path)
		if assert.NoError(t, err, "message %q of %q", filename, mailbox) {
			assert.Equal(t, mailbox, meta.subject, "message of mailbox %q", mailbox)
		}
	}
	require.NoError(t, rows.Err())
	want := make(map[string]int, len(mailboxes))
	for _, mbox := range mailboxes {
		want[mbox] = 1
	}
	assert.Equal(t, want, counts, "messages per imported mailbox")

	for idx, mbox := range mailboxes {
		dir, err := exporter.mailboxDir(mbox)
		require.NoError(t, err, mbox)
		if uidList := importer.dovecotUIDLists[dir]; assert.NotNil(t, uidList, "dovecot-uidlist of %q", mbox) {
			assert.Equal(t, uint32(100+idx), uidList.UIDValidity, "UIDVALIDITY of %q", mbox)
		}
		kws, err := parseKeywordsFile(filepath.Join(dir, "dovecot-keywords"))
		if assert.NoError(t, err, "dovecot-keywords of %q", mbox) {
			assert.Equal(t, map[int]string{0: "$Important"}, kws, "dovecot-keywords of %q", mbox)
		}
	}

	content, err := os.ReadFile(filepath.Join(root, "subscriptions"))
	require.NoError(t, err, "subscriptions file")
	var gotSubs []string
	for _, entry := range parseDovecotSubscriptions(string(content)) {
		name, err := importedFolderName(entry)
		require.NoError(t, err, entry)
		gotSubs = append(gotSubs, name)
	}
	wantSubs := slices.Clone(mailboxes[1:])
	slices.Sort(gotSubs)
	slices.Sort(wantSubs)
	assert.Equal(t, wantSubs, gotSubs, "subscriptions read back")
}

// TestGenerateDovecotUIDListsContinuesAfterAFailure: a folder whose dovecot-uidlist
// cannot be written does not cost the other folders theirs, and every failure is
// reported (#1225). Before, the first failure ended the loop, so the folders the map
// iteration had not reached yet got no uidlist.
func TestGenerateDovecotUIDListsContinuesAfterAFailure(t *testing.T) {
	root := t.TempDir()
	exporter, err := NewExporter(context.Background(), root, "user@example.com", 1, nil, nil, ExporterOptions{ExportUIDList: true})
	require.NoError(t, err)
	defer exporter.Close()

	names := []string{"INBOX", "Sent", "Drafts", "Archive", "Blocked1", "Blocked2"}
	var mailboxes []*db.DBMailbox
	for i, name := range names {
		require.NoError(t, exporter.createMailboxDirectory(name))
		mailboxes = append(mailboxes, &db.DBMailbox{ID: int64(i + 1), Name: name, UIDValidity: uint32(100 + i)})
		exporter.uidMappings[name] = []UIDFileMapping{{UID: 1, Filename: fmt.Sprintf("1700000000.M%dP1.host", i)}}
	}
	// A directory where a folder's dovecot-uidlist has to go makes its write fail.
	for _, name := range []string{"Blocked1", "Blocked2"} {
		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "dovecot-uidlist"), 0755))
	}

	err = exporter.generateDovecotUIDLists(mailboxes)
	require.Error(t, err)
	for _, name := range []string{"Blocked1", "Blocked2"} {
		assert.Contains(t, err.Error(), "mailbox "+name+":", "every failed folder is reported")
	}
	for i, name := range names[:4] {
		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err)
		uidList, err := ParseDovecotUIDList(dir)
		if assert.NoError(t, err, name) && assert.NotNil(t, uidList, "dovecot-uidlist of %q", name) {
			assert.Equal(t, uint32(100+i), uidList.UIDValidity, name)
		}
	}
}
