package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFolderNames are mailbox names whose export directory the import must read
// back unchanged (#1166): a '.' inside a level is not the Maildir++ separator the
// import splits on, '&' and non-ASCII characters are not modified UTF-7 the import
// decodes, and a literal escape sequence is not an escape.
var roundTripFolderNames = []string{
	"Sent",
	"Work/Projects",
	"v1.2",
	"Work/v1.2/Notes",
	".hidden",
	"Archive/.git",
	"..foo",
	"R&D25-Notes",
	"Literal &AOk-",
	"Données/Q1",
	"日本語/2026",
	"Projects/\U0001f60a",
	`back\slash`,
	`a\2eb`,
}

// TestExportedFolderNamesRoundTripThroughImport: the directory the exporter writes a
// mailbox to is read back by the importer as that mailbox's name (#1166).
func TestExportedFolderNamesRoundTripThroughImport(t *testing.T) {
	root := t.TempDir()
	exporter := &Exporter{maildirPath: root}
	importer := &Importer{maildirPath: root}

	for _, name := range roundTripFolderNames {
		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err, name)
		got, err := importer.resolveMailboxName(dir)
		if assert.NoError(t, err, name) {
			rel, _ := filepath.Rel(root, dir)
			assert.Equal(t, name, got, "mailbox %q exported to directory %q", name, rel)
		}
	}
}

// TestExportedFolderTreeScansAsTheExportedMailboxes: a maildir laid out by the
// exporter, every folder holding a message, is scanned by the import as exactly the
// exported mailboxes. The levels a nested name passes through ("Work/v1.2" for
// "Work/v1.2/Notes") hold no messages and are no mailboxes of their own.
func TestExportedFolderTreeScansAsTheExportedMailboxes(t *testing.T) {
	root := t.TempDir()
	exporter := &Exporter{maildirPath: root}
	const msg = "1700000000.M1P1.host:2,S"

	want := append([]string{"INBOX"}, roundTripFolderNames...)
	for _, name := range want {
		require.NoError(t, exporter.createMailboxDirectory(name), name)
		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err, name)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", msg), []byte("Subject: "+name+"\r\n\r\nx\r\n"), 0o644))
	}

	importer := newTestModeImporter(t, root, newMockResilientDatabase(), ImporterOptions{})
	require.NoError(t, importer.scanMaildir())

	rows, err := importer.sqliteDB.Query(`SELECT DISTINCT mailbox FROM messages`)
	require.NoError(t, err)
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		got = append(got, name)
	}
	require.NoError(t, rows.Err())
	assert.ElementsMatch(t, want, got)
}

// TestImportRestoresEscapedFolderNameCharacters: a folder level escaped as Dovecot's
// storage name escape character writes it ('\' and two hex digits, listescape) is
// imported with the character restored before modified UTF-7 is decoded, so a
// Maildir++ folder ".v1\2e2.Notes" is "v1.2/Notes". An escape that encodes no
// printable US-ASCII character, or is not followed by two hex digits, is kept.
func TestImportRestoresEscapedFolderNameCharacters(t *testing.T) {
	root := t.TempDir()
	importer := &Importer{maildirPath: root}
	for _, tc := range []struct{ dir, want string }{
		{`.v1\2e2.Notes`, "v1.2/Notes"},
		{`.R\5cD`, `R\D`},
		{`.Upper\2Ecase`, "Upper.case"},
		{`.Donn&AOk-es\2e2026`, "Données.2026"},
		{`.a\09b`, `a\09b`},
		{`.a\00b`, `a\00b`},
		{`.a\c3\a9b`, `a\c3\a9b`},
		{`.a\zzb`, `a\zzb`},
		{`.trailing\2`, `trailing\2`},
	} {
		got, err := importer.resolveMailboxName(filepath.Join(root, tc.dir))
		if assert.NoError(t, err, tc.dir) {
			assert.Equal(t, tc.want, got, tc.dir)
		}
	}
}

// TestSubscriptionsNameTheMailboxesTheirFoldersImportAs: a subscriptions file names a
// folder by its storage name, the name its directory has: Dovecot writes box->name
// (index_storage_set_subscribed), escaped by its storage name escape character, and
// reads it back with mailbox_list_get_vname. So a Dovecot Maildir++ maildir with
// listescape has the folder ".v1\2e2.Notes" subscribed as "v1\2e2" TAB "Notes", and
// both must import as "v1.2/Notes" (#1166). Sora's export writes a subscription the
// same way, so each name's subscriptions entry imports as the name.
func TestSubscriptionsNameTheMailboxesTheirFoldersImportAs(t *testing.T) {
	root := t.TempDir()
	importer := &Importer{maildirPath: root}
	subscribedAs := func(file string) string {
		t.Helper()
		names := parseDovecotSubscriptions(file)
		require.Len(t, names, 1, "%q", file)
		name, err := importedFolderName(names[0])
		require.NoError(t, err, file)
		return name
	}

	for _, tc := range []struct{ dir, subscriptions string }{
		{`.v1\2e2.Notes`, "V\t2\n\nv1\\2e2\tNotes\n"},
		{`.v1\2e2.Notes`, "v1\\2e2.Notes\n"}, // unversioned: levels joined by '.'
		{`.R\5cD`, "V\t2\n\nR\\5cD\n"},
		{`.Donn&AOk-es\2e2026`, "V\t2\n\nDonn&AOk-es\\2e2026\n"},
	} {
		folder, err := importer.resolveMailboxName(filepath.Join(root, tc.dir))
		require.NoError(t, err, tc.dir)
		assert.Equal(t, folder, subscribedAs(tc.subscriptions), "folder %q, subscriptions %q", tc.dir, tc.subscriptions)
	}

	exporter := &Exporter{maildirPath: root}
	for _, name := range roundTripFolderNames {
		dir, err := exporter.mailboxDir(name)
		require.NoError(t, err, name)
		rel, err := filepath.Rel(root, dir)
		require.NoError(t, err, name)
		entry := maildirFolderName(name)
		assert.Equal(t, filepath.ToSlash(rel), entry, "subscription of %q names its directory", name)
		assert.Equal(t, name, subscribedAs(formatDovecotSubscriptions([]string{entry})), "subscription of %q", name)
	}
}

// TestReexportWritesMessagesWhereTheFolderIsNamedNow: a message an older version
// exported is exported again when its file is not in the directory this version
// names the mailbox by. An older export wrote "v1.2" to the directory "v1.2", which
// the importer reads as "v1/2" (#1166); re-running the export into that directory
// must fill "v1\2e2" with every message of "v1.2", not only with those the older
// run did not write.
func TestReexportWritesMessagesWhereTheFolderIsNamedNow(t *testing.T) {
	root := t.TempDir()
	exporter, err := NewExporter(context.Background(), root, "user@example.com", 1, nil, nil, ExporterOptions{})
	require.NoError(t, err)
	defer exporter.Close()

	const hash, filename = "0123456789abcdef", "1700000000.M1700000000P1.host:2,S"
	oldPath := filepath.Join(root, "v1.2", "cur", filename)
	require.NoError(t, os.MkdirAll(filepath.Dir(oldPath), 0o755))
	require.NoError(t, os.WriteFile(oldPath, []byte("Subject: x\r\n\r\nx\r\n"), 0o644))
	require.NoError(t, exporter.recordExport(hash, "v1.2", filename, oldPath, 17))

	exported, existing, err := exporter.isMessageExported(hash, "v1.2")
	require.NoError(t, err)
	assert.False(t, exported, "the file is in %q, not in the directory this export writes \"v1.2\" to", oldPath)
	assert.Equal(t, filename, existing, "the message is written again under its recorded name")

	dir, err := exporter.mailboxDir("v1.2")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "cur"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", filename), []byte("Subject: x\r\n\r\nx\r\n"), 0o644))
	exported, existing, err = exporter.isMessageExported(hash, "v1.2")
	require.NoError(t, err)
	assert.True(t, exported, "the file is where this export writes \"v1.2\"")
	assert.Equal(t, filename, existing)
}
