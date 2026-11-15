package main

import (
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
