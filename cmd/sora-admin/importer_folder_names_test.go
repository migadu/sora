package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPathsFileNamesFoldersLikeResolveMailboxName: an import restricted with
// --paths-file must name each folder as the full maildir walk and resolveMailboxName
// do (the subscriptions import relies on that name too). "&AAk-" is modified UTF-7
// for TAB, which the folder import refuses.
func TestPathsFileNamesFoldersLikeResolveMailboxName(t *testing.T) {
	root := t.TempDir()
	const msg = "1700000000.M1P1.host:2,S"
	var paths []string
	for _, folder := range []string{".", ".Sent Items", ".Work.Projects", ".Bad&AAk-Name"} {
		dir := filepath.Join(root, folder)
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "cur", msg), []byte("Subject: x\r\n\r\nx\r\n"), 0o644))
		paths = append(paths, filepath.Join(folder, "cur", msg))
	}
	pathsFile := filepath.Join(t.TempDir(), "paths.txt")
	require.NoError(t, os.WriteFile(pathsFile, []byte(strings.Join(paths, "\n")+"\n"), 0o644))

	imp, err := NewImporter(context.Background(), root, "user@example.com", 1, nil, nil, ImporterOptions{PathsFile: pathsFile})
	require.NoError(t, err)
	defer imp.Close()

	files := make(chan fileToProcess, len(paths))
	require.NoError(t, imp.processPathsFile(filepath.Clean(root), files))
	close(files)

	var got []string
	for f := range files {
		got = append(got, f.mailboxName)
		want, err := imp.resolveMailboxName(filepath.Dir(filepath.Dir(f.path)))
		if assert.NoError(t, err, f.path) {
			assert.Equal(t, want, f.mailboxName, f.path)
		}
	}
	assert.ElementsMatch(t, []string{"INBOX", "Sent", "Work/Projects"}, got)
}

// TestEncodedPrintableASCIIIsNotDecoded: modified BASE64 must not encode printable
// US-ASCII (RFC 3501 §5.1.3), so "&AC8-" is not a '/' that adds a level. The import
// keeps such a folder's raw name and fix-utf7 refuses to decode the level.
func TestEncodedPrintableASCIIIsNotDecoded(t *testing.T) {
	name, err := importedFolderName("a&AC8-b")
	require.NoError(t, err)
	assert.Equal(t, "a&AC8-b", name)

	name, err = importedFolderName("Work/&AGE-")
	require.NoError(t, err)
	assert.Equal(t, "Work/&AGE-", name)

	_, err = decodeMailboxLevelUTF7("Parent/a&AC8-b")
	assert.Error(t, err)
}

// TestUndecodableLevelStaysBelowDecodedParent: a folder level that is not valid
// modified UTF-7 keeps its raw name, but the levels above it are still decoded. The
// parent folder ".Donn&AOk-es" is imported as "Données", so its child must be named
// below it; keeping the whole raw name put the child below a second, auto-created
// "Donn&AOk-es" that no folder of the maildir names.
func TestUndecodableLevelStaysBelowDecodedParent(t *testing.T) {
	parent, err := importedFolderName("Donn&AOk-es")
	require.NoError(t, err)
	require.Equal(t, "Données", parent)

	for _, tc := range []struct{ raw, want string }{
		{"Donn&AOk-es/a&AC8-b", "Données/a&AC8-b"}, // encoded '/'
		{"Donn&AOk-es/&2AA-", "Données/&2AA-"},     // lone surrogate
		{"Donn&AOk-es/R&D/&APw-bersicht", "Données/R&D/übersicht"},
	} {
		name, err := importedFolderName(tc.raw)
		require.NoError(t, err, tc.raw)
		assert.Equal(t, tc.want, name, tc.raw)
	}
}
