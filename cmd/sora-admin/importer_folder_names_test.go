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
