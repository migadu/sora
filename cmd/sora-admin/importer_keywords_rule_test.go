package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDovecotKeywordFilesSameRuleEveryFolder: the a-z letters in a maildir filename
// index the dovecot-keywords file of that message's folder. Whether those files are
// read must not depend on the folder: --dovecot is documented as what processes
// dovecot-keywords, so INBOX (the maildir root) and a subfolder must either both get
// their keywords or both not.
func TestDovecotKeywordFilesSameRuleEveryFolder(t *testing.T) {
	const filename = "1700000000.M1P1.host:2,Sa"

	for _, dovecot := range []bool{false, true} {
		t.Run(fmt.Sprintf("dovecot=%v", dovecot), func(t *testing.T) {
			root := t.TempDir()
			work := filepath.Join(root, ".Work")
			for _, dir := range []string{root, work} {
				for _, sub := range []string{"cur", "new", "tmp"} {
					require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
				}
			}
			require.NoError(t, os.WriteFile(filepath.Join(root, "dovecot-keywords"), []byte("0 $Important\n"), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(work, "dovecot-keywords"), []byte("0 Project\n"), 0o644))

			imp, err := NewImporter(context.Background(), root, "user@example.com", 1, nil, nil, ImporterOptions{Dovecot: dovecot})
			require.NoError(t, err)
			defer imp.Close()

			flagsIn := func(folder string) []imap.Flag {
				path := filepath.Join(folder, "cur", filename)
				return imp.parseMaildirFlagsWith(filename, imp.keywordsForMessagePath(path))
			}

			wantInbox, wantWork := []imap.Flag{imap.FlagSeen}, []imap.Flag{imap.FlagSeen}
			if dovecot {
				wantInbox = append(wantInbox, "$Important")
				wantWork = append(wantWork, "Project")
			}
			assert.ElementsMatch(t, wantInbox, flagsIn(root), "INBOX")
			assert.ElementsMatch(t, wantWork, flagsIn(work), "Work")
		})
	}
}

// TestDovecotKeywordsOnlyFromTheFolderOwnFile: Dovecot reads a folder's keyword
// letters through <folder>/dovecot-keywords only, and clears the list when that file
// does not exist (maildir-keywords.c, maildir_keywords_sync on ENOENT). INBOX's file,
// at the maildir root, says nothing about the letters of any other folder, so a
// folder without a file of its own, or whose file cannot be read, gets no keyword.
func TestDovecotKeywordsOnlyFromTheFolderOwnFile(t *testing.T) {
	const filename = "1700000000.M1P1.host:2,Sa"

	root := t.TempDir()
	work := filepath.Join(root, ".Work")       // no dovecot-keywords
	unreadable := filepath.Join(root, ".Junk") // a dovecot-keywords that cannot be read
	for _, dir := range []string{root, work, unreadable} {
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o755))
		}
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "dovecot-keywords"), []byte("0 $Important\n"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(unreadable, "dovecot-keywords"), 0o755))

	imp, err := NewImporter(context.Background(), root, "user@example.com", 1, nil, nil, ImporterOptions{Dovecot: true})
	require.NoError(t, err)
	defer imp.Close()

	flagsIn := func(folder string) []imap.Flag {
		path := filepath.Join(folder, "cur", filename)
		return imp.parseMaildirFlagsWith(filename, imp.keywordsForMessagePath(path))
	}
	assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, "$Important"}, flagsIn(root), "INBOX")
	assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen}, flagsIn(work), "Work, without a dovecot-keywords file")
	assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen}, flagsIn(unreadable), "Junk, with an unreadable dovecot-keywords file")
}
