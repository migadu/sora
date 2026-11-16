package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The export, often run as root, writes into the directory --maildir-path names, and
// creates the directories missing on the way to it. When the operator exports an
// account into a user's maildir in place (#1597), the user can make ~/Maildir, or a
// directory on the way to it, a symbolic link to another user's maildir or home, which
// the account's mail, Dovecot metadata and cache would then be written into. A link on
// the way is followed under the import's rule (#1729): only when root made it or it
// belongs to the owner of the directory it leads to, and nothing is created before it
// is checked (#1785).

// treeNames lists every entry below dir, by its path relative to dir.
func treeNames(t *testing.T, dir string) []string {
	t.Helper()
	var names []string
	require.NoError(t, filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil || path == dir {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		names = append(names, rel)
		return err
	}))
	return names
}

func TestNewExporterRefusesAUsersLinkToAnotherUsersMaildir(t *testing.T) {
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name string
		// layout links alice's home to victimHome, bob's home holding his maildir,
		// and returns the --maildir-path and the link the refusal must name.
		layout func(t *testing.T, home, victimHome string) (maildirPath, link string)
	}{
		{"the maildir path is the link", func(t *testing.T, home, victimHome string) (string, string) {
			link := filepath.Join(home, "Maildir")
			require.NoError(t, os.Symlink(filepath.Join(victimHome, "Maildir"), link))
			ownedByUID(t, alice, link)
			return link, link
		}},
		{"a directory on the maildir path is the link", func(t *testing.T, home, victimHome string) (string, string) {
			link := filepath.Join(home, "x")
			require.NoError(t, os.Symlink(victimHome, link))
			ownedByUID(t, alice, link)
			return filepath.Join(link, "Maildir"), link
		}},
		// os.MkdirAll created the missing directories in the tree the link leads to.
		{"a directory on the way to a missing maildir is the link", func(t *testing.T, home, victimHome string) (string, string) {
			link := filepath.Join(home, "x")
			require.NoError(t, os.Symlink(victimHome, link))
			ownedByUID(t, alice, link)
			return filepath.Join(link, "new", "Maildir"), link
		}},
		// The system resolves ".." after a link from the link's target.
		{"dot-dot after the link", func(t *testing.T, home, victimHome string) (string, string) {
			link := filepath.Join(home, "x")
			require.NoError(t, os.Symlink(filepath.Join(victimHome, "Maildir", "cur"), link))
			ownedByUID(t, alice, link)
			ownedByUID(t, bob, filepath.Join(victimHome, "Maildir", "cur"))
			return link + string(filepath.Separator) + "..", link
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victimHome := t.TempDir()
			victim := filepath.Join(victimHome, "Maildir")
			for _, sub := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(victim, sub), 0755))
			}
			ownedByUID(t, bob, victimHome, victim)
			before := treeNames(t, victimHome)
			home := t.TempDir()
			maildirPath, link := tc.layout(t, home, victimHome)

			exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ExporterOptions{})
			if exporter != nil {
				exporter.Close()
			}
			if assert.Error(t, err, "another user's maildir was opened for the export through alice's link") {
				assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
			}
			assert.Equal(t, before, treeNames(t, victimHome), "the export created entries in the tree the link leads to")
		})
	}

	// A link to a directory that does not exist is not created through, as os.MkdirAll
	// does not: the directory would be the export's, and the link then checked against it.
	t.Run("a link to a missing directory", func(t *testing.T) {
		victimHome := t.TempDir()
		ownedByUID(t, bob, victimHome)
		link := filepath.Join(t.TempDir(), "Maildir")
		require.NoError(t, os.Symlink(filepath.Join(victimHome, "Maildir"), link))
		ownedByUID(t, alice, link)

		exporter, err := NewExporter(context.Background(), link, "alice@example.com", 1, nil, nil, ExporterOptions{})
		if exporter != nil {
			exporter.Close()
		}
		assert.Error(t, err, "the export opened a directory it created through alice's link")
		assert.Empty(t, treeNames(t, victimHome), "the export created entries in the tree the link leads to")
	})
}

func TestNewExporterFollowsALinkOfRootOrOfTheMaildirsOwner(t *testing.T) {
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name      string
		linkOwner uint32
		dirOwner  uint32
		// below names the maildir below the link's target, created by the export.
		below string
	}{
		{"root's link to a user's maildir", 0, bob, ""},                        // /var/mail/bob -> /srv/mail/bob
		{"the user's link to their own maildir", alice, alice, ""},             // ~/Maildir -> ~/mail/Maildir
		{"a missing maildir below root's link", 0, bob, "Maildir"},             // /home/bob -> /srv/home/bob
		{"a missing maildir below the user's link", alice, alice, "a/Maildir"}, // ~/x -> ~/mail
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			link := filepath.Join(t.TempDir(), "link")
			require.NoError(t, os.Symlink(target, link))
			ownedByUID(t, tc.linkOwner, link)
			ownedByUID(t, tc.dirOwner, target)
			maildirPath, real := link, target
			if tc.below != "" {
				maildirPath, real = filepath.Join(link, tc.below), filepath.Join(target, tc.below)
			}

			exporter, err := NewExporter(context.Background(), maildirPath, "user@example.com", 1, nil, messageStorage{[]byte(linkTestMessageBody)}, ExporterOptions{})
			require.NoError(t, err)
			t.Cleanup(func() { exporter.Close() })
			rootInfo, err := exporter.root.Stat(".")
			require.NoError(t, err)
			realInfo, err := os.Stat(real)
			require.NoError(t, err)
			assert.True(t, os.SameFile(realInfo, rootInfo), "the export does not write into the directory the link leads to")

			msg := linkTestMessage()
			filename := exporter.generateMaildirFilename(&msg, "INBOX")
			require.NoError(t, exporter.createMailboxDirectory("INBOX"))
			require.NoError(t, exporter.exportMessage(&msg, "INBOX"))
			require.NoError(t, exporter.Close())
			assert.FileExists(t, filepath.Join(real, "cur", filename))
			assert.FileExists(t, filepath.Join(real, maildirCacheName))
		})
	}
}

// The directories missing on the way to --maildir-path are created, as os.MkdirAll
// created them, whether it is absolute or relative to the working directory.
func TestNewExporterCreatesTheMissingDirectoriesOfTheMaildirPath(t *testing.T) {
	sep := string(filepath.Separator)
	for _, tc := range []struct {
		name, path, want string
	}{
		{"absolute", "", filepath.Join("a", "b", "Maildir")},
		{"relative", filepath.Join("a", "b", "Maildir"), filepath.Join("a", "b", "Maildir")},
		{"dot-dot", "a" + sep + "b" + sep + ".." + sep + "c" + sep + "Maildir", filepath.Join("a", "c", "Maildir")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			maildirPath := filepath.Join(dir, tc.want)
			if tc.path != "" {
				t.Chdir(dir)
				maildirPath = tc.path
			}

			exporter, err := NewExporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ExporterOptions{})
			require.NoError(t, err)
			require.NoError(t, exporter.Close())
			assert.FileExists(t, filepath.Join(dir, tc.want, maildirCacheName))
		})
	}
}
