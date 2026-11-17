//go:build darwin || linux

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The export's dry run reads the sora-maildir.db of the directory --maildir-path leads
// to, to report the messages an earlier run exported as skipped. It must reach that
// directory as the export does (#1785): through the links the export follows, never
// through one it refuses, and by the directory that was checked, not by the path
// again. Otherwise a dry run through a user's link to another user's maildir reads that
// user's cache, and reports on it, where the export itself refuses to start.

// newExportCacheWith makes the sora-maildir.db of dir, holding the message hash as
// filename in INBOX.
func newExportCacheWith(t *testing.T, dir, hash, filename string) {
	t.Helper()
	cache, err := sql.Open("sqlite", filepath.Join(dir, maildirCacheName))
	require.NoError(t, err)
	_, err = cache.Exec(`CREATE TABLE messages(hash TEXT,mailbox TEXT,filename TEXT)`)
	require.NoError(t, err)
	_, err = cache.Exec(`INSERT INTO messages VALUES(?,'INBOX',?)`, hash, filename)
	require.NoError(t, err)
	require.NoError(t, cache.Close())
}

// exportedName is the file name the dry run's cache gives the message hash in INBOX,
// or "" when it holds none.
func exportedName(t *testing.T, exporter *Exporter, hash string) string {
	t.Helper()
	_, filename, err := exporter.isMessageExported(hash, "INBOX")
	require.NoError(t, err)
	return filename
}

func TestExporterDryRunRefusesAUsersLinkToAnotherUsersMaildir(t *testing.T) {
	alice, bob := rootLinkUIDs()
	sep := string(filepath.Separator)

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
		// The export refuses the link before the missing directories below it; the
		// dry run must not report them as a missing target, with every message new.
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
			return link + sep + "..", link
		}},
		// A ".." after a missing directory goes back to the directory that holds it,
		// and on to the link.
		{"a link after a missing directory and dot-dot", func(t *testing.T, home, victimHome string) (string, string) {
			link := filepath.Join(home, "x")
			require.NoError(t, os.Symlink(victimHome, link))
			ownedByUID(t, alice, link)
			return home + sep + "a" + sep + ".." + sep + "x" + sep + "Maildir", link
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victimHome := t.TempDir()
			victim := filepath.Join(victimHome, "Maildir")
			for _, sub := range []string{"cur", "new", "tmp"} {
				require.NoError(t, os.MkdirAll(filepath.Join(victim, sub), 0755))
			}
			newExportCacheWith(t, victim, "victim", "victim.eml")
			ownedByUID(t, bob, victimHome, victim)
			before := exportCacheSourceState(t, victimHome)
			home := t.TempDir()
			maildirPath, link := tc.layout(t, home, victimHome)
			homeBefore := treeNames(t, home)

			exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			if exporter != nil {
				assert.Empty(t, exportedName(t, exporter, "victim"), "the dry run read the cache of the maildir alice's link leads to")
				exporter.Close()
			}
			// The refusal comes from the walk, before the cache is looked for.
			if assert.Error(t, err, "the dry run opened another user's maildir through alice's link") {
				assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
				assert.Contains(t, err.Error(), "is a symbolic link of uid", "not the walk's refusal of the link")
			}
			assert.Equal(t, before, exportCacheSourceState(t, victimHome), "the dry run changed the tree the link leads to")
			assert.Equal(t, homeBefore, treeNames(t, home), "the dry run created entries")
		})
	}
}

// The dry run follows the links the export follows, and reads the cache of the
// directory they lead to.
func TestExporterDryRunFollowsALinkTheExportFollows(t *testing.T) {
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name      string
		linkOwner *uint32 // nil: the link belongs to the user running the test
		dirOwner  uint32
	}{
		{"root's link to a user's maildir", new(uint32), bob},     // /var/mail/bob -> /srv/mail/bob
		{"the user's link to their own maildir", &alice, alice},   // ~/Maildir -> ~/mail/Maildir
		{"the running user's link to a user's maildir", nil, bob}, // /srv/export/bob -> /var/vmail/bob
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			newExportCacheWith(t, target, "hash", "message.eml")
			ownedByUID(t, tc.dirOwner, target)
			link := filepath.Join(t.TempDir(), "Maildir")
			require.NoError(t, os.Symlink(target, link))
			if tc.linkOwner != nil {
				ownedByUID(t, *tc.linkOwner, link)
			}
			before := exportCacheSourceState(t, target)

			exporter, err := NewExporter(context.Background(), link, "user@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
			require.NoError(t, err)
			assert.Equal(t, "message.eml", exportedName(t, exporter, "hash"), "the dry run did not read the cache the link leads to")
			require.NoError(t, exporter.Close())
			assert.Equal(t, before, exportCacheSourceState(t, target))
		})
	}
}

// Once the dry run has checked the directory --maildir-path leads to, the owner of the
// directory holding it can rename it and put a link to bob's maildir in its place. The
// cache must then be copied from the directory that was checked, or the dry run fail;
// it must not read bob's.
func TestExporterDryRunCopiesTheCacheOfTheCheckedRootWhenThePathIsReplaced(t *testing.T) {
	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	require.NoError(t, os.Mkdir(maildirPath, 0755))
	newExportCacheWith(t, maildirPath, "checked", "checked.eml")
	victim := newMaildirWith(t, nil)
	newExportCacheWith(t, victim, "victim", "victim.eml")
	before := exportCacheSourceState(t, victim)
	checked := maildirPath + ".checked"
	exportRootOpened = func() {
		require.NoError(t, os.Rename(maildirPath, checked))
		require.NoError(t, os.Symlink(victim, maildirPath))
	}
	t.Cleanup(func() { exportRootOpened = nil })

	exporter, err := NewExporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ExporterOptions{DryRun: true})
	if err == nil {
		assert.Empty(t, exportedName(t, exporter, "victim"), "the dry run read the cache the path leads to now")
		assert.Equal(t, "checked.eml", exportedName(t, exporter, "checked"), "the dry run did not read the cache of the directory it checked")
		require.NoError(t, exporter.Close())
	} else {
		assert.ErrorContains(t, err, "replaced", "not a refusal of the replaced path")
	}
	assert.Equal(t, before, exportCacheSourceState(t, victim), "the dry run changed the directory the path leads to now")
}

// A dry run fails where the export fails before it writes anything, rather than
// reporting a missing target: a link to a directory that does not exist is not created
// through, by the export as by os.MkdirAll before it.
func TestExporterDryRunFailsOnALinkToAMissingDirectoryAsTheExportDoes(t *testing.T) {
	target := filepath.Join(t.TempDir(), "Maildir")
	link := filepath.Join(t.TempDir(), "Maildir")
	require.NoError(t, os.Symlink(target, link))

	for _, dryRun := range []bool{false, true} {
		exporter, err := NewExporter(context.Background(), link, "user@example.com", 1, nil, nil, ExporterOptions{DryRun: dryRun})
		if exporter != nil {
			exporter.Close()
		}
		assert.Error(t, err, "dry run %v: a target was opened through a link to a missing directory", dryRun)
		assert.NoDirExists(t, target)
	}
}
