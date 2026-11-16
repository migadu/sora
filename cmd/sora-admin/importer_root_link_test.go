package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The import, often run as root, reads the directory --maildir-path names, and the
// --sieve file through its directory. When the operator imports a user's maildir in
// place, the user can make ~/Maildir (or ~/sieve) a symbolic link to any directory the
// import can read, such as another user's maildir, which would then be read into the
// account named by --email. A link on the way to the root is followed only when root
// made it or it belongs to the owner of the directory it leads to (#1729).

// rootLinkUIDs are two users other than the one running the test, and other than root.
func rootLinkUIDs() (alice, bob uint32) {
	uid := uint32(os.Getuid())
	return uid + 1, uid + 2
}

// resolvedName is path with every symbolic link in its directory resolved, as the
// refusal names a link.
func resolvedName(t *testing.T, path string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	require.NoError(t, err)
	return filepath.Join(dir, filepath.Base(path))
}

func TestNewImporterRefusesAUsersLinkToAnotherUsersMaildir(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name string
		// layout links alice's home to victim, bob's maildir, and returns the
		// --maildir-path and the link the refusal must name.
		layout func(t *testing.T, home, victim string) (maildirPath, link string)
	}{
		{"the maildir path is the link", func(t *testing.T, home, victim string) (string, string) {
			link := filepath.Join(home, "Maildir")
			require.NoError(t, os.Symlink(victim, link))
			ownedByUID(t, alice, link)
			return link, link
		}},
		{"a directory on the maildir path is the link", func(t *testing.T, home, victim string) (string, string) {
			link := filepath.Join(home, "mail")
			require.NoError(t, os.Symlink(filepath.Dir(victim), link))
			ownedByUID(t, alice, link)
			ownedByUID(t, bob, filepath.Dir(victim))
			return filepath.Join(link, filepath.Base(victim)), link
		}},
		// The system resolves ".." after a link from the link's target, so the path
		// names the victim's maildir; it must be checked as given, not as cleaned or
		// resolved.
		{"dot-dot after the link", func(t *testing.T, home, victim string) (string, string) {
			link := filepath.Join(home, "x")
			require.NoError(t, os.Symlink(filepath.Join(victim, "cur"), link))
			ownedByUID(t, alice, link)
			ownedByUID(t, bob, filepath.Join(victim, "cur"))
			return link + string(filepath.Separator) + "..", link
		}},
		// A link root made is followed, but not a link of the user's it leads to.
		{"root's link to the user's link", func(t *testing.T, home, victim string) (string, string) {
			link := filepath.Join(home, "Maildir")
			require.NoError(t, os.Symlink(victim, link))
			ownedByUID(t, alice, link)
			spool := filepath.Join(t.TempDir(), "alice")
			require.NoError(t, os.Symlink(link, spool))
			ownedByUID(t, 0, spool)
			return spool, link
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			victim := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("Victim", 100)})
			ownedByUID(t, bob, victim)
			home := t.TempDir()
			maildirPath, link := tc.layout(t, home, victim)

			importer, err := NewImporter(context.Background(), maildirPath, "alice@example.com", 1, nil, nil, ImporterOptions{TestMode: true})
			if importer != nil {
				importer.Close()
			}
			if assert.Error(t, err, "another user's maildir was opened through alice's link") {
				assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
			}
			assert.NoFileExists(t, filepath.Join(victim, maildirCacheName), "the cache was created in the directory the link leads to")
		})
	}
}

func TestNewImporterFollowsALinkOfRootOrOfTheMaildirsOwner(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name      string
		linkOwner uint32
		dirOwner  uint32
	}{
		{"root's link to a user's maildir", 0, bob},            // /var/mail/bob -> /srv/mail/bob
		{"the user's link to their own maildir", alice, alice}, // ~/Maildir -> ~/mail/Maildir
	} {
		t.Run(tc.name, func(t *testing.T) {
			real := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("Own", 100)})
			link := filepath.Join(t.TempDir(), "Maildir")
			require.NoError(t, os.Symlink(real, link))
			ownedByUID(t, tc.linkOwner, link)
			ownedByUID(t, tc.dirOwner, real)

			importer := newTestModeImporter(t, link, newMockResilientDatabase(), ImporterOptions{})
			require.NoError(t, importer.scanMaildir())
			assert.Equal(t, map[string]string{filepath.Join(link, "cur", name): "INBOX"}, scannedMessages(t, importer))
		})
	}
}

func TestImportSieveScriptRefusesAUsersLinkedDirectoryToAnotherUsers(t *testing.T) {
	const script = "keep;\n"
	alice, bob := rootLinkUIDs()

	for _, tc := range []struct {
		name     string
		dirOwner uint32
		refused  bool
	}{
		{"another user's directory", bob, true},
		{"the user's own directory", alice, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "sieve")
			require.NoError(t, os.Mkdir(target, 0755))
			require.NoError(t, os.WriteFile(filepath.Join(target, "managesieve.sieve"), []byte(script), 0644))
			ownedByUID(t, tc.dirOwner, target)
			home := t.TempDir()
			link := filepath.Join(home, "sieve")
			require.NoError(t, os.Symlink(target, link))
			ownedByUID(t, alice, link)
			sievePath := filepath.Join(link, "managesieve.sieve")

			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
			require.NoError(t, importer.lookupAccount())

			err := importer.importSieveScript()
			if !tc.refused {
				require.NoError(t, err)
				assert.Equal(t, []string{script}, rdb.stored)
				return
			}
			if assert.Error(t, err, "the script in another user's directory was read through alice's link") {
				assert.Contains(t, err.Error(), resolvedName(t, link), "the refusal does not name the link")
			}
			assert.Empty(t, rdb.stored, "another user's script was stored")
		})
	}
}
