package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sieveRecordingDB has no Sieve script for the account and records each one stored.
type sieveRecordingDB struct {
	*mockResilientDatabase
	stored []string
}

func (m *sieveRecordingDB) GetScriptByNameWithRetry(ctx context.Context, name string, accountID int64) (*db.SieveScript, error) {
	return nil, consts.ErrDBNotFound
}

func (m *sieveRecordingDB) CreateScriptWithRetry(ctx context.Context, accountID int64, name, content string) (*db.SieveScript, error) {
	m.stored = append(m.stored, content)
	return &db.SieveScript{ID: 1, AccountID: accountID, Name: name, Script: content}, nil
}

// TestImportSieveScriptFollowsLinksOnlyWithinItsDirectory: the usual --sieve file of a
// Dovecot migration is the user's ~/.dovecot.sieve, which Pigeonhole keeps as a
// symbolic link to sieve/<name>.sieve. The link is the user's, and the import runs
// with privileges the user lacks, so the link must not choose which file is read into
// the account (a file that does not compile is still stored, readable through
// ManageSieve). A link is followed only to a file within the directory it is in; one
// out of it, or an absolute one, is refused, named, and nothing is stored (#1607).
func TestImportSieveScriptFollowsLinksOnlyWithinItsDirectory(t *testing.T) {
	const secret = "root:secret-hash:19000:0:99999:7:::\n"
	const script = "keep;\n"

	// newHome returns a home directory holding a Pigeonhole sieve/ directory with
	// script, and the path of a file outside it holding secret.
	newHome := func(t *testing.T) (home, outside string) {
		t.Helper()
		base := t.TempDir()
		home = filepath.Join(base, "home")
		require.NoError(t, os.MkdirAll(filepath.Join(home, "sieve"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(home, "sieve", "managesieve.sieve"), []byte(script), 0644))
		outsideDir := filepath.Join(base, "etc")
		require.NoError(t, os.MkdirAll(outsideDir, 0755))
		outside = filepath.Join(outsideDir, "shadow")
		require.NoError(t, os.WriteFile(outside, []byte(secret), 0600))
		return home, outside
	}

	refused := []struct {
		name string
		link func(t *testing.T, home, outside string) string // returns the --sieve path
	}{
		{"absolute link out of the directory", func(t *testing.T, home, outside string) string {
			require.NoError(t, os.Symlink(outside, filepath.Join(home, ".dovecot.sieve")))
			return filepath.Join(home, ".dovecot.sieve")
		}},
		{"relative link out of the directory", func(t *testing.T, home, outside string) string {
			require.NoError(t, os.Symlink(filepath.Join("..", "etc", "shadow"), filepath.Join(home, ".dovecot.sieve")))
			return filepath.Join(home, ".dovecot.sieve")
		}},
		{"link through a linked directory out of it", func(t *testing.T, home, outside string) string {
			require.NoError(t, os.RemoveAll(filepath.Join(home, "sieve")))
			require.NoError(t, os.Symlink(filepath.Dir(outside), filepath.Join(home, "sieve")))
			require.NoError(t, os.Symlink(filepath.Join("sieve", "shadow"), filepath.Join(home, ".dovecot.sieve")))
			return filepath.Join(home, ".dovecot.sieve")
		}},
		{"absolute link to a file within the directory", func(t *testing.T, home, outside string) string {
			require.NoError(t, os.Symlink(filepath.Join(home, "sieve", "managesieve.sieve"), filepath.Join(home, ".dovecot.sieve")))
			return filepath.Join(home, ".dovecot.sieve")
		}},
	}
	for _, dryRun := range []bool{false, true} {
		for _, tc := range refused {
			name := tc.name
			if dryRun {
				name += "/dry run"
			}
			t.Run(name, func(t *testing.T) {
				home, outside := newHome(t)
				sievePath := tc.link(t, home, outside)
				rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
				importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath, DryRun: dryRun})
				require.NoError(t, importer.lookupAccount())

				err := importer.importSieveScript()
				if assert.Error(t, err, "the link was followed") {
					assert.Contains(t, err.Error(), sievePath, "the refusal does not name the file")
				}
				assert.Empty(t, rdb.stored, "the file the link names was stored as a Sieve script")
				assert.Empty(t, importer.sieveOutcome, "the outcome says the script was or would be stored")
			})
		}
	}

	t.Run("Pigeonhole relative link within the directory is followed", func(t *testing.T) {
		home, _ := newHome(t)
		sievePath := filepath.Join(home, ".dovecot.sieve")
		require.NoError(t, os.Symlink(filepath.Join("sieve", "managesieve.sieve"), sievePath))
		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		require.NoError(t, importer.importSieveScript())
		assert.Equal(t, []string{script}, rdb.stored)
		assert.Equal(t, `imported and activated as "imported"`, importer.sieveOutcome)
	})

	t.Run("a missing file is ignored", func(t *testing.T) {
		home, _ := newHome(t)
		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		for _, sievePath := range []string{
			filepath.Join(home, ".dovecot.sieve"),
			filepath.Join(home, "missing", ".dovecot.sieve"),
		} {
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
			require.NoError(t, importer.lookupAccount())
			require.NoError(t, importer.importSieveScript(), sievePath)
		}
		assert.Empty(t, rdb.stored)
	})
}
