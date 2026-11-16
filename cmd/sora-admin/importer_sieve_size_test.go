package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sieveScriptLimit is the size limit `sora-admin sieve put` and the User API enforce.
const sieveScriptLimit = 65536

// sieveScriptOfSize returns a script of exactly size bytes that compiles.
func sieveScriptOfSize(t *testing.T, size int) string {
	t.Helper()
	const line = "# padding padding padding padding padding padding padding padding\n"
	const tail = "keep;\n"
	var b strings.Builder
	for b.Len()+len(line)+len(tail) <= size {
		b.WriteString(line)
	}
	if rest := size - b.Len() - len(tail); rest > 0 {
		b.WriteString(strings.Repeat("\n", rest))
	}
	b.WriteString(tail)
	require.Equal(t, size, b.Len())
	return b.String()
}

// TestImportSieveScriptRefusesAnOversizedScript: every other way a Sieve script reaches
// an account has a size limit (ManageSieve max_script_size, the User API, `sora-admin
// sieve put`). The usual --sieve file of a Dovecot migration is the user's
// ~/.dovecot.sieve, so a file over the limit `sieve put` enforces must be refused and
// named, nothing stored, and the import must go on; one at the limit is imported (#1662).
func TestImportSieveScriptRefusesAnOversizedScript(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "import", true: "dry run"}[dryRun], func(t *testing.T) {
			sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
			require.NoError(t, os.WriteFile(sievePath, []byte(sieveScriptOfSize(t, 16*sieveScriptLimit)), 0644))

			rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
			importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath, DryRun: dryRun})
			require.NoError(t, importer.Run(), "the import did not go on")

			assert.Zero(t, len(rdb.stored), "the oversized script was stored")
			want := "NOT imported: "
			if dryRun {
				want = "would NOT be imported: "
			}
			assert.True(t, strings.HasPrefix(importer.sieveOutcome, want), "the summary does not say the script was not imported: %q", importer.sieveOutcome)
			assert.Contains(t, importer.sieveOutcome, sievePath, "the summary does not name the file")
			assert.Contains(t, importer.sieveOutcome, "65536", "the summary does not name the limit")
		})
	}

	t.Run("a script at the limit is imported", func(t *testing.T) {
		script := sieveScriptOfSize(t, sieveScriptLimit)
		sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
		require.NoError(t, os.WriteFile(sievePath, []byte(script), 0644))

		rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
		require.NoError(t, importer.lookupAccount())

		require.NoError(t, importer.importSieveScript())
		assert.Equal(t, []string{script}, rdb.stored)
		assert.Equal(t, `imported and activated as "imported"`, importer.sieveOutcome)
	})

	t.Run("the read stops at the limit", func(t *testing.T) {
		// A sparse file costs no disk; reading it whole costs its size in memory.
		const size = 64 << 20
		sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
		require.NoError(t, os.WriteFile(sievePath, nil, 0644))
		require.NoError(t, os.Truncate(sievePath, size))

		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		_, err := readSieveFile(sievePath)
		runtime.ReadMemStats(&after)

		assert.Error(t, err, "a file over the limit was read")
		assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20), "the whole file was read into memory")
	})
}
