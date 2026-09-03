package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `uploader resolve` once had two outcomes: repair if the object is in S3, otherwise
// delete the message rows. On 2026-08-21 a provider fault parked 4161 uploads whose
// bodies were intact in the spool; that tool would have deleted every one of them.
// These tests pin the rule that deletion needs proof the body is nowhere.
func TestDecideResolve(t *testing.T) {
	cases := []struct {
		name      string
		inS3      bool
		ownedHere bool
		staged    stagedBody
		want      resolveOutcome
	}{
		{"object in S3 is finalized regardless of the spool", true, false, stagedAbsent, resolveRepair},
		{"object in S3 is finalized even with a body here", true, true, stagedIntact, resolveRepair},
		{"another host's row is never deleted from here", false, false, stagedAbsent, resolveSkipRemote},
		{"intact body here is re-armed, not deleted", false, true, stagedIntact, resolveRearm},
		{"size mismatch is left to a human", false, true, stagedSizeMismatch, resolveSkipSizeMismatch},
		{"nowhere at all is deleted", false, true, stagedAbsent, resolveDelete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decideResolve(tc.inS3, tc.ownedHere, tc.staged))
		})
	}
}

func TestStagedBodyState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body")

	assert.Equal(t, stagedAbsent, stagedBodyState(path, 4), "missing file")

	require.NoError(t, os.WriteFile(path, []byte("abcd"), 0644))
	assert.Equal(t, stagedIntact, stagedBodyState(path, 4), "exact size")
	assert.Equal(t, stagedSizeMismatch, stagedBodyState(path, 5), "wrong size")

	assert.Equal(t, stagedAbsent, stagedBodyState(dir, 4), "a directory is not a body")
}
