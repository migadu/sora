package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
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

// With the default [uploader] path, the bodies a previous release staged under its /tmp
// default are intact but not where resolve looks: it would [DELETE] their messages. It
// must refuse before touching the database, as the server refuses to start.
func TestResolveRefusesWhileLegacySpoolHoldsBodies(t *testing.T) {
	legacy := filepath.Join(t.TempDir(), "uploads")
	body := filepath.Join(legacy, "42", strings.Repeat("a", 64))
	require.NoError(t, os.MkdirAll(filepath.Dir(body), 0o755))
	require.NoError(t, os.WriteFile(body, []byte("staged"), 0o644))

	saved := legacyUploaderPath
	legacyUploaderPath = legacy
	t.Cleanup(func() { legacyUploaderPath = saved })

	var cfg AdminConfig
	cfg.Uploader.Path = config.DefaultUploaderPath
	cfg.Uploader.MaxAttempts = 1

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := resolveFailedUploads(ctx, cfg, false, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), body, "the error names the stranded body")
}
