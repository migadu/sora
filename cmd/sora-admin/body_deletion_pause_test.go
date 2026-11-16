package main

import (
	"context"
	"github.com/migadu/sora/config"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestDestructiveBodyCommandsDefaultPausedBeforeIO(t *testing.T) {
	// Empty config/nil dependencies prove refusal occurs before database or S3 work.
	cfg := AdminConfig{}
	err := purgeAccountWithStorage(context.Background(), cfg, nil, 1, "user@example.com", nil)
	require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)
	err = verifyS3Storage(context.Background(), cfg, "user@example.com", false, true, false, false, 1, false)
	require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)
	report, err := rekeyAccount(context.Background(), nil, nil, 1, rekeyOptions{DeleteOldObjects: true})
	require.ErrorIs(t, err, config.ErrS3BodyDeletionPaused)
	require.NotNil(t, report)
	require.Zero(t, report.OldDeleted)
}

func TestAdminConfigRefusesUnknownBodyDeletionProtocol(t *testing.T) {
	name := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(name, []byte("[s3]\nbody_deletion_protocol = \"unsafe\"\n"), 0600))
	var cfg AdminConfig
	require.ErrorContains(t, loadAdminConfig(name, &cfg), "body_deletion_protocol")
}
