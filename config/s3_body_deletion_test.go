package config

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestS3BodyDeletionProtocol(t *testing.T) {
	for _, protocol := range []string{"", "paused", S3BodyDeletionGlobalHashV1} {
		t.Run("valid_"+protocol, func(t *testing.T) {
			cfg := S3Config{BodyDeletionProtocol: protocol}
			require.NoError(t, cfg.ValidateBodyDeletionProtocol())
			if protocol == S3BodyDeletionGlobalHashV1 {
				require.NoError(t, cfg.RequireBodyDeletionProtocol())
			} else {
				require.ErrorIs(t, cfg.RequireBodyDeletionProtocol(), ErrS3BodyDeletionPaused)
			}
		})
	}
	for _, protocol := range []string{"global", "GLOBAL-HASH-V1", "global-hash-v1 ", "true"} {
		t.Run("invalid_"+protocol, func(t *testing.T) {
			cfg := S3Config{Endpoint: "localhost:9000", Bucket: "mail", BodyDeletionProtocol: protocol}
			require.ErrorContains(t, cfg.Validate(), "body_deletion_protocol")
			require.Error(t, cfg.RequireBodyDeletionProtocol())
		})
	}
}
