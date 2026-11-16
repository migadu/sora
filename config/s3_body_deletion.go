package config

import (
	"errors"
	"fmt"
)

// S3BodyDeletionGlobalHashV1 acknowledges the stopped/drained upgrade to the
// account-independent body lock protocol. It is not automatic fleet detection.
const S3BodyDeletionGlobalHashV1 = "global-hash-v1"

var ErrS3BodyDeletionPaused = errors.New(`S3 message-body deletion is paused; complete the body-lock upgrade runbook before setting [s3] body_deletion_protocol = "global-hash-v1"`)

// ValidateBodyDeletionProtocol accepts a paused configuration, which keeps mail
// delivery, reads and uploads running while destructive body work is disabled.
func (s *S3Config) ValidateBodyDeletionProtocol() error {
	switch s.BodyDeletionProtocol {
	case "", "paused", S3BodyDeletionGlobalHashV1:
		return nil
	default:
		return fmt.Errorf("invalid body_deletion_protocol %q: expected paused or global-hash-v1", s.BodyDeletionProtocol)
	}
}

func (s *S3Config) RequireBodyDeletionProtocol() error {
	if err := s.ValidateBodyDeletionProtocol(); err != nil {
		return err
	}
	if s.BodyDeletionProtocol != S3BodyDeletionGlobalHashV1 {
		return ErrS3BodyDeletionPaused
	}
	return nil
}
