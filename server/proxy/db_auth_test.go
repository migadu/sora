package proxy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

func TestClassifyDBAuthFailure(t *testing.T) {
	ssha512, err := db.GenerateSSHA512Hash("secret")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		err            error
		wantReason     string
		wantDefinitive bool
		wantTemporary  bool // answered as a temporary failure and not rate-limited
	}{
		{"unknown address", consts.ErrUserNotFound, "user_not_found", true, false},
		{"wrong SSHA512 password", db.VerifyPassword(ssha512, "wrong"), "invalid_password", true, false},
		{"wrong SHA512 password", db.VerifyPassword(db.GenerateSHA512Hash("secret"), "wrong"), "invalid_password", true, false},
		// A stored hash that cannot be checked is not a wrong password: it has its own
		// reason, is not cached, and is a temporary failure, like a database outage.
		{"unparseable stored hash", db.VerifyPassword("{SSHA512}tooshort", "secret"), "unverifiable_hash", false, true},
		{"unsupported scheme", db.VerifyPassword("{SHA512-CRYPT}$6$saltsaltsaltsalt$Uz0B733KLAcpeAFT5hlALRwUMzwqxSoBO9VG7Ph8v7auZDaXL8PutBQPqOVLMvwy0rORlpwlXHm83Z4uAhgLB0", "secret"), "unverifiable_hash", false, true},
		{"password in the hash field", db.VerifyPassword("Secret-2026", "Secret-2026"), "unverifiable_hash", false, true},
		{"database unavailable", fmt.Errorf("%w: %w", server.ErrAuthServiceUnavailable, errors.New("connection refused")), "transient_error", false, true},
		{"server shutting down", server.ErrServerShuttingDown, "transient_error", false, true},
		{"database error", fmt.Errorf("database error during authentication: %w", errors.New("connection refused")), "transient_error", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, definitive := ClassifyDBAuthFailure(tt.err)
			if reason != tt.wantReason || definitive != tt.wantDefinitive {
				t.Errorf("ClassifyDBAuthFailure(%v) = (%q, %v), want (%q, %v)", tt.err, reason, definitive, tt.wantReason, tt.wantDefinitive)
			}
			if temporary := IsTemporaryDBAuthFailure(tt.err); temporary != tt.wantTemporary {
				t.Errorf("IsTemporaryDBAuthFailure(%v) = %v, want %v", tt.err, temporary, tt.wantTemporary)
			}
		})
	}
}
