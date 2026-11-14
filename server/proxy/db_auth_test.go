package proxy

import (
	"errors"
	"fmt"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
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
	}{
		{"unknown address", consts.ErrUserNotFound, "user_not_found", true},
		{"wrong SSHA512 password", db.VerifyPassword(ssha512, "wrong"), "invalid_password", true},
		{"wrong SHA512 password", db.VerifyPassword(db.GenerateSHA512Hash("secret"), "wrong"), "invalid_password", true},
		// A stored hash that cannot be checked is neither a wrong password nor a database
		// failure: it has its own reason, and is not cached.
		{"unparseable stored hash", db.VerifyPassword("{SSHA512}tooshort", "secret"), "unverifiable_hash", false},
		{"unsupported scheme", db.VerifyPassword("{SHA512-CRYPT}$6$saltsaltsaltsalt$Uz0B733KLAcpeAFT5hlALRwUMzwqxSoBO9VG7Ph8v7auZDaXL8PutBQPqOVLMvwy0rORlpwlXHm83Z4uAhgLB0", "secret"), "unverifiable_hash", false},
		{"password in the hash field", db.VerifyPassword("Secret-2026", "Secret-2026"), "unverifiable_hash", false},
		{"database error", fmt.Errorf("database error during authentication: %w", errors.New("connection refused")), "transient_error", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, definitive := ClassifyDBAuthFailure(tt.err)
			if reason != tt.wantReason || definitive != tt.wantDefinitive {
				t.Errorf("ClassifyDBAuthFailure(%v) = (%q, %v), want (%q, %v)", tt.err, reason, definitive, tt.wantReason, tt.wantDefinitive)
			}
		})
	}
}
