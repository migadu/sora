package userapi

import (
	"strings"
	"testing"
	"time"
)

// TestNew_ClampsTokenDuration verifies the M10 hardening: token_duration is
// capped at maxTokenDuration so a misconfiguration cannot mint effectively
// permanent (and non-revocable) sessions.
func TestNew_ClampsTokenDuration(t *testing.T) {
	secret := strings.Repeat("k", minJWTSecretLength)

	tests := []struct {
		name       string
		configured time.Duration
		want       time.Duration
	}{
		{name: "zero uses default", configured: 0, want: 24 * time.Hour},
		{name: "under cap preserved", configured: 48 * time.Hour, want: 48 * time.Hour},
		{name: "at cap preserved", configured: maxTokenDuration, want: maxTokenDuration},
		{name: "over cap clamped", configured: 8760 * time.Hour, want: maxTokenDuration},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(nil, ServerOptions{
				Name:          "clamp-test-" + string(rune('a'+i)),
				JWTSecret:     secret,
				TokenDuration: tt.configured,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if s.tokenDuration != tt.want {
				t.Errorf("tokenDuration = %v, want %v", s.tokenDuration, tt.want)
			}
		})
	}
}

// TestGenerateToken_EmbedsAuthEpoch verifies the issued token carries the password
// epoch claim that the refresh-gate compares against.
func TestGenerateToken_EmbedsAuthEpoch(t *testing.T) {
	s := &Server{jwtSecret: strings.Repeat("k", minJWTSecretLength), tokenIssuer: "sora-test", tokenDuration: time.Hour}

	const epoch int64 = 1_700_000_000
	tok, _, err := s.generateToken("user@example.com", 7, epoch)
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}

	claims, err := s.validateToken(tok)
	if err != nil {
		t.Fatalf("validateToken: %v", err)
	}
	if claims.AuthEpoch != epoch {
		t.Errorf("AuthEpoch = %d, want %d", claims.AuthEpoch, epoch)
	}
	if claims.AccountID != 7 {
		t.Errorf("AccountID = %d, want 7", claims.AccountID)
	}
}
