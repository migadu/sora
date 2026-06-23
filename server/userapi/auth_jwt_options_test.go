package userapi

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestValidateToken_ParserOptions verifies the JWT parser hardening added for H5:
// the algorithm is pinned to HS256 (alg=none rejected), an exp claim is required, and
// the issuer is enforced.
func TestValidateToken_ParserOptions(t *testing.T) {
	secret := strings.Repeat("k", 32)
	s := &Server{jwtSecret: secret, tokenIssuer: "sora-test", tokenDuration: time.Hour}

	sign := func(method jwt.SigningMethod, key any, claims JWTClaims) string {
		t.Helper()
		str, err := jwt.NewWithClaims(method, claims).SignedString(key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return str
	}
	hour := jwt.NewNumericDate(time.Now().Add(time.Hour))

	t.Run("valid token round-trips", func(t *testing.T) {
		tok, _, err := s.generateToken("user@example.com", 1, 0)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if _, err := s.validateToken(tok); err != nil {
			t.Errorf("valid token rejected: %v", err)
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		tok := sign(jwt.SigningMethodHS256, []byte(secret), JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "attacker", Subject: "u@x", ExpiresAt: hour},
		})
		if _, err := s.validateToken(tok); err == nil {
			t.Error("token with wrong issuer should be rejected")
		}
	})

	t.Run("missing exp rejected", func(t *testing.T) {
		tok := sign(jwt.SigningMethodHS256, []byte(secret), JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "sora-test", Subject: "u@x"},
		})
		if _, err := s.validateToken(tok); err == nil {
			t.Error("token without exp should be rejected")
		}
	})

	t.Run("alg=none rejected", func(t *testing.T) {
		tok := sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "sora-test", Subject: "u@x", ExpiresAt: hour},
		})
		if _, err := s.validateToken(tok); err == nil {
			t.Error("alg=none token should be rejected")
		}
	})
}
