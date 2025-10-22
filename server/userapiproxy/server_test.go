package userapiproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/pkg/resilient"
)

// TestValidateToken tests JWT token validation
func TestValidateToken(t *testing.T) {
	secret := "test-secret-key"

	// Create a test server
	server := &Server{
		jwtSecret: secret,
	}

	tests := []struct {
		name      string
		token     string
		shouldErr bool
		email     string
		accountID int64
	}{
		{
			name: "valid token",
			token: func() string {
				claims := JWTClaims{
					Email:     "test@example.com",
					AccountID: 123,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						Issuer:    "sora-test",
						Subject:   "test@example.com",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			}(),
			shouldErr: false,
			email:     "test@example.com",
			accountID: 123,
		},
		{
			name: "expired token",
			token: func() string {
				claims := JWTClaims{
					Email:     "test@example.com",
					AccountID: 123,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
						Issuer:    "sora-test",
						Subject:   "test@example.com",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte(secret))
				return tokenString
			}(),
			shouldErr: true,
		},
		{
			name: "invalid signature",
			token: func() string {
				claims := JWTClaims{
					Email:     "test@example.com",
					AccountID: 123,
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						Issuer:    "sora-test",
						Subject:   "test@example.com",
					},
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, _ := token.SignedString([]byte("wrong-secret"))
				return tokenString
			}(),
			shouldErr: true,
		},
		{
			name:      "malformed token",
			token:     "not.a.valid.jwt.token",
			shouldErr: true,
		},
		{
			name:      "empty token",
			token:     "",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := server.validateToken(tt.token)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if claims.Email != tt.email {
				t.Errorf("Expected email %s, got %s", tt.email, claims.Email)
			}

			if claims.AccountID != tt.accountID {
				t.Errorf("Expected account ID %d, got %d", tt.accountID, claims.AccountID)
			}
		})
	}
}

// TestExtractAndValidateToken tests token extraction from HTTP requests
func TestExtractAndValidateToken(t *testing.T) {
	secret := "test-secret-key"

	server := &Server{
		jwtSecret: secret,
	}

	// Create a valid token
	validToken := func() string {
		claims := JWTClaims{
			Email:     "test@example.com",
			AccountID: 123,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "sora-test",
				Subject:   "test@example.com",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte(secret))
		return tokenString
	}()

	tests := []struct {
		name       string
		authHeader string
		shouldErr  bool
		email      string
	}{
		{
			name:       "valid bearer token",
			authHeader: "Bearer " + validToken,
			shouldErr:  false,
			email:      "test@example.com",
		},
		{
			name:       "valid bearer token lowercase",
			authHeader: "bearer " + validToken,
			shouldErr:  false,
			email:      "test@example.com",
		},
		{
			name:       "missing authorization header",
			authHeader: "",
			shouldErr:  true,
		},
		{
			name:       "invalid format - no bearer prefix",
			authHeader: validToken,
			shouldErr:  true,
		},
		{
			name:       "invalid format - wrong prefix",
			authHeader: "Basic " + validToken,
			shouldErr:  true,
		},
		{
			name:       "malformed token",
			authHeader: "Bearer invalid.token",
			shouldErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			claims, err := server.extractAndValidateToken(req)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if claims.Email != tt.email {
				t.Errorf("Expected email %s, got %s", tt.email, claims.Email)
			}
		})
	}
}

// TestNewServerValidation tests server creation validation
func TestNewServerValidation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		opts      ServerOptions
		shouldErr bool
		errMsg    string
	}{
		{
			name: "valid configuration",
			opts: ServerOptions{
				Name:        "test-proxy",
				Addr:        ":8080",
				RemoteAddrs: []string{"backend1:8081"},
				RemotePort:  8081,
				JWTSecret:   "test-secret",
			},
			shouldErr: false,
		},
		{
			name: "missing remote addresses",
			opts: ServerOptions{
				Name:        "test-proxy",
				Addr:        ":8080",
				RemoteAddrs: []string{},
				JWTSecret:   "test-secret",
			},
			shouldErr: true,
			errMsg:    "no remote addresses",
		},
		{
			name: "missing JWT secret",
			opts: ServerOptions{
				Name:        "test-proxy",
				Addr:        ":8080",
				RemoteAddrs: []string{"backend1:8081"},
				JWTSecret:   "",
			},
			shouldErr: true,
			errMsg:    "JWT secret is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := New(ctx, &resilient.ResilientDatabase{}, tt.opts)

			if tt.shouldErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if server == nil {
				t.Errorf("Expected server to be created")
				return
			}

			if server.jwtSecret != tt.opts.JWTSecret {
				t.Errorf("Expected JWT secret %s, got %s", tt.opts.JWTSecret, server.jwtSecret)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			len(s) > len(substr)+1 && s[1:len(substr)+1] == substr))
}
