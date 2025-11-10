package userapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	contextKeyEmail     contextKey = "email"
	contextKeyAccountID contextKey = "accountID"
)

// JWTClaims represents the JWT token claims
type JWTClaims struct {
	Email     string `json:"email"`
	AccountID int64  `json:"account_id"`
	jwt.RegisteredClaims
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse represents the login response payload
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	Email     string `json:"email"`
	AccountID int64  `json:"account_id"`
}

// RefreshTokenRequest represents the token refresh request
type RefreshTokenRequest struct {
	Token string `json:"token"`
}

// handleLogin handles user authentication and JWT token generation
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	ctx := r.Context()

	// Get client IP for rate limiting
	clientIP := getClientIP(r)
	remoteAddr := &server.StringAddr{Addr: clientIP}

	// Apply progressive authentication delay BEFORE any other checks
	server.ApplyAuthenticationDelay(ctx, s.authLimiter, remoteAddr, "USER-API-LOGIN")

	// Check authentication rate limiting
	if s.authLimiter != nil {
		if err := s.authLimiter.CanAttemptAuth(ctx, remoteAddr, req.Email); err != nil {
			logger.Debug("User API: Login rate limited", "name", s.name, "ip", clientIP, "email", req.Email, "error", err)
			s.writeError(w, http.StatusTooManyRequests, "Too many authentication attempts. Please try again later.")
			return
		}
	}

	// Authenticate user
	accountID, hashedPassword, err := s.rdb.GetCredentialForAuthWithRetry(ctx, req.Email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			// Record failed attempt
			if s.authLimiter != nil {
				s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, false)
			}
			// Don't reveal whether user exists or not
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		logger.Warn("HTTP Mail API: Error retrieving credentials", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Verify password
	if err := db.VerifyPassword(hashedPassword, req.Password); err != nil {
		// Record failed attempt
		if s.authLimiter != nil {
			s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, false)
		}
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Record successful attempt
	if s.authLimiter != nil {
		s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, true)
	}

	// Generate JWT token
	token, expiresAt, err := s.generateToken(req.Email, accountID)
	if err != nil {
		logger.Warn("HTTP Mail API: Error generating token", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}

	response := LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Unix(),
		Email:     req.Email,
		AccountID: accountID,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleRefreshToken handles JWT token refresh
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		s.writeError(w, http.StatusBadRequest, "Token is required")
		return
	}

	// Parse and validate existing token
	claims, err := s.validateToken(req.Token)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Generate new token with extended expiration
	newToken, expiresAt, err := s.generateToken(claims.Email, claims.AccountID)
	if err != nil {
		logger.Warn("HTTP Mail API: Error generating refresh token", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}

	response := LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt.Unix(),
		Email:     claims.Email,
		AccountID: claims.AccountID,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// generateToken creates a new JWT token for the user
func (s *Server) generateToken(email string, accountID int64) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.tokenDuration)

	claims := JWTClaims{
		Email:     email,
		AccountID: accountID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.tokenIssuer,
			Subject:   email,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// validateToken validates a JWT token and returns the claims
func (s *Server) validateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// jwtAuthMiddleware validates JWT tokens and adds user context
func (s *Server) jwtAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request is from trusted proxy (via X-Forwarded-User header)
		if forwardedUser := r.Header.Get("X-Forwarded-User"); forwardedUser != "" {
			// Verify the request comes from a trusted network
			clientIP := getClientIP(r)
			if isIPAllowed(clientIP, s.allowedHosts) {
				// Trust the proxy's authentication - extract user info from headers
				forwardedAccountIDStr := r.Header.Get("X-Forwarded-User-ID")
				var accountID int64
				if forwardedAccountIDStr != "" {
					if id, err := fmt.Sscanf(forwardedAccountIDStr, "%d", &accountID); err == nil && id == 1 {
						// Successfully parsed account ID
						ctx := context.WithValue(r.Context(), contextKeyEmail, forwardedUser)
						ctx = context.WithValue(ctx, contextKeyAccountID, accountID)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
				// If we couldn't parse account ID, still trust the email
				ctx := context.WithValue(r.Context(), contextKeyEmail, forwardedUser)
				ctx = context.WithValue(ctx, contextKeyAccountID, int64(0)) // Unknown account ID
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Standard JWT authentication for direct clients (not from proxy)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header must be 'Bearer <token>'")
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := s.validateToken(tokenString)
		if err != nil {
			logger.Warn("HTTP Mail API: Token validation error", "name", s.name, "error", err)
			s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), contextKeyEmail, claims.Email)
		ctx = context.WithValue(ctx, contextKeyAccountID, claims.AccountID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getAccountIDFromContext retrieves the account ID from the request context
func getAccountIDFromContext(ctx context.Context) (int64, error) {
	accountID, ok := ctx.Value(contextKeyAccountID).(int64)
	if !ok {
		return 0, fmt.Errorf("account ID not found in context")
	}
	return accountID, nil
}
