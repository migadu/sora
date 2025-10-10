package userapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
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

	// Authenticate user
	accountID, hashedPassword, err := s.rdb.GetCredentialForAuthWithRetry(ctx, req.Email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			// Don't reveal whether user exists or not
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		log.Printf("HTTP Mail API [%s] Error retrieving credentials: %v", s.name, err)
		s.writeError(w, http.StatusInternalServerError, "Authentication failed")
		return
	}

	// Verify password
	if err := db.VerifyPassword(hashedPassword, req.Password); err != nil {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Generate JWT token
	token, expiresAt, err := s.generateToken(req.Email, accountID)
	if err != nil {
		log.Printf("HTTP Mail API [%s] Error generating token: %v", s.name, err)
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
		log.Printf("HTTP Mail API [%s] Error generating refresh token: %v", s.name, err)
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
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
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
			log.Printf("HTTP Mail API [%s] Token validation error: %v", s.name, err)
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
