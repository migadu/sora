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
	// AuthEpoch is the credential's password epoch (credentials.updated_at, unix
	// seconds) at the time the token was issued. The refresh endpoint compares it
	// against the current epoch so a password change invalidates the session; a
	// missing/zero value (e.g. a token issued before this field existed) is treated
	// as stale and forces re-login. See db.GetCredentialEpoch.
	AuthEpoch int64 `json:"auth_epoch,omitempty"`
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

	// Reject empty passwords immediately
	if req.Password == "" {
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Apply progressive authentication delay BEFORE any other checks
	if err := server.ApplyAuthenticationDelay(ctx, s.authLimiter, remoteAddr, "USER-API-LOGIN"); err != nil {
		if errors.Is(err, server.ErrDelayQueueFull) {
			// Delay queue full - reject immediately to prevent goroutine exhaustion
			logger.Info("User API: Delay queue full, rejecting connection", "email", req.Email, "remote", remoteAddr)
			s.writeError(w, http.StatusTooManyRequests, "Too many concurrent authentication attempts. Please try again later.")
			return
		}
		// Context cancelled or other error
		s.writeError(w, http.StatusServiceUnavailable, "Service unavailable")
		return
	}

	var accountID int64
	var hashedPassword string
	var err error

	// Check cache first (if enabled)
	if s.authCache != nil {
		cachedAccountID, found, cacheErr := s.authCache.Authenticate(req.Email, req.Password)
		if cacheErr != nil {
			// Cached failure (same wrong password)
			logger.Debug("User API: Cache hit - authentication failed", "name", s.name, "email", req.Email)
			if s.authLimiter != nil {
				s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, false)
			}
			s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		if found {
			// Cache hit - successful authentication
			logger.Debug("User API: Cache hit - using cached auth", "name", s.name, "email", req.Email, "account_id", cachedAccountID)
			accountID = cachedAccountID
			if s.authLimiter != nil {
				s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, true)
			}
			// Skip database lookup - use cached account ID
			goto generateToken
		}
		// Cache miss or revalidation needed - fall through to full auth
		logger.Debug("User API: Cache miss - performing full authentication", "name", s.name, "email", req.Email)
	}

	// Check authentication rate limiting (after cache check to avoid delays for cached hits)
	if s.authLimiter != nil {
		if err := s.authLimiter.CanAttemptAuth(ctx, remoteAddr, req.Email); err != nil {
			logger.Debug("User API: Login rate limited", "name", s.name, "ip", clientIP, "email", req.Email, "error", err)
			s.writeError(w, http.StatusTooManyRequests, "Too many authentication attempts. Please try again later.")
			return
		}
	}

	// Authenticate user (full database lookup)
	accountID, hashedPassword, err = s.rdb.GetCredentialForAuthWithRetry(ctx, req.Email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			// Cache negative result if cache enabled (result=1 for user not found)
			if s.authCache != nil {
				s.authCache.SetFailure(req.Email, 1, req.Password)
			}
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
		// Cache negative result if cache enabled (result=2 for invalid password)
		if s.authCache != nil {
			s.authCache.SetFailure(req.Email, 2, req.Password)
		}
		// Record failed attempt
		if s.authLimiter != nil {
			s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, false)
		}
		s.writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Cache positive result if cache enabled
	if s.authCache != nil {
		s.authCache.SetSuccess(req.Email, accountID, hashedPassword, req.Password)
	}

	// Record successful attempt
	if s.authLimiter != nil {
		s.authLimiter.RecordAuthAttempt(ctx, remoteAddr, req.Email, true)
	}

generateToken:

	// Bind the token to the current password epoch so a later password change or
	// account deletion invalidates it at refresh time (the cache fast-path above
	// can skip the DB, so fetch it here for both paths).
	_, epoch, err := s.rdb.GetCredentialEpochWithRetry(ctx, req.Email)
	if err != nil {
		logger.Warn("HTTP Mail API: Error fetching credential epoch", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}

	// Generate JWT token
	token, expiresAt, err := s.generateToken(req.Email, accountID, epoch.Unix())
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

	ctx := r.Context()

	// Refresh-gate: re-validate account state before renewing. A stateless JWT is
	// otherwise non-revocable, so refresh is where we cut off sessions for accounts
	// that have been deleted/disabled or had their password changed since the token
	// was issued. This bounds a leaked token to at most one token_duration window.
	accountID, epoch, err := s.rdb.GetCredentialEpochWithRetry(ctx, claims.Email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			// Account soft-deleted or credential removed since the token was issued.
			logger.Info("HTTP Mail API: Refusing refresh for deleted/unknown account", "name", s.name, "email", claims.Email)
			s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
			return
		}
		logger.Warn("HTTP Mail API: Error revalidating account on refresh", "name", s.name, "error", err)
		s.writeError(w, http.StatusServiceUnavailable, "Service unavailable")
		return
	}
	if claims.AuthEpoch < epoch.Unix() {
		// Password changed after this token was issued (or the token predates the
		// auth_epoch claim) — force a fresh login instead of renewing.
		logger.Info("HTTP Mail API: Refusing refresh for stale token (password changed)", "name", s.name, "email", claims.Email)
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	// Generate new token with extended expiration, carrying the current epoch.
	newToken, expiresAt, err := s.generateToken(claims.Email, accountID, epoch.Unix())
	if err != nil {
		logger.Warn("HTTP Mail API: Error generating refresh token", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Token generation failed")
		return
	}

	response := LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt.Unix(),
		Email:     claims.Email,
		AccountID: accountID,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// generateToken creates a new JWT token for the user. authEpoch binds the token
// to the credential's password version (see JWTClaims.AuthEpoch) so a later
// password change can invalidate it on refresh.
func (s *Server) generateToken(email string, accountID int64, authEpoch int64) (string, time.Time, error) {
	expiresAt := time.Now().Add(s.tokenDuration)

	claims := JWTClaims{
		Email:     email,
		AccountID: accountID,
		AuthEpoch: authEpoch,
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
	// Pin the algorithm to HS256 (rejects alg=none / key-confusion), require an exp
	// claim, and enforce the issuer we sign tokens with (when configured).
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	}
	if s.tokenIssuer != "" {
		opts = append(opts, jwt.WithIssuer(s.tokenIssuer))
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	}, opts...)

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
		// Validate JWT token from Authorization header
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
