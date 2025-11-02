package adminapi

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/migadu/sora/logger"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// Server represents the HTTP API server
type Server struct {
	name               string
	addr               string
	apiKey             string
	allowedHosts       []string
	rdb                *resilient.ResilientDatabase
	cache              *cache.Cache
	uploader           *uploader.UploadWorker
	storage            *storage.S3Storage
	relayQueue         delivery.RelayQueue // Global relay queue for mail delivery
	server             *http.Server
	tls                bool
	tlsConfig          *tls.Config // TLS config from manager (takes precedence) or nil
	tlsCertFile        string
	tlsKeyFile         string
	tlsVerify          bool
	hostname           string
	ftsRetention       time.Duration
	affinityManager    AffinityManager
	validBackends      map[string][]string
	connectionTrackers map[string]*proxy.ConnectionTracker // protocol -> tracker
}

// ServerOptions holds configuration options for the HTTP API server
type ServerOptions struct {
	Name               string
	Addr               string
	APIKey             string
	AllowedHosts       []string
	Cache              *cache.Cache
	Uploader           *uploader.UploadWorker
	Storage            *storage.S3Storage
	RelayQueue         delivery.RelayQueue // Global relay queue for mail delivery
	TLS                bool
	TLSConfig          *tls.Config // TLS config from manager (takes precedence over cert files)
	TLSCertFile        string
	TLSKeyFile         string
	TLSVerify          bool
	Hostname           string
	FTSRetention       time.Duration
	AffinityManager    AffinityManager
	ValidBackends      map[string][]string                 // Map of protocol -> valid backend addresses
	ConnectionTrackers map[string]*proxy.ConnectionTracker // protocol -> tracker (for gossip-based kick)
}

// AffinityManager interface for managing user-to-backend affinity
type AffinityManager interface {
	GetBackend(username, protocol string) (string, bool)
	SetBackend(username, backend, protocol string)
	DeleteBackend(username, protocol string)
}

// New creates a new HTTP API server
func New(rdb *resilient.ResilientDatabase, options ServerOptions) (*Server, error) {
	if options.APIKey == "" {
		return nil, fmt.Errorf("API key is required for HTTP API server")
	}

	// Validate TLS configuration
	if options.TLS {
		// If TLSConfig is provided (from manager), use it. Otherwise require cert files.
		if options.TLSConfig == nil {
			if options.TLSCertFile == "" || options.TLSKeyFile == "" {
				return nil, fmt.Errorf("TLS certificate and key files are required when TLS is enabled (or use TLS manager)")
			}
		}
	}

	s := &Server{
		name:               options.Name,
		addr:               options.Addr,
		apiKey:             options.APIKey,
		allowedHosts:       options.AllowedHosts,
		rdb:                rdb,
		cache:              options.Cache,
		uploader:           options.Uploader,
		storage:            options.Storage,
		relayQueue:         options.RelayQueue,
		tls:                options.TLS,
		tlsConfig:          options.TLSConfig,
		tlsCertFile:        options.TLSCertFile,
		tlsKeyFile:         options.TLSKeyFile,
		tlsVerify:          options.TLSVerify,
		hostname:           options.Hostname,
		ftsRetention:       options.FTSRetention,
		affinityManager:    options.AffinityManager,
		validBackends:      options.ValidBackends,
		connectionTrackers: options.ConnectionTrackers,
	}

	return s, nil
}

// Start starts the HTTP API server
func Start(ctx context.Context, rdb *resilient.ResilientDatabase, options ServerOptions, errChan chan error) {
	server, err := New(rdb, options)
	if err != nil {
		errChan <- fmt.Errorf("failed to create HTTP API server: %w", err)
		return
	}

	protocol := "HTTP"
	if options.TLS {
		protocol = "HTTPS"
	}
	serverName := options.Name
	if serverName == "" {
		serverName = "default"
	}
	logger.Info("HTTP API: Starting server", "name", serverName, "protocol", protocol, "addr", options.Addr)
	if err := server.start(ctx); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		errChan <- fmt.Errorf("HTTP API server failed: %w", err)
	}
}

// start initializes and starts the HTTP server
func (s *Server) start(ctx context.Context) error {
	router := s.setupRoutes()

	s.server = &http.Server{
		Addr:    s.addr,
		Handler: router,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		logger.Info("HTTP API: Shutting down server", "name", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("HTTP API: Error shutting down server", "name", s.name, "error", err)
		}
	}()

	// Start server with or without TLS
	if s.tls {
		// Use TLS config from manager if provided, otherwise create one for static certs
		var tlsConfig *tls.Config
		if s.tlsConfig != nil {
			// Clone the manager's TLS config
			tlsConfig = s.tlsConfig.Clone()
		} else {
			// Create new TLS config for static certificates
			tlsConfig = &tls.Config{
				Renegotiation: tls.RenegotiateNever,
			}
		}

		// Apply client verification settings
		if s.tlsVerify {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.NoClientCert
		}
		s.server.TLSConfig = tlsConfig

		// If using TLS manager (tlsConfig from manager), pass empty cert files
		// The GetCertificate callback in the config will handle certificate retrieval
		if s.tlsConfig != nil {
			return s.server.ListenAndServeTLS("", "")
		}
		// Otherwise use static certificate files
		return s.server.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
	}
	return s.server.ListenAndServe()
}

// setupRoutes configures all HTTP routes and middleware
func (s *Server) setupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Account management routes
	mux.HandleFunc("/admin/accounts", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":  s.handleListAccounts,
		"POST": s.handleCreateAccount,
	}))
	mux.HandleFunc("/admin/accounts/", s.handleAccountOperations)

	// Credential management routes
	mux.HandleFunc("/admin/credentials/", s.handleCredentialOperations)

	// Connection management routes
	mux.HandleFunc("/admin/connections", routeHandler("GET", s.handleListConnections))
	mux.HandleFunc("/admin/connections/stats", routeHandler("GET", s.handleConnectionStats))
	mux.HandleFunc("/admin/connections/kick", routeHandler("POST", s.handleKickConnections))
	mux.HandleFunc("/admin/connections/user/", routeHandler("GET", s.handleGetUserConnections))

	// Cache management routes
	mux.HandleFunc("/admin/cache/stats", routeHandler("GET", s.handleCacheStats))
	mux.HandleFunc("/admin/cache/metrics", routeHandler("GET", s.handleCacheMetrics))
	mux.HandleFunc("/admin/cache/purge", routeHandler("POST", s.handleCachePurge))

	// Uploader routes
	mux.HandleFunc("/admin/uploader/status", routeHandler("GET", s.handleUploaderStatus))
	mux.HandleFunc("/admin/uploader/failed", routeHandler("GET", s.handleFailedUploads))

	// Authentication statistics routes
	mux.HandleFunc("/admin/auth/stats", routeHandler("GET", s.handleAuthStats))

	// Health monitoring routes
	mux.HandleFunc("/admin/health/overview", routeHandler("GET", s.handleHealthOverview))
	mux.HandleFunc("/admin/health/servers/", s.handleHealthOperations)

	// System configuration and status routes
	mux.HandleFunc("/admin/config", routeHandler("GET", s.handleConfigInfo))

	// Mail delivery route
	mux.HandleFunc("/admin/mail/deliver", routeHandler("POST", s.handleDeliverMail))

	// ACL management routes
	mux.HandleFunc("/admin/mailboxes/acl/grant", routeHandler("POST", s.handleACLGrant))
	mux.HandleFunc("/admin/mailboxes/acl/revoke", routeHandler("POST", s.handleACLRevoke))
	mux.HandleFunc("/admin/mailboxes/acl", routeHandler("GET", s.handleACLList))

	// Affinity management routes
	mux.HandleFunc("/admin/affinity", multiMethodHandler(map[string]http.HandlerFunc{
		"GET":    s.handleAffinityGet,
		"POST":   s.handleAffinitySet,
		"DELETE": s.handleAffinityDelete,
	}))
	mux.HandleFunc("/admin/affinity/list", routeHandler("GET", s.handleAffinityList))

	// Wrap with middleware (in reverse order - last applied is outermost)
	handler := s.loggingMiddleware(mux)
	handler = s.allowedHostsMiddleware(handler)
	handler = s.authMiddleware(handler)

	return handler
}

// handleAccountOperations routes account-related operations
func (s *Server) handleAccountOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for message-related operations first (before checking for account /restore)
	if strings.Contains(path, "/messages/deleted") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListDeletedMessages(w, r)
		return
	}
	if strings.Contains(path, "/messages/restore") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRestoreMessages(w, r)
		return
	}

	// Check for account-level sub-operations
	if strings.HasSuffix(path, "/restore") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleRestoreAccount(w, r)
		return
	}
	if strings.HasSuffix(path, "/exists") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleAccountExists(w, r)
		return
	}
	if strings.Contains(path, "/credentials") {
		switch r.Method {
		case "GET":
			s.handleListCredentials(w, r)
		case "POST":
			s.handleAddCredential(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	// Otherwise it's a basic account operation
	switch r.Method {
	case "GET":
		s.handleGetAccount(w, r)
	case "PUT":
		s.handleUpdateAccount(w, r)
	case "DELETE":
		s.handleDeleteAccount(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCredentialOperations routes credential operations
func (s *Server) handleCredentialOperations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.handleGetCredential(w, r)
	case "DELETE":
		s.handleDeleteCredential(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHealthOperations routes health monitoring operations
func (s *Server) handleHealthOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check if it's a component-specific operation
	if strings.Contains(path, "/components/") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleHealthStatusByComponent(w, r)
		return
	}

	// Otherwise it's a host-level operation
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleHealthStatusByHost(w, r)
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger.Debug("HTTP API: Request", "name", s.name, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		next.ServeHTTP(w, r)
		logger.Debug("HTTP API: Request completed", "name", s.name, "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (s *Server) allowedHostsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(s.allowedHosts) == 0 {
			// No restrictions, allow all hosts
			next.ServeHTTP(w, r)
			return
		}

		clientIP := getClientIP(r)

		allowed := false
		for _, allowedHost := range s.allowedHosts {
			if allowedHost == clientIP {
				allowed = true
				break
			}
			// Check CIDR blocks
			if strings.Contains(allowedHost, "/") {
				if _, cidr, err := net.ParseCIDR(allowedHost); err == nil {
					if ip := net.ParseIP(clientIP); ip != nil {
						if cidr.Contains(ip) {
							allowed = true
							break
						}
					}
				}
			}
		}

		if !allowed {
			s.writeError(w, http.StatusForbidden, "Host not allowed")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			s.writeError(w, http.StatusUnauthorized, "Authorization header must be 'Bearer <token>'")
			return
		}

		if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.apiKey)) != 1 {
			s.writeError(w, http.StatusForbidden, "Invalid API key")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Utility functions

func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Try X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Warn("HTTP API: Error encoding JSON response", "name", s.name, "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// Request/Response types

type CreateAccountRequest struct {
	Email        string                 `json:"email"`
	Password     string                 `json:"password"`
	PasswordHash string                 `json:"password_hash"`
	Credentials  []CreateCredentialSpec `json:"credentials,omitempty"`
}

type CreateCredentialSpec struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
	IsPrimary    bool   `json:"is_primary"`
	HashType     string `json:"hash_type"`
}

type UpdateAccountRequest struct {
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
}

type AddCredentialRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
}

type KickConnectionsRequest struct {
	UserEmail  string `json:"user_email,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	ServerAddr string `json:"server_addr,omitempty"`
	ClientAddr string `json:"client_addr,omitempty"`
}

// Import/Export request types removed - these operations are not suitable
// for HTTP API as they are long-running processes

// Handler functions

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req CreateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ctx := r.Context()

	// Check if credentials array is provided for multi-credential creation
	if len(req.Credentials) > 0 {
		// Multi-credential creation
		if req.Email != "" || req.Password != "" || req.PasswordHash != "" {
			s.writeError(w, http.StatusBadRequest, "Cannot specify email, password, or password_hash when using credentials array")
			return
		}

		// Convert API types to database types
		dbCredentials := make([]db.CredentialSpec, len(req.Credentials))
		for i, cred := range req.Credentials {
			if cred.Email == "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: email is required", i+1))
				return
			}
			if cred.Password == "" && cred.PasswordHash == "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: either password or password_hash is required", i+1))
				return
			}
			if cred.Password != "" && cred.PasswordHash != "" {
				s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Credential %d: cannot specify both password and password_hash", i+1))
				return
			}

			hashType := cred.HashType
			if hashType == "" {
				hashType = "bcrypt"
			}

			dbCredentials[i] = db.CredentialSpec{
				Email:        cred.Email,
				Password:     cred.Password,
				PasswordHash: cred.PasswordHash,
				IsPrimary:    cred.IsPrimary,
				HashType:     hashType,
			}
		}

		// Create account with multiple credentials
		createReq := db.CreateAccountWithCredentialsRequest{
			Credentials: dbCredentials,
		}

		accountID, err := s.rdb.CreateAccountWithCredentialsWithRetry(ctx, createReq)
		if err != nil {
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				s.writeError(w, http.StatusConflict, "One or more email addresses already exist")
				return
			}
			logger.Warn("HTTP API: Error creating account with credentials", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to create account with credentials")
			return
		}

		// Prepare response with all created credentials
		var createdCredentials []string
		for _, cred := range req.Credentials {
			createdCredentials = append(createdCredentials, cred.Email)
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"account_id":  accountID,
			"credentials": createdCredentials,
			"message":     "Account created successfully with multiple credentials",
		})
	} else {
		if req.Email == "" {
			s.writeError(w, http.StatusBadRequest, "Email is required")
			return
		}

		if req.Password == "" && req.PasswordHash == "" {
			s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
			return
		}

		if req.Password != "" && req.PasswordHash != "" {
			s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
			return
		}

		// Create account using the existing single-credential method
		createReq := db.CreateAccountRequest{
			Email:        req.Email,
			Password:     req.Password,
			PasswordHash: req.PasswordHash,
			IsPrimary:    true,
			HashType:     "bcrypt",
		}

		err := s.rdb.CreateAccountWithRetry(ctx, createReq)
		if err != nil {
			if errors.Is(err, consts.ErrDBUniqueViolation) {
				s.writeError(w, http.StatusConflict, "Account already exists")
				return
			}
			logger.Warn("HTTP API: Error creating account", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to create account")
			return
		}

		// Get the created account ID
		accountID, err := s.rdb.GetAccountIDByAddressWithRetry(ctx, req.Email)
		if err != nil {
			logger.Warn("HTTP API: Error getting new account ID", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to retrieve new account ID")
			return
		}

		s.writeJSON(w, http.StatusCreated, map[string]any{
			"account_id": accountID,
			"email":      req.Email,
			"message":    "Account created successfully",
		})
	}
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accounts, err := s.rdb.ListAccountsWithRetry(ctx)
	if err != nil {
		logger.Warn("HTTP API: Error listing accounts", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing accounts")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"accounts": accounts,
		"total":    len(accounts),
	})
}

func (s *Server) handleAccountExists(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}/exists
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/exists")

	ctx := r.Context()

	exists, err := s.rdb.AccountExistsWithRetry(ctx, email)
	if err != nil {
		logger.Warn("HTTP API: Error checking account existence", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error checking account existence")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":  email,
		"exists": exists,
	})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}
	email := extractLastPathSegment(r.URL.Path)
	ctx := r.Context()

	accountDetails, err := s.rdb.GetAccountDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error getting account details", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get account details")
		return
	}

	s.writeJSON(w, http.StatusOK, accountDetails)
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Extract email from path: /admin/accounts/{email}
	email := extractLastPathSegment(r.URL.Path)

	var req UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Password == "" && req.PasswordHash == "" {
		s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
		return
	}

	if req.Password != "" && req.PasswordHash != "" {
		s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
		return
	}

	ctx := r.Context()

	// Update account using the database's method
	updateReq := db.UpdateAccountRequest{
		Email:        email,
		Password:     req.Password,
		PasswordHash: req.PasswordHash,
		HashType:     "bcrypt",
	}

	err := s.rdb.UpdateAccountWithRetry(ctx, updateReq)
	if err != nil {
		logger.Warn("HTTP API: Error updating account", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update account")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "Account updated successfully",
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}
	email := extractLastPathSegment(r.URL.Path)
	ctx := r.Context()

	err := s.rdb.DeleteAccountWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountAlreadyDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			logger.Warn("HTTP API: Error deleting account", "name", s.name, "email", email, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Error deleting account")
			return
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Account soft-deleted successfully. It will be permanently removed after the grace period.",
	})
}

func (s *Server) handleRestoreAccount(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}/restore
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/restore")
	ctx := r.Context()

	err := s.rdb.RestoreAccountWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountNotDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			logger.Warn("HTTP API: Error restoring account", "name", s.name, "email", email, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Error restoring account")
			return
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Account restored successfully.",
	})
}

func (s *Server) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Extract email from path: /admin/accounts/{email}/credentials
	primaryEmail := extractPathParam(r.URL.Path, "/admin/accounts/", "/credentials")

	var req AddCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Email == "" {
		s.writeError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.Password == "" && req.PasswordHash == "" {
		s.writeError(w, http.StatusBadRequest, "Either password or password_hash is required")
		return
	}

	if req.Password != "" && req.PasswordHash != "" {
		s.writeError(w, http.StatusBadRequest, "Cannot specify both password and password_hash")
		return
	}

	ctx := r.Context()

	// 1. Get the account ID for the primary email address in the path.
	accountID, err := s.rdb.GetAccountIDByAddressWithRetry(ctx, primaryEmail)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found for the specified primary email")
			return
		}
		logger.Warn("HTTP API: Error getting account ID", "name", s.name, "email", primaryEmail, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to find account")
		return
	}

	// 2. Add the new credential to the existing account.
	// This assumes a new database method `AddCredential` exists.
	addReq := db.AddCredentialRequest{
		AccountID:       accountID,
		NewEmail:        req.Email,
		NewPassword:     req.Password,
		NewPasswordHash: req.PasswordHash,
		NewHashType:     "bcrypt",
	}

	err = s.rdb.AddCredentialWithRetry(ctx, addReq)
	if err != nil {
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.writeError(w, http.StatusConflict, "Credential with this email already exists")
			return
		}
		logger.Warn("HTTP API: Error adding credential", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to add credential")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]any{
		"new_email": req.Email,
		"message":   "Credential added successfully",
	})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}/credentials
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/credentials")

	ctx := r.Context()

	credentials, err := s.rdb.ListCredentialsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error listing credentials", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list credentials")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":       email,
		"credentials": credentials,
		"count":       len(credentials),
	})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/credentials/{email}
	email := extractLastPathSegment(r.URL.Path)
	ctx := r.Context()

	// Get detailed credential information using the same logic as CLI
	credentialDetails, err := s.rdb.GetCredentialDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		logger.Warn("HTTP API: Error getting credential details", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get credential details")
		return
	}

	s.writeJSON(w, http.StatusOK, credentialDetails)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/credentials/{email}
	email := extractLastPathSegment(r.URL.Path)
	ctx := r.Context()

	err := s.rdb.DeleteCredentialWithRetry(ctx, email)
	if err != nil {
		// Check for specific user-facing errors from the DB layer
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrCannotDeleteLastCredential) || errors.Is(err, db.ErrCannotDeletePrimaryCredential) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Generic server error for other issues
		logger.Warn("HTTP API: Error deleting credential", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete credential")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":   email,
		"message": "Credential deleted successfully",
	})
}

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	if len(s.connectionTrackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"connections": []any{},
			"count":       0,
			"note":        "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	// Collect connections from all trackers
	allConnections := make([]map[string]any, 0)
	for protocol, tracker := range s.connectionTrackers {
		if tracker == nil {
			continue
		}
		conns := tracker.GetAllConnections()
		for _, connInfo := range conns {
			allConnections = append(allConnections, map[string]any{
				"protocol":    protocol,
				"account_id":  connInfo.AccountID,
				"local_count": connInfo.LocalCount,
				"total_count": connInfo.TotalCount,
				"last_update": connInfo.LastUpdate,
				"email":       connInfo.Username,
			})
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"connections": allConnections,
		"count":       len(allConnections),
		"source":      "in-memory connection tracker",
	})
}

func (s *Server) handleKickConnections(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var req KickConnectionsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	ctx := r.Context()

	// Require user email for gossip-based kick
	if req.UserEmail == "" {
		s.writeError(w, http.StatusBadRequest, "user_email is required for kick operation")
		return
	}

	// Get account ID from email
	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, req.UserEmail)
	if err != nil {
		logger.Warn("HTTP API: Error getting account ID", "name", s.name, "email", req.UserEmail, "error", err)
		s.writeError(w, http.StatusNotFound, "User not found")
		return
	}

	// Determine which protocols to kick
	protocols := []string{}
	if req.Protocol != "" {
		protocols = []string{req.Protocol}
	} else {
		// Kick all protocols if not specified
		for proto := range s.connectionTrackers {
			protocols = append(protocols, proto)
		}
	}

	if len(s.connectionTrackers) == 0 {
		// No connection trackers available (not running in cluster/proxy mode)
		logger.Debug("HTTP API: No connection trackers available - gossip-based kick requires cluster mode", "name", s.name)
		s.writeError(w, http.StatusServiceUnavailable, "Connection tracking not available (requires cluster mode)")
		return
	}

	// Kick user on all specified protocols
	kickedProtocols := []string{}
	for _, protocol := range protocols {
		tracker := s.connectionTrackers[protocol]
		if tracker == nil {
			logger.Debug("HTTP API: No tracker for protocol", "name", s.name, "proto", protocol)
			continue
		}

		if err := tracker.KickUser(accountID, protocol); err != nil {
			logger.Warn("HTTP API: Error kicking user on protocol", "name", s.name, "email", req.UserEmail, "proto", protocol, "error", err)
			continue
		}

		kickedProtocols = append(kickedProtocols, protocol)
		logger.Debug("HTTP API: Kicked user on protocol", "name", s.name, "email", req.UserEmail, "account_id", accountID, "proto", protocol)
	}

	if len(kickedProtocols) == 0 {
		s.writeError(w, http.StatusInternalServerError, "Failed to kick user on any protocol")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":   "User kicked successfully via gossip protocol",
		"user":      req.UserEmail,
		"protocols": kickedProtocols,
		"note":      "Kick event broadcast to cluster. Connections will be terminated within seconds.",
	})
}

func (s *Server) handleConnectionStats(w http.ResponseWriter, r *http.Request) {
	if len(s.connectionTrackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"total_connections":       0,
			"connections_by_protocol": map[string]int{},
			"note":                    "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	// Aggregate stats from all trackers
	totalConnections := 0
	byProtocol := make(map[string]int)

	for protocol, tracker := range s.connectionTrackers {
		if tracker == nil {
			continue
		}
		conns := tracker.GetAllConnections()
		count := len(conns)
		totalConnections += count
		byProtocol[protocol] = count
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"total_connections":       totalConnections,
		"connections_by_protocol": byProtocol,
		"source":                  "in-memory connection tracker",
	})
}

func (s *Server) handleGetUserConnections(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/connections/user/{email}
	email := extractLastPathSegment(r.URL.Path)

	if len(s.connectionTrackers) == 0 {
		// No connection trackers available
		s.writeJSON(w, http.StatusOK, map[string]any{
			"email":       email,
			"connections": []any{},
			"count":       0,
			"note":        "Connection tracking not available (requires cluster mode or backend server with tracking enabled)",
		})
		return
	}

	ctx := r.Context()

	// Get account ID from email
	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		logger.Warn("HTTP API: Error getting account ID", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusNotFound, "User not found")
		return
	}

	// Collect connections for this user from all trackers
	userConnections := make([]map[string]any, 0)
	for protocol, tracker := range s.connectionTrackers {
		if tracker == nil {
			continue
		}
		conns := tracker.GetAllConnections()
		for _, connInfo := range conns {
			if connInfo.AccountID == accountID {
				userConnections = append(userConnections, map[string]any{
					"protocol":    protocol,
					"account_id":  accountID,
					"email":       connInfo.Username,
					"local_count": connInfo.LocalCount,
					"total_count": connInfo.TotalCount,
					"last_update": connInfo.LastUpdate,
				})
			}
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":       email,
		"connections": userConnections,
		"count":       len(userConnections),
		"source":      "in-memory connection tracker",
	})
}

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats")
		return
	}
	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleCacheMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	instanceID := r.URL.Query().Get("instance_id")
	sinceParam := r.URL.Query().Get("since")
	limitParam := r.URL.Query().Get("limit")
	latest := r.URL.Query().Get("latest") == "true"

	limit := 100
	if limitParam != "" {
		if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
			limit = l
		}
	}

	if latest {
		// Get latest metrics
		metrics, err := s.rdb.GetLatestCacheMetricsWithRetry(ctx)
		if err != nil {
			logger.Warn("HTTP API: Error getting latest cache metrics", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get latest cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"metrics": metrics,
			"count":   len(metrics),
		})
	} else {
		// Get historical metrics
		var since time.Time
		if sinceParam != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceParam)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "Invalid since parameter format (use RFC3339)")
				return
			}
		} else {
			since = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
		}

		metrics, err := s.rdb.GetCacheMetricsWithRetry(ctx, instanceID, since, limit)
		if err != nil {
			logger.Warn("HTTP API: Error getting cache metrics", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"metrics":     metrics,
			"count":       len(metrics),
			"instance_id": instanceID,
			"since":       since,
		})
	}
}

func (s *Server) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	ctx := r.Context()

	// Get stats before purge
	statsBefore, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats before purge", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats before purge")
		return
	}

	// Purge cache
	err = s.cache.PurgeAll(ctx)
	if err != nil {
		logger.Warn("HTTP API: Error purging cache", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to purge cache")
		return
	}

	// Get stats after purge
	statsAfter, err := s.cache.GetStats()
	if err != nil {
		logger.Warn("HTTP API: Error getting cache stats after purge", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats after purge")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"message":      "Cache purged successfully",
		"stats_before": statsBefore,
		"stats_after":  statsAfter,
	})
}

func (s *Server) handleHealthOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get query parameter for hostname, default to empty for system-wide
	hostname := r.URL.Query().Get("hostname")

	overview, err := s.rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		logger.Warn("HTTP API: Error getting health overview", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health overview")
		return
	}

	s.writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleHealthStatusByHost(w http.ResponseWriter, r *http.Request) {
	// Extract hostname from path: /admin/health/servers/{hostname}
	hostname := extractPathParam(r.URL.Path, "/admin/health/servers/", "")

	ctx := r.Context()

	statuses, err := s.rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
	if err != nil {
		logger.Warn("HTTP API: Error getting health statuses for host", "name", s.name, "hostname", hostname, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health statuses for host")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"hostname": hostname,
		"statuses": statuses,
		"count":    len(statuses),
	})
}

func (s *Server) handleHealthStatusByComponent(w http.ResponseWriter, r *http.Request) {
	// Extract hostname and component from path: /admin/health/servers/{hostname}/components/{component}
	path := r.URL.Path
	// Remove prefix to get "{hostname}/components/{component}"
	remaining := strings.TrimPrefix(path, "/admin/health/servers/")
	// Split by "/components/"
	parts := strings.Split(remaining, "/components/")
	if len(parts) != 2 {
		s.writeError(w, http.StatusBadRequest, "Invalid path format")
		return
	}
	hostname := parts[0]
	component := parts[1]

	ctx := r.Context()

	// Parse query parameters for history
	showHistory := r.URL.Query().Get("history") == "true"
	sinceParam := r.URL.Query().Get("since")
	limitParam := r.URL.Query().Get("limit")

	if showHistory {
		// Get historical health status
		var since time.Time
		if sinceParam != "" {
			var err error
			since, err = time.Parse(time.RFC3339, sinceParam)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "Invalid since parameter format (use RFC3339)")
				return
			}
		} else {
			since = time.Now().Add(-24 * time.Hour) // Default to last 24 hours
		}

		limit := 100
		if limitParam != "" {
			if l, err := strconv.Atoi(limitParam); err == nil && l > 0 {
				limit = l
			}
		}

		history, err := s.rdb.GetHealthHistoryWithRetry(ctx, hostname, component, since, limit)
		if err != nil {
			logger.Warn("HTTP API: Error getting health history", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get health history")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"hostname":  hostname,
			"component": component,
			"history":   history,
			"count":     len(history),
			"since":     since,
		})
	} else {
		// Get current health status
		status, err := s.rdb.GetHealthStatusWithRetry(ctx, hostname, component)
		if err != nil {
			// This could be a normal "not found" case, so don't log as a server error
			s.writeError(w, http.StatusNotFound, "Health status not found")
			return
		}
		s.writeJSON(w, http.StatusOK, status)
	}
}

func (s *Server) handleUploaderStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	showFailedStr := r.URL.Query().Get("show_failed")
	maxAttemptsStr := r.URL.Query().Get("max_attempts")

	maxAttempts := 5 // Default value
	if maxAttemptsStr != "" {
		if ma, err := strconv.Atoi(maxAttemptsStr); err == nil && ma > 0 {
			maxAttempts = ma
		}
	}

	// Get uploader stats
	stats, err := s.rdb.GetUploaderStatsWithRetry(ctx, maxAttempts)
	if err != nil {
		logger.Warn("HTTP API: Error getting uploader stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get uploader stats")
		return
	}

	response := map[string]any{
		"stats": stats,
	}

	// Include failed uploads if requested
	if showFailedStr == "true" {
		failedLimitStr := r.URL.Query().Get("failed_limit")
		failedLimit := 10
		if failedLimitStr != "" {
			if fl, err := strconv.Atoi(failedLimitStr); err == nil && fl > 0 {
				failedLimit = fl
			}
		}

		failedUploads, err := s.rdb.GetFailedUploadsWithRetry(ctx, maxAttempts, failedLimit)
		if err != nil {
			logger.Warn("HTTP API: Error getting failed uploads", "name", s.name, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get failed uploads")
			return
		}

		response["failed_uploads"] = failedUploads
		response["failed_count"] = len(failedUploads)
	}

	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleFailedUploads(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	maxAttemptsStr := r.URL.Query().Get("max_attempts")
	limitStr := r.URL.Query().Get("limit")

	maxAttempts := 5 // Default value
	if maxAttemptsStr != "" {
		if ma, err := strconv.Atoi(maxAttemptsStr); err == nil && ma > 0 {
			maxAttempts = ma
		}
	}

	limit := 50 // Default value
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	failedUploads, err := s.rdb.GetFailedUploadsWithRetry(ctx, maxAttempts, limit)
	if err != nil {
		logger.Warn("HTTP API: Error getting failed uploads", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get failed uploads")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"failed_uploads": failedUploads,
		"count":          len(failedUploads),
		"max_attempts":   maxAttempts,
		"limit":          limit,
	})
}

func (s *Server) handleAuthStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	windowParam := r.URL.Query().Get("window")

	windowDuration := 24 * time.Hour // Default to last 24 hours
	if windowParam != "" {
		var err error
		windowDuration, err = time.ParseDuration(windowParam)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid window duration: %v", err))
			return
		}
	}

	stats, err := s.rdb.GetAuthAttemptsStatsWithRetry(ctx, windowDuration)
	if err != nil {
		logger.Warn("HTTP API: Error getting auth stats", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get auth stats")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"stats":          stats,
		"window":         windowDuration.String(),
		"window_seconds": int64(windowDuration.Seconds()),
	})
}

// Message restoration handlers

func (s *Server) handleListDeletedMessages(w http.ResponseWriter, r *http.Request) {
	// Extract email from path: /admin/accounts/{email}/messages/deleted
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/messages/deleted")
	email, _ = url.QueryUnescape(email) // Decode URL-encoded characters
	ctx := r.Context()

	// Parse query parameters
	mailboxPath := r.URL.Query().Get("mailbox")
	since := r.URL.Query().Get("since")
	until := r.URL.Query().Get("until")
	limitStr := r.URL.Query().Get("limit")

	// Build parameters
	params := db.ListDeletedMessagesParams{
		Email: email,
		Limit: 100, // default limit
	}

	if mailboxPath != "" {
		params.MailboxPath = &mailboxPath
	}

	if since != "" {
		sinceTime, err := parseTimeParam(since)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid since parameter: %v", err))
			return
		}
		params.Since = &sinceTime
	}

	if until != "" {
		untilTime, err := parseTimeParam(until)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid until parameter: %v", err))
			return
		}
		params.Until = &untilTime
	}

	if limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 0 {
			s.writeError(w, http.StatusBadRequest, "Invalid limit parameter")
			return
		}
		params.Limit = limit
	}

	// List deleted messages
	messages, err := s.rdb.ListDeletedMessagesWithRetry(ctx, params)
	if err != nil {
		if strings.Contains(err.Error(), "account not found") {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error listing deleted messages", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing deleted messages")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":    email,
		"messages": messages,
		"total":    len(messages),
	})
}

func (s *Server) handleRestoreMessages(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	// Extract email from path: /admin/accounts/{email}/messages/restore
	email := extractPathParam(r.URL.Path, "/admin/accounts/", "/messages/restore")
	email, _ = url.QueryUnescape(email) // Decode URL-encoded characters
	ctx := r.Context()

	var req struct {
		MessageIDs  []int64 `json:"message_ids,omitempty"`
		MailboxPath *string `json:"mailbox,omitempty"`
		Since       *string `json:"since,omitempty"`
		Until       *string `json:"until,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	// Validate that at least one filter is provided
	hasFilter := len(req.MessageIDs) > 0 || req.MailboxPath != nil || req.Since != nil || req.Until != nil
	if !hasFilter {
		s.writeError(w, http.StatusBadRequest, "At least one filter is required (message_ids, mailbox, since, or until)")
		return
	}

	// Build parameters
	params := db.RestoreMessagesParams{
		Email:       email,
		MessageIDs:  req.MessageIDs,
		MailboxPath: req.MailboxPath,
	}

	if req.Since != nil {
		sinceTime, err := parseTimeParam(*req.Since)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid since parameter: %v", err))
			return
		}
		params.Since = &sinceTime
	}

	if req.Until != nil {
		untilTime, err := parseTimeParam(*req.Until)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid until parameter: %v", err))
			return
		}
		params.Until = &untilTime
	}

	// Restore messages
	count, err := s.rdb.RestoreMessagesWithRetry(ctx, params)
	if err != nil {
		if strings.Contains(err.Error(), "account not found") {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		logger.Warn("HTTP API: Error restoring messages", "name", s.name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error restoring messages")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":    email,
		"restored": count,
		"message":  fmt.Sprintf("Successfully restored %d message(s)", count),
	})
}

// parseTimeParam parses a time string in YYYY-MM-DD or RFC3339 format
func parseTimeParam(value string) (time.Time, error) {
	// Try parsing as YYYY-MM-DD first
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid date format (use YYYY-MM-DD or RFC3339)")
}

func (s *Server) handleConfigInfo(w http.ResponseWriter, r *http.Request) {
	// Return basic configuration information (non-sensitive)
	// This is useful for debugging and system information

	s.writeJSON(w, http.StatusOK, map[string]any{
		"server_type": "sora-http-api",
		"features_enabled": map[string]bool{
			"account_management":    true,
			"connection_management": true,
			"cache_management":      s.cache != nil,
			"health_monitoring":     true,
			"auth_statistics":       true,
			"uploader_monitoring":   true,
			"message_restoration":   true,
		},
		"endpoints": map[string][]string{
			"account_management": {
				"POST /admin/accounts",
				"GET /admin/accounts",
				"GET /admin/accounts/{email}",
				"PUT /admin/accounts/{email}",
				"DELETE /admin/accounts/{email}",
				"POST /admin/accounts/{email}/restore",
				"GET /admin/accounts/{email}/exists",
				"POST /admin/accounts/{email}/credentials",
				"GET /admin/accounts/{email}/credentials",
			},
			"credential_management": {
				"GET /admin/credentials/{email}",
			},
			"message_restoration": {
				"GET /admin/accounts/{email}/messages/deleted",
				"POST /admin/accounts/{email}/messages/restore",
			},
			"connection_management": {
				"GET /admin/connections",
				"GET /admin/connections/stats",
				"POST /admin/connections/kick",
				"GET /admin/connections/user/{email}",
			},
			"cache_management": {
				"GET /admin/cache/stats",
				"GET /admin/cache/metrics",
				"POST /admin/cache/purge",
			},
			"health_monitoring": {
				"GET /admin/health/overview",
				"GET /admin/health/servers/{hostname}",
				"GET /admin/health/servers/{hostname}/components/{component}",
			},
			"uploader_monitoring": {
				"GET /admin/uploader/status",
				"GET /admin/uploader/failed",
			},
			"system_information": {
				"GET /admin/auth/stats",
				"GET /admin/config",
			},
		},
	})
}
