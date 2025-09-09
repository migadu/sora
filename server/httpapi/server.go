package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
)

// Server represents the HTTP API server
type Server struct {
	addr         string
	apiKey       string
	allowedHosts []string
	database     *db.Database
	cache        *cache.Cache
	server       *http.Server
	tls          bool
	tlsCertFile  string
	tlsKeyFile   string
}

// ServerOptions holds configuration options for the HTTP API server
type ServerOptions struct {
	Addr         string
	APIKey       string
	AllowedHosts []string
	Cache        *cache.Cache
	TLS          bool
	TLSCertFile  string
	TLSKeyFile   string
}

// New creates a new HTTP API server
func New(database *db.Database, options ServerOptions) (*Server, error) {
	if options.APIKey == "" {
		return nil, fmt.Errorf("API key is required for HTTP API server")
	}

	// Validate TLS configuration
	if options.TLS {
		if options.TLSCertFile == "" || options.TLSKeyFile == "" {
			return nil, fmt.Errorf("TLS certificate and key files are required when TLS is enabled")
		}
	}

	s := &Server{
		addr:         options.Addr,
		apiKey:       options.APIKey,
		allowedHosts: options.AllowedHosts,
		database:     database,
		cache:        options.Cache,
		tls:          options.TLS,
		tlsCertFile:  options.TLSCertFile,
		tlsKeyFile:   options.TLSKeyFile,
	}

	return s, nil
}

// Start starts the HTTP API server
func Start(ctx context.Context, database *db.Database, options ServerOptions, errChan chan error) {
	server, err := New(database, options)
	if err != nil {
		errChan <- fmt.Errorf("failed to create HTTP API server: %w", err)
		return
	}

	protocol := "HTTP"
	if options.TLS {
		protocol = "HTTPS"
	}
	log.Printf("Starting %s API server on %s", protocol, options.Addr)
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
		log.Println("Shutting down HTTP API server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down HTTP API server: %v", err)
		}
	}()

	// Start server with or without TLS
	if s.tls {
		return s.server.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
	}
	return s.server.ListenAndServe()
}

// setupRoutes configures all HTTP routes and middleware
func (s *Server) setupRoutes() *mux.Router {
	router := mux.NewRouter()

	// Add middleware
	router.Use(s.loggingMiddleware)
	router.Use(s.allowedHostsMiddleware)
	router.Use(s.authMiddleware)

	// API v1 routes
	v1 := router.PathPrefix("/api/v1").Subrouter()

	// Account management routes
	v1.HandleFunc("/accounts", s.handleCreateAccount).Methods("POST")
	v1.HandleFunc("/accounts", s.handleListAccounts).Methods("GET")
	v1.HandleFunc("/accounts/{email}", s.handleGetAccount).Methods("GET")
	v1.HandleFunc("/accounts/{email}", s.handleUpdateAccount).Methods("PUT")
	v1.HandleFunc("/accounts/{email}", s.handleDeleteAccount).Methods("DELETE")
	v1.HandleFunc("/accounts/{email}/restore", s.handleRestoreAccount).Methods("POST")
	v1.HandleFunc("/accounts/{email}/exists", s.handleAccountExists).Methods("GET")

	// Credential management routes
	v1.HandleFunc("/accounts/{email}/credentials", s.handleAddCredential).Methods("POST")
	v1.HandleFunc("/accounts/{email}/credentials", s.handleListCredentials).Methods("GET")
	v1.HandleFunc("/credentials/{email}", s.handleGetCredential).Methods("GET")
	v1.HandleFunc("/credentials/{email}", s.handleDeleteCredential).Methods("DELETE")

	// Connection management routes
	v1.HandleFunc("/connections", s.handleListConnections).Methods("GET")
	v1.HandleFunc("/connections/stats", s.handleConnectionStats).Methods("GET")
	v1.HandleFunc("/connections/kick", s.handleKickConnections).Methods("POST")
	v1.HandleFunc("/connections/user/{email}", s.handleGetUserConnections).Methods("GET")

	// Cache management routes
	v1.HandleFunc("/cache/stats", s.handleCacheStats).Methods("GET")
	v1.HandleFunc("/cache/metrics", s.handleCacheMetrics).Methods("GET")
	v1.HandleFunc("/cache/purge", s.handleCachePurge).Methods("POST")

	// Uploader routes
	v1.HandleFunc("/uploader/status", s.handleUploaderStatus).Methods("GET")
	v1.HandleFunc("/uploader/failed", s.handleFailedUploads).Methods("GET")

	// Authentication statistics routes
	v1.HandleFunc("/auth/stats", s.handleAuthStats).Methods("GET")

	// Note: Import/Export operations are not suitable for HTTP API
	// as they are long-running processes. Use sora-admin CLI for these operations.

	// System configuration routes
	v1.HandleFunc("/health/overview", s.handleHealthOverview).Methods("GET")
	v1.HandleFunc("/health/servers/{hostname}", s.handleHealthStatusByHost).Methods("GET")
	v1.HandleFunc("/health/servers/{hostname}/components/{component}", s.handleHealthStatusByComponent).Methods("GET")

	// System configuration and status routes
	v1.HandleFunc("/config", s.handleConfigInfo).Methods("GET")

	return router
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("HTTP API: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("HTTP API: %s %s completed in %v", r.Method, r.URL.Path, time.Since(start))
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

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("HTTP API: Error encoding JSON response: %v", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}

// Request/Response types

type CreateAccountRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UpdateAccountRequest struct {
	Password string `json:"password"`
}

type AddCredentialRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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

	if req.Email == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	ctx := r.Context()

	// Create account using the database's method
	createReq := db.CreateAccountRequest{
		Email:     req.Email,
		Password:  req.Password,
		IsPrimary: true,
		HashType:  "bcrypt",
	}

	err := s.database.CreateAccount(ctx, createReq)
	if err != nil {
		// Rely on the DB unique constraint to handle duplicates atomically.
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.writeError(w, http.StatusConflict, "Account already exists")
			return
		}
		log.Printf("HTTP API: Error creating account: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to create account")
		return
	}

	// Get the created account ID
	accountID, err := s.database.GetAccountIDByAddress(ctx, req.Email)
	if err != nil {
		log.Printf("HTTP API: Error getting new account ID: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to retrieve new account ID")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"account_id": accountID,
		"email":      req.Email,
		"message":    "Account created successfully",
	})
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	accounts, err := s.database.ListAccounts(ctx)
	if err != nil {
		log.Printf("HTTP API: Error listing accounts: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Error listing accounts")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"accounts": accounts,
		"total":    len(accounts),
	})
}

func (s *Server) handleAccountExists(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]

	ctx := r.Context()

	exists, err := s.database.AccountExists(ctx, email)
	if err != nil {
		log.Printf("HTTP API: Error checking account existence: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Error checking account existence")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":  email,
		"exists": exists,
	})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	ctx := r.Context()

	accountDetails, err := s.database.GetAccountDetails(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		log.Printf("HTTP API: Error getting account details: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get account details")
		return
	}

	s.writeJSON(w, http.StatusOK, accountDetails)
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	vars := mux.Vars(r)
	email := vars["email"]

	var req UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Password is required")
		return
	}

	ctx := r.Context()

	// Update account using the database's method
	updateReq := db.UpdateAccountRequest{
		Email:    email,
		Password: req.Password,
		HashType: "bcrypt",
	}

	err := s.database.UpdateAccount(ctx, updateReq)
	if err != nil {
		log.Printf("HTTP API: Error updating account: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to update account")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{
		"message": "Account updated successfully",
	})
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	ctx := r.Context()

	err := s.database.DeleteAccount(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountAlreadyDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			log.Printf("HTTP API: Error deleting account %s: %v", email, err)
			s.writeError(w, http.StatusInternalServerError, "Error deleting account")
			return
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":   email,
		"message": "Account soft-deleted successfully. It will be permanently removed after the grace period.",
	})
}

func (s *Server) handleRestoreAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	ctx := r.Context()

	err := s.database.RestoreAccount(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if errors.Is(err, db.ErrAccountNotDeleted) {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		} else {
			log.Printf("HTTP API: Error restoring account %s: %v", email, err)
			s.writeError(w, http.StatusInternalServerError, "Error restoring account")
			return
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":   email,
		"message": "Account restored successfully.",
	})
}

func (s *Server) handleAddCredential(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	vars := mux.Vars(r)
	primaryEmail := vars["email"]

	var req AddCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if req.Email == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, "Email and password are required")
		return
	}

	ctx := r.Context()

	// 1. Get the account ID for the primary email address in the path.
	accountID, err := s.database.GetAccountIDByAddress(ctx, primaryEmail)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found for the specified primary email")
			return
		}
		log.Printf("HTTP API: Error getting account ID for '%s': %v", primaryEmail, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to find account")
		return
	}

	// 2. Add the new credential to the existing account.
	// This assumes a new database method `AddCredential` exists.
	addReq := db.AddCredentialRequest{
		AccountID:   accountID,
		NewEmail:    req.Email,
		NewPassword: req.Password,
		NewHashType: "bcrypt",
	}

	err = s.database.AddCredential(ctx, addReq)
	if err != nil {
		if errors.Is(err, consts.ErrDBUniqueViolation) {
			s.writeError(w, http.StatusConflict, "Credential with this email already exists")
			return
		}
		log.Printf("HTTP API: Error adding credential: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to add credential")
		return
	}

	s.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"new_email": req.Email,
		"message":   "Credential added successfully",
	})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]

	ctx := r.Context()

	credentials, err := s.database.ListCredentials(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, "Account not found")
			return
		}
		log.Printf("HTTP API: Error listing credentials: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to list credentials")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":       email,
		"credentials": credentials,
		"count":       len(credentials),
	})
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	ctx := r.Context()

	// Get detailed credential information using the same logic as CLI
	credentialDetails, err := s.database.GetCredentialDetails(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		log.Printf("HTTP API: Error getting credential details: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get credential details")
		return
	}

	s.writeJSON(w, http.StatusOK, credentialDetails)
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]
	ctx := r.Context()

	err := s.database.DeleteCredential(ctx, email)
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
		log.Printf("HTTP API: Error deleting credential %s: %v", email, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to delete credential")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":   email,
		"message": "Credential deleted successfully",
	})
}

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connections, err := s.database.GetActiveConnections(ctx)
	if err != nil {
		log.Printf("HTTP API: Error getting connections: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get connections")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"connections": connections,
		"count":       len(connections),
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

	criteria := db.TerminationCriteria{
		Email:      req.UserEmail,
		Protocol:   req.Protocol,
		ServerAddr: req.ServerAddr,
		ClientAddr: req.ClientAddr,
	}

	count, err := s.database.MarkConnectionsForTermination(ctx, criteria)
	if err != nil {
		log.Printf("HTTP API: Error kicking connections: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to kick connections")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":            "Connections marked for termination successfully",
		"connections_marked": count,
	})
}

func (s *Server) handleConnectionStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	stats, err := s.database.GetConnectionStats(ctx)
	if err != nil {
		log.Printf("HTTP API: Error getting connection stats: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get connection stats")
		return
	}

	s.writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleGetUserConnections(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email := vars["email"]

	ctx := r.Context()

	connections, err := s.database.GetUserConnections(ctx, email)
	if err != nil {
		log.Printf("HTTP API: Error getting user connections: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get user connections")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"email":       email,
		"connections": connections,
		"count":       len(connections),
	})
}

func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Cache not available")
		return
	}

	stats, err := s.cache.GetStats()
	if err != nil {
		log.Printf("HTTP API: Error getting cache stats: %v", err)
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
		metrics, err := s.database.GetLatestCacheMetrics(ctx)
		if err != nil {
			log.Printf("HTTP API: Error getting latest cache metrics: %v", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get latest cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]interface{}{
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

		metrics, err := s.database.GetCacheMetrics(ctx, instanceID, since, limit)
		if err != nil {
			log.Printf("HTTP API: Error getting cache metrics: %v", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get cache metrics")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]interface{}{
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
		log.Printf("HTTP API: Error getting cache stats before purge: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats before purge")
		return
	}

	// Purge cache
	err = s.cache.PurgeAll(ctx)
	if err != nil {
		log.Printf("HTTP API: Error purging cache: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to purge cache")
		return
	}

	// Get stats after purge
	statsAfter, err := s.cache.GetStats()
	if err != nil {
		log.Printf("HTTP API: Error getting cache stats after purge: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get cache stats after purge")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message":      "Cache purged successfully",
		"stats_before": statsBefore,
		"stats_after":  statsAfter,
	})
}

func (s *Server) handleHealthOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get query parameter for hostname, default to empty for system-wide
	hostname := r.URL.Query().Get("hostname")

	overview, err := s.database.GetSystemHealthOverview(ctx, hostname)
	if err != nil {
		log.Printf("HTTP API: Error getting health overview: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health overview")
		return
	}

	s.writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleHealthStatusByHost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostname := vars["hostname"] // from /health/servers/{hostname}

	ctx := r.Context()

	statuses, err := s.database.GetAllHealthStatuses(ctx, hostname)
	if err != nil {
		log.Printf("HTTP API: Error getting health statuses for host %s: %v", hostname, err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get health statuses for host")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"hostname": hostname,
		"statuses": statuses,
		"count":    len(statuses),
	})
}

func (s *Server) handleHealthStatusByComponent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostname := vars["hostname"]   // from /health/servers/{hostname}/components/{component}
	component := vars["component"] // from /health/servers/{hostname}/components/{component}

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

		history, err := s.database.GetHealthHistory(ctx, hostname, component, since, limit)
		if err != nil {
			log.Printf("HTTP API: Error getting health history: %v", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to get health history")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]interface{}{
			"hostname":  hostname,
			"component": component,
			"history":   history,
			"count":     len(history),
			"since":     since,
		})
	} else {
		// Get current health status
		status, err := s.database.GetHealthStatus(ctx, hostname, component)
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
	stats, err := s.database.GetUploaderStats(ctx, maxAttempts)
	if err != nil {
		log.Printf("HTTP API: Error getting uploader stats: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get uploader stats")
		return
	}

	response := map[string]interface{}{
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

		failedUploads, err := s.database.GetFailedUploads(ctx, maxAttempts, failedLimit)
		if err != nil {
			log.Printf("HTTP API: Error getting failed uploads: %v", err)
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

	failedUploads, err := s.database.GetFailedUploads(ctx, maxAttempts, limit)
	if err != nil {
		log.Printf("HTTP API: Error getting failed uploads: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get failed uploads")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
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

	stats, err := s.database.GetAuthAttemptsStats(ctx, windowDuration)
	if err != nil {
		log.Printf("HTTP API: Error getting auth stats: %v", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to get auth stats")
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"stats":          stats,
		"window":         windowDuration.String(),
		"window_seconds": int64(windowDuration.Seconds()),
	})
}

func (s *Server) handleConfigInfo(w http.ResponseWriter, r *http.Request) {
	// Return basic configuration information (non-sensitive)
	// This is useful for debugging and system information

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"api_version": "v1",
		"server_type": "sora-http-api",
		"features_enabled": map[string]bool{
			"account_management":    true,
			"connection_management": true,
			"cache_management":      s.cache != nil,
			"health_monitoring":     true,
			"auth_statistics":       true,
			"uploader_monitoring":   true,
		},
		"endpoints": map[string][]string{
			"account_management": {
				"POST /api/v1/accounts",
				"GET /api/v1/accounts",
				"GET /api/v1/accounts/{email}",
				"PUT /api/v1/accounts/{email}",
				"DELETE /api/v1/accounts/{email}",
				"POST /api/v1/accounts/{email}/restore",
				"GET /api/v1/accounts/{email}/exists",
				"POST /api/v1/accounts/{email}/credentials",
				"GET /api/v1/accounts/{email}/credentials",
			},
			"credential_management": {
				"GET /api/v1/credentials/{email}",
			},
			"connection_management": {
				"GET /api/v1/connections",
				"GET /api/v1/connections/stats",
				"POST /api/v1/connections/kick",
				"GET /api/v1/connections/user/{email}",
			},
			"cache_management": {
				"GET /api/v1/cache/stats",
				"GET /api/v1/cache/metrics",
				"POST /api/v1/cache/purge",
			},
			"health_monitoring": {
				"GET /api/v1/health/overview",
				"GET /api/v1/health/servers/{hostname}",
				"GET /api/v1/health/servers/{hostname}/components/{component}",
			},
			"uploader_monitoring": {
				"GET /api/v1/uploader/status",
				"GET /api/v1/uploader/failed",
			},
			"system_information": {
				"GET /api/v1/auth/stats",
				"GET /api/v1/config",
			},
		},
	})
}
