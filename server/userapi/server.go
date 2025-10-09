package userapi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// Server represents the HTTP Mail API server for user operations
type Server struct {
	name           string
	addr           string
	jwtSecret      string
	tokenDuration  time.Duration
	tokenIssuer    string
	allowedOrigins []string
	allowedHosts   []string
	rdb            *resilient.ResilientDatabase
	storage        *storage.S3Storage
	cache          *cache.Cache
	server         *http.Server
	tls            bool
	tlsCertFile    string
	tlsKeyFile     string
	tlsVerify      bool
}

// ServerOptions holds configuration options for the HTTP Mail API server
type ServerOptions struct {
	Name           string
	Addr           string
	JWTSecret      string
	TokenDuration  time.Duration
	TokenIssuer    string
	AllowedOrigins []string
	AllowedHosts   []string
	Storage        *storage.S3Storage
	Cache          *cache.Cache
	TLS            bool
	TLSCertFile    string
	TLSKeyFile     string
	TLSVerify      bool
}

// New creates a new HTTP Mail API server
func New(rdb *resilient.ResilientDatabase, options ServerOptions) (*Server, error) {
	if options.JWTSecret == "" {
		return nil, fmt.Errorf("JWT secret is required for Mail API server")
	}

	if options.TokenDuration == 0 {
		options.TokenDuration = 24 * time.Hour // Default to 24 hours
	}

	if options.TokenIssuer == "" {
		options.TokenIssuer = "sora-mail-api"
	}

	// Validate TLS configuration
	if options.TLS {
		if options.TLSCertFile == "" || options.TLSKeyFile == "" {
			return nil, fmt.Errorf("TLS certificate and key files are required when TLS is enabled")
		}
	}

	s := &Server{
		name:           options.Name,
		addr:           options.Addr,
		jwtSecret:      options.JWTSecret,
		tokenDuration:  options.TokenDuration,
		tokenIssuer:    options.TokenIssuer,
		allowedOrigins: options.AllowedOrigins,
		allowedHosts:   options.AllowedHosts,
		rdb:            rdb,
		storage:        options.Storage,
		cache:          options.Cache,
		tls:            options.TLS,
		tlsCertFile:    options.TLSCertFile,
		tlsKeyFile:     options.TLSKeyFile,
		tlsVerify:      options.TLSVerify,
	}

	return s, nil
}

// Start starts the HTTP Mail API server
func Start(ctx context.Context, rdb *resilient.ResilientDatabase, options ServerOptions, errChan chan error) {
	server, err := New(rdb, options)
	if err != nil {
		errChan <- fmt.Errorf("failed to create HTTP Mail API server: %w", err)
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
	log.Printf("HTTP Mail API [%s] Starting %s server on %s", serverName, protocol, options.Addr)
	if err := server.start(ctx); err != nil && err != http.ErrServerClosed && ctx.Err() == nil {
		errChan <- fmt.Errorf("HTTP Mail API server failed: %w", err)
	}
}

// start initializes and starts the HTTP server
func (s *Server) start(ctx context.Context) error {
	router := s.SetupRoutes()

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		log.Printf("HTTP Mail API [%s] Shutting down server...", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP Mail API [%s] Error shutting down server: %v", s.name, err)
		}
	}()

	// Start server with or without TLS
	if s.tls {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if s.tlsVerify {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.NoClientCert
		}
		s.server.TLSConfig = tlsConfig

		return s.server.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
	}
	return s.server.ListenAndServe()
}

// SetupRoutes configures all HTTP routes and middleware
func (s *Server) SetupRoutes() http.Handler {
	mux := http.NewServeMux()

	// Public routes (no authentication required)
	mux.HandleFunc("/user/auth/login", routeHandler("POST", s.handleLogin))
	mux.HandleFunc("/user/auth/refresh", routeHandler("POST", s.handleRefreshToken))

	// Mailbox operations
	mux.Handle("/user/mailboxes", s.jwtAuthMiddleware(multiMethodHandler(map[string]http.HandlerFunc{
		"GET":  s.handleListMailboxes,
		"POST": s.handleCreateMailbox,
	})))
	mux.Handle("/user/mailboxes/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleMailboxWithName)))

	// Message operations
	mux.Handle("/user/messages/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleMessageOperations)))

	// Sieve filter operations
	mux.Handle("/user/filters", s.jwtAuthMiddleware(routeHandler("GET", s.handleListFilters)))
	mux.Handle("/user/filters/", s.jwtAuthMiddleware(http.HandlerFunc(s.handleFilterOperations)))

	// Wrap with middleware (in reverse order - last applied is outermost)
	handler := s.loggingMiddleware(mux)
	handler = s.corsMiddleware(handler)
	handler = s.allowedHostsMiddleware(handler)

	return handler
}

// handleMailboxWithName routes mailbox operations that include a mailbox name
func (s *Server) handleMailboxWithName(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for subscribe/unsubscribe operations
	if strings.HasSuffix(path, "/subscribe") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSubscribeMailbox(w, r)
		return
	}
	if strings.HasSuffix(path, "/unsubscribe") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleUnsubscribeMailbox(w, r)
		return
	}

	// Check for message listing/search
	if strings.HasSuffix(path, "/messages") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleListMessages(w, r)
		return
	}
	if strings.HasSuffix(path, "/search") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleSearchMessages(w, r)
		return
	}

	// Otherwise it's a delete operation on the mailbox itself
	if r.Method == "DELETE" {
		s.handleDeleteMailbox(w, r)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

// handleMessageOperations routes message operations
func (s *Server) handleMessageOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for body/raw endpoints
	if strings.HasSuffix(path, "/body") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetMessageBody(w, r)
		return
	}
	if strings.HasSuffix(path, "/raw") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetMessageRaw(w, r)
		return
	}

	// Otherwise it's a basic message operation
	switch r.Method {
	case "GET":
		s.handleGetMessage(w, r)
	case "PATCH":
		s.handleUpdateMessage(w, r)
	case "DELETE":
		s.handleDeleteMessage(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleFilterOperations routes Sieve filter operations
func (s *Server) handleFilterOperations(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Check for capabilities endpoint
	if strings.HasSuffix(path, "/capabilities") {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleGetCapabilities(w, r)
		return
	}

	// Check for activate endpoint
	if strings.HasSuffix(path, "/activate") {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleActivateFilter(w, r)
		return
	}

	// Otherwise it's a CRUD operation on the filter itself
	switch r.Method {
	case "GET":
		s.handleGetFilter(w, r)
	case "PUT":
		s.handlePutFilter(w, r)
	case "DELETE":
		s.handleDeleteFilter(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("HTTP Mail API [%s] %s %s from %s", s.name, r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("HTTP Mail API [%s] %s %s completed in %v", s.name, r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is allowed
		if origin != "" && len(s.allowedOrigins) > 0 {
			allowed := false
			for _, allowedOrigin := range s.allowedOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.Header().Set("Access-Control-Max-Age", "3600")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
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
		if !isIPAllowed(clientIP, s.allowedHosts) {
			s.writeError(w, http.StatusForbidden, "Host not allowed")
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
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

func isIPAllowed(clientIP string, allowedHosts []string) bool {
	for _, allowedHost := range allowedHosts {
		if allowedHost == clientIP {
			return true
		}
		// TODO: Add CIDR block support if needed
	}
	return false
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("HTTP Mail API [%s] Error encoding JSON response: %v", s.name, err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
	s.writeJSON(w, status, map[string]string{"error": message})
}
