package userapiproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// JWTClaims represents the JWT token claims (must match userapi.JWTClaims)
type JWTClaims struct {
	Email     string `json:"email"`
	AccountID int64  `json:"account_id"`
	jwt.RegisteredClaims
}

// Server represents a User API proxy server
type Server struct {
	name            string
	addr            string
	connManager     *proxy.ConnectionManager
	rdb             *resilient.ResilientDatabase
	routingLookup   proxy.UserRoutingLookup // PreLookup client for user routing (optional)
	affinityManager *server.AffinityManager // Affinity manager for sticky routing (optional)
	jwtSecret       string                  // JWT secret for token validation
	tls             bool
	tlsCertFile     string
	tlsKeyFile      string
	tlsVerify       bool
	tlsConfig       *tls.Config // Global TLS config from TLS manager (optional)
	trustedProxies  []string    // CIDR blocks for trusted proxies
	limiter         *server.ConnectionLimiter
	httpServer      *http.Server
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup

	// Shared HTTP transport (prevents connection pool leaks)
	transport *http.Transport
}

// ServerOptions holds configuration options for the User API proxy server
type ServerOptions struct {
	Name                string
	Addr                string
	RemoteAddrs         []string
	RemotePort          int    // Default port for backends if not in address
	JWTSecret           string // JWT secret for token validation
	TLS                 bool
	TLSCertFile         string
	TLSKeyFile          string
	TLSVerify           bool
	TLSConfig           *tls.Config // Global TLS config from TLS manager (optional)
	RemoteTLS           bool
	RemoteTLSVerify     bool
	ConnectTimeout      time.Duration
	MaxConnections      int                     // Maximum total connections (0 = unlimited)
	MaxConnectionsPerIP int                     // Maximum connections per client IP (0 = unlimited)
	TrustedNetworks     []string                // CIDR blocks for trusted networks that bypass per-IP limits
	TrustedProxies      []string                // CIDR blocks for trusted proxies
	PreLookup           *config.PreLookupConfig // PreLookup configuration for user routing
	AffinityManager     *server.AffinityManager // Affinity manager for sticky routing (optional)
}

// New creates a new User API proxy server
func New(appCtx context.Context, rdb *resilient.ResilientDatabase, opts ServerOptions) (*Server, error) {
	ctx, cancel := context.WithCancel(appCtx)

	if len(opts.RemoteAddrs) == 0 {
		cancel()
		return nil, fmt.Errorf("no remote addresses configured")
	}

	if opts.JWTSecret == "" {
		cancel()
		return nil, fmt.Errorf("JWT secret is required for User API proxy")
	}

	// Set default timeout if not specified
	connectTimeout := opts.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 10 * time.Second
	}

	// Initialize prelookup client if configured
	var routingLookup proxy.UserRoutingLookup
	if opts.PreLookup != nil && opts.PreLookup.Enabled {
		prelookupClient, err := proxy.InitializePrelookup("userapi", opts.PreLookup)
		if err != nil {
			logger.Warn("User API Proxy: Failed to initialize prelookup client", "name", opts.Name, "error", err)
			if !opts.PreLookup.FallbackDefault {
				cancel()
				return nil, fmt.Errorf("prelookup initialization failed and fallback disabled: %w", err)
			}
			logger.Info("User API Proxy: Continuing with consistent hash fallback", "name", opts.Name)
		} else {
			routingLookup = prelookupClient
			logger.Info("User API Proxy: Prelookup enabled", "name", opts.Name)
		}
	}

	// Create connection manager with routing lookup
	connManager, err := proxy.NewConnectionManagerWithRouting(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSVerify, false, connectTimeout, routingLookup, opts.Name)
	if err != nil {
		if routingLookup != nil {
			// Close prelookup client on error
			if closer, ok := routingLookup.(interface{ Close() error }); ok {
				closer.Close()
			}
		}
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		logger.Warn("User API Proxy: Failed to resolve addresses", "name", opts.Name, "error", err)
	}

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		limiter = server.NewConnectionLimiterWithTrustedNets("USER-API-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
	}

	// Create shared HTTP transport (reused for all proxied requests to prevent connection pool leaks)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !opts.RemoteTLSVerify,
			Renegotiation:      tls.RenegotiateNever,
		},
		DialContext: (&net.Dialer{
			Timeout:   connectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &Server{
		name:            opts.Name,
		addr:            opts.Addr,
		connManager:     connManager,
		rdb:             rdb,
		routingLookup:   routingLookup,
		affinityManager: opts.AffinityManager,
		jwtSecret:       opts.JWTSecret,
		tls:             opts.TLS,
		tlsCertFile:     opts.TLSCertFile,
		tlsKeyFile:      opts.TLSKeyFile,
		tlsVerify:       opts.TLSVerify,
		tlsConfig:       opts.TLSConfig,
		trustedProxies:  opts.TrustedProxies,
		limiter:         limiter,
		transport:       transport,
		ctx:             ctx,
		cancel:          cancel,
	}, nil
}

// Start starts the User API proxy server
func (s *Server) Start() error {
	// Setup HTTP handler
	handler := s.setupHandler()

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		ConnState:    s.connStateHandler,
	}

	// Configure TLS
	if s.tls && s.tlsCertFile != "" && s.tlsKeyFile != "" {
		// Scenario 1: Per-server TLS with explicit cert files
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			s.cancel()
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		clientAuth := tls.NoClientCert
		if s.tlsVerify {
			clientAuth = tls.RequireAndVerifyClientCert
		}

		s.httpServer.TLSConfig = &tls.Config{
			Certificates:             []tls.Certificate{cert},
			MinVersion:               tls.VersionTLS12,
			ClientAuth:               clientAuth,
			PreferServerCipherSuites: true,
			Renegotiation:            tls.RenegotiateNever,
		}
	} else if s.tls && s.tlsConfig != nil {
		// Scenario 2: Global TLS manager
		s.httpServer.TLSConfig = s.tlsConfig
	} else if s.tls {
		// TLS enabled but no cert files and no global TLS config provided
		s.cancel()
		return fmt.Errorf("TLS enabled for User API proxy [%s] but no tls_cert_file/tls_key_file provided and no global TLS manager configured", s.name)
	}

	// Start connection limiter cleanup if enabled
	if s.limiter != nil {
		s.limiter.StartCleanup(s.ctx)
	}

	// Graceful shutdown
	go func() {
		<-s.ctx.Done()
		logger.Info("User API Proxy: Shutting down server", "name", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("User API Proxy: Error shutting down server", "name", s.name, "error", err)
		}
	}()

	// Start server
	protocol := "HTTP"
	if s.tls {
		protocol = "HTTPS"
	}
	logger.Info("User API Proxy: Starting server", "name", s.name, "protocol", protocol, "addr", s.addr)

	if s.tls {
		if s.tlsCertFile != "" && s.tlsKeyFile != "" {
			return s.httpServer.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
		}
		return s.httpServer.ListenAndServeTLS("", "")
	}
	return s.httpServer.ListenAndServe()
}

// setupHandler creates the HTTP handler with reverse proxy logic
func (s *Server) setupHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Track metrics
		metrics.ConnectionsTotal.WithLabelValues("userapi_proxy").Inc()
		metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy").Inc()
		defer metrics.ConnectionsCurrent.WithLabelValues("userapi_proxy").Dec()

		// Check if this is an authentication endpoint (no JWT required)
		isAuthEndpoint := strings.HasPrefix(r.URL.Path, "/user/auth/")

		if !isAuthEndpoint {
			// Validate JWT token and extract claims for non-auth endpoints
			claims, err := s.extractAndValidateToken(r)
			if err != nil {
				logger.Warn("User API Proxy: Authentication failed", "name", s.name, "path", r.URL.Path, "error", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get backend for this user
			backendAddr, err := s.getBackendForUser(claims.Email, claims.AccountID)
			if err != nil {
				logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "user", claims.Email, "error", err)
				http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
				return
			}

			// Proxy authenticated request with user headers
			s.proxyRequest(w, r, backendAddr, &claims.Email, &claims.AccountID)
			return
		}

		// For auth endpoints (login/refresh), use consistent hash with path as key
		// This provides some distribution without needing user info
		// Backend will handle rate limiting
		backendAddr := s.connManager.GetBackendByConsistentHash(r.URL.Path)
		if backendAddr == "" {
			logger.Warn("User API Proxy: Failed to get backend", "name", s.name, "path", r.URL.Path)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Proxy unauthenticated request (no user headers)
		s.proxyRequest(w, r, backendAddr, nil, nil)
	})
}

// getBackendForUser determines the backend server for a user using affinity and prelookup
func (s *Server) getBackendForUser(email string, accountID int64) (string, error) {
	ctx := context.Background()

	// 1. Check affinity first (if configured)
	if s.affinityManager != nil {
		if backend, found := s.affinityManager.GetBackend(email, "userapi"); found {
			logger.Debug("User API Proxy: Using affinity backend", "name", s.name, "user", email, "backend", backend)
			return backend, nil
		}
	}

	// 2. Use prelookup if configured
	if s.routingLookup != nil {
		// Use routeOnly=true since user is already authenticated via JWT
		routingInfo, _, err := s.routingLookup.LookupUserRouteWithOptions(ctx, email, "", true)
		if err != nil {
			logger.Warn("User API Proxy: Prelookup failed", "name", s.name, "user", email, "error", err)
			// Fall through to consistent hash
		} else if routingInfo != nil && routingInfo.ServerAddress != "" {
			logger.Debug("User API Proxy: Using prelookup backend", "name", s.name, "user", email, "backend", routingInfo.ServerAddress)

			// Set affinity for future requests
			if s.affinityManager != nil {
				s.affinityManager.SetBackend(email, routingInfo.ServerAddress, "userapi")
			}

			return routingInfo.ServerAddress, nil
		}
	}

	// 3. Fall back to consistent hash
	backendAddr := s.connManager.GetBackendByConsistentHash(email)
	if backendAddr == "" {
		return "", fmt.Errorf("no backend available")
	}

	logger.Debug("User API Proxy: Using consistent hash backend", "name", s.name, "user", email, "backend", backendAddr)

	// Set affinity for future requests
	if s.affinityManager != nil {
		s.affinityManager.SetBackend(email, backendAddr, "userapi")
	}

	return backendAddr, nil
}

// proxyRequest proxies the request to the backend
func (s *Server) proxyRequest(w http.ResponseWriter, r *http.Request, backendAddr string, userEmail *string, accountID *int64) {
	// Create reverse proxy to backend
	scheme := "http"
	if s.connManager.IsRemoteTLS() {
		scheme = "https"
	}

	target, err := url.Parse(fmt.Sprintf("%s://%s", scheme, backendAddr))
	if err != nil {
		logger.Warn("User API Proxy: Failed to parse backend URL", "name", s.name, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create reverse proxy with shared transport (prevents connection pool leaks)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = s.transport

	// Modify request
	r.URL.Host = target.Host
	r.URL.Scheme = target.Scheme
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
	r.Host = target.Host

	// Add headers for backend to identify the authenticated user (if authenticated)
	// Backend should trust these headers from trusted proxy networks
	if userEmail != nil {
		r.Header.Set("X-Forwarded-User", *userEmail)
	}
	if accountID != nil {
		r.Header.Set("X-Forwarded-User-ID", fmt.Sprintf("%d", *accountID))
	}

	// Keep Authorization header for backend verification if needed
	// (Backend can choose to skip validation for trusted networks)

	// Proxy the request
	proxy.ServeHTTP(w, r)
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

// extractAndValidateToken extracts and validates JWT token from request
func (s *Server) extractAndValidateToken(r *http.Request) (*JWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("authorization header required")
	}

	// Extract token from "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, fmt.Errorf("authorization header must be 'Bearer <token>'")
	}

	tokenString := parts[1]

	// Validate token
	claims, err := s.validateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}

// connStateHandler handles connection state changes for tracking
func (s *Server) connStateHandler(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		// Check connection limits
		if s.limiter != nil {
			if _, err := s.limiter.AcceptWithRealIP(conn.RemoteAddr(), ""); err != nil {
				logger.Warn("User API Proxy: Connection rejected", "name", s.name, "error", err)
				conn.Close()
			}
		}
	case http.StateClosed:
		// Connection closed - limiter will handle cleanup
	}
}

// GetConnectionManager returns the connection manager for health checks
func (s *Server) GetConnectionManager() *proxy.ConnectionManager {
	return s.connManager
}

// Stop stops the User API proxy server
func (s *Server) Stop() error {
	logger.Info("User API Proxy: Stopping", "name", s.name)

	s.cancel()

	// HTTP server shutdown is handled by the graceful shutdown goroutine
	// Wait for it to complete
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("User API Proxy: Server stopped gracefully", "name", s.name)
	case <-time.After(30 * time.Second):
		logger.Warn("User API Proxy: Server stop timeout", "name", s.name)
	}

	return nil
}
