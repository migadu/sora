package userapiproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	name           string
	addr           string
	connManager    *proxy.ConnectionManager
	rdb            *resilient.ResilientDatabase
	jwtSecret      string // JWT secret for token validation
	tls            bool
	tlsCertFile    string
	tlsKeyFile     string
	tlsVerify      bool
	tlsConfig      *tls.Config // Global TLS config from TLS manager (optional)
	trustedProxies []string    // CIDR blocks for trusted proxies
	limiter        *server.ConnectionLimiter
	httpServer     *http.Server
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
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
	MaxConnections      int      // Maximum total connections (0 = unlimited)
	MaxConnectionsPerIP int      // Maximum connections per client IP (0 = unlimited)
	TrustedNetworks     []string // CIDR blocks for trusted networks that bypass per-IP limits
	TrustedProxies      []string // CIDR blocks for trusted proxies
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

	// Create connection manager (no routing lookup needed for User API)
	connManager, err := proxy.NewConnectionManager(opts.RemoteAddrs, opts.RemotePort, opts.RemoteTLS, opts.RemoteTLSVerify, false, connectTimeout)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}

	// Resolve addresses to expand hostnames to IPs
	if err := connManager.ResolveAddresses(); err != nil {
		log.Printf("[User API Proxy %s] Failed to resolve addresses: %v", opts.Name, err)
	}

	// Initialize connection limiter with trusted networks
	var limiter *server.ConnectionLimiter
	if opts.MaxConnections > 0 || opts.MaxConnectionsPerIP > 0 {
		limiter = server.NewConnectionLimiterWithTrustedNets("USER-API-PROXY", opts.MaxConnections, opts.MaxConnectionsPerIP, opts.TrustedNetworks)
	}

	return &Server{
		name:           opts.Name,
		addr:           opts.Addr,
		connManager:    connManager,
		rdb:            rdb,
		jwtSecret:      opts.JWTSecret,
		tls:            opts.TLS,
		tlsCertFile:    opts.TLSCertFile,
		tlsKeyFile:     opts.TLSKeyFile,
		tlsVerify:      opts.TLSVerify,
		tlsConfig:      opts.TLSConfig,
		trustedProxies: opts.TrustedProxies,
		limiter:        limiter,
		ctx:            ctx,
		cancel:         cancel,
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
		log.Printf("[User API Proxy %s] Shutting down server...", s.name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[User API Proxy %s] Error shutting down server: %v", s.name, err)
		}
	}()

	// Start server
	protocol := "HTTP"
	if s.tls {
		protocol = "HTTPS"
	}
	log.Printf("[User API Proxy %s] Starting %s server on %s", s.name, protocol, s.addr)

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

		// Validate JWT token and extract claims
		claims, err := s.extractAndValidateToken(r)
		if err != nil {
			log.Printf("[User API Proxy %s] Authentication failed for request %s: %v", s.name, r.URL.Path, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Get backend for this user using consistent hash
		backendAddr := s.connManager.GetBackendByConsistentHash(claims.Email)
		if backendAddr == "" {
			log.Printf("[User API Proxy %s] Failed to get backend for user %s", s.name, claims.Email)
			http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Create reverse proxy to backend
		scheme := "http"
		if s.connManager.IsRemoteTLS() {
			scheme = "https"
		}

		target, err := url.Parse(fmt.Sprintf("%s://%s", scheme, backendAddr))
		if err != nil {
			log.Printf("[User API Proxy %s] Failed to parse backend URL: %v", s.name, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(target)

		// Configure TLS for backend connections
		if s.connManager.IsRemoteTLS() {
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !s.connManager.IsRemoteTLSVerifyEnabled(),
				},
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}

		// Modify request
		r.URL.Host = target.Host
		r.URL.Scheme = target.Scheme
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Host = target.Host

		// Add headers for backend to identify the authenticated user
		// Backend should trust these headers from trusted proxy networks
		r.Header.Set("X-Forwarded-User", claims.Email)
		r.Header.Set("X-Forwarded-User-ID", fmt.Sprintf("%d", claims.AccountID))

		// Keep Authorization header for backend verification if needed
		// (Backend can choose to skip validation for trusted networks)

		// Proxy the request
		proxy.ServeHTTP(w, r)
	})
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
			if _, err := s.limiter.Accept(conn.RemoteAddr()); err != nil {
				log.Printf("[User API Proxy %s] Connection rejected: %v", s.name, err)
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
	log.Printf("[User API Proxy %s] stopping...", s.name)

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
		log.Printf("[User API Proxy %s] server stopped gracefully", s.name)
	case <-time.After(30 * time.Second):
		log.Printf("[User API Proxy %s] Server stop timeout", s.name)
	}

	return nil
}
