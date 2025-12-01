package tlsmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// ErrMissingServerName is returned when a TLS handshake is attempted without SNI
var ErrMissingServerName = errors.New("missing server name")

// ErrHostNotAllowed is returned when a TLS handshake is attempted for a domain not in the allowlist
var ErrHostNotAllowed = errors.New("host not allowed")

// ErrCertificateUnavailable is returned when a certificate cannot be retrieved (cache miss + ACME failure)
// This is often a transient error (S3 down, ACME rate limit, network issues) and should not crash the server
var ErrCertificateUnavailable = errors.New("certificate unavailable")

// Manager handles TLS certificate management for Sora.
// It supports both file-based certificates and automatic Let's Encrypt certificates.
type Manager struct {
	config         config.TLSConfig
	autocertMgr    *autocert.Manager
	tlsConfig      *tls.Config
	clusterManager *cluster.Manager
	stopCertSync   chan struct{} // Signal to stop certificate sync worker
}

// New creates a new TLS manager based on the provided configuration.
// If clusterMgr is provided, only the cluster leader will request new certificates.
func New(cfg config.TLSConfig, clusterMgr *cluster.Manager) (*Manager, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled in configuration")
	}

	m := &Manager{
		config:         cfg,
		clusterManager: clusterMgr,
		stopCertSync:   make(chan struct{}),
	}

	// Log cluster integration status
	if clusterMgr != nil {
		logger.Info("TLS manager integrated with cluster", "node",
			clusterMgr.GetNodeID(), "is_leader", clusterMgr.IsLeader())
	}

	switch cfg.Provider {
	case "file":
		if err := m.initFileProvider(); err != nil {
			return nil, fmt.Errorf("failed to initialize file provider: %w", err)
		}
	case "letsencrypt":
		if err := m.initLetsEncryptProvider(); err != nil {
			return nil, fmt.Errorf("failed to initialize Let's Encrypt provider: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown TLS provider: %s (must be 'file' or 'letsencrypt')", cfg.Provider)
	}

	logger.Info("TLS manager initialized", "provider", cfg.Provider)
	return m, nil
}

// initFileProvider initializes TLS with certificate files
func (m *Manager) initFileProvider() error {
	if m.config.CertFile == "" || m.config.KeyFile == "" {
		return fmt.Errorf("cert_file and key_file are required for provider='file'")
	}

	cert, err := tls.LoadX509KeyPair(m.config.CertFile, m.config.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	m.tlsConfig = &tls.Config{
		Certificates:  []tls.Certificate{cert},
		MinVersion:    tls.VersionTLS12,
		NextProtos:    []string{"imap", "pop3", "sieve", "lmtp", "http/1.1", "h2"},
		Renegotiation: tls.RenegotiateNever,
	}

	logger.Info("Loaded TLS certificate from files", "cert", m.config.CertFile, "key", m.config.KeyFile)
	return nil
}

// initLetsEncryptProvider initializes autocert for automatic certificate management
func (m *Manager) initLetsEncryptProvider() error {
	if m.config.LetsEncrypt == nil {
		return fmt.Errorf("letsencrypt configuration is required for provider='letsencrypt'")
	}

	leCfg := m.config.LetsEncrypt

	if leCfg.Email == "" {
		return fmt.Errorf("letsencrypt.email is required")
	}

	if len(leCfg.Domains) == 0 {
		return fmt.Errorf("letsencrypt.domains is required and must not be empty")
	}

	if leCfg.StorageProvider != "s3" {
		return fmt.Errorf("only storage_provider='s3' is currently supported for Let's Encrypt")
	}

	// Initialize S3 cache
	s3cache, err := NewS3Cache(leCfg.S3)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 cache: %w", err)
	}

	// Wrap S3 cache with fallback to local filesystem for resilience (if enabled)
	var cache autocert.Cache = s3cache

	// EnableFallback defaults to true if not explicitly set to false
	enableFallback := leCfg.EnableFallback
	if !enableFallback {
		// Check if it was explicitly set - if EnableFallback is false and FallbackDir is empty,
		// assume user wants fallback disabled. Otherwise, enable by default.
		if leCfg.FallbackDir == "" {
			// Not explicitly configured either way - enable by default
			enableFallback = true
		}
	} else {
		enableFallback = true
	}

	if enableFallback {
		fallbackDir := leCfg.FallbackDir
		if fallbackDir == "" {
			fallbackDir = "/var/lib/sora/certs" // Default fallback directory
		}

		// NewFallbackCache will return S3-only cache if fallback dir cannot be created
		// This prevents server crashes due to permission issues
		fallbackCache, err := NewFallbackCache(s3cache, fallbackDir)
		if err != nil {
			return fmt.Errorf("failed to initialize fallback cache: %w", err)
		}
		cache = fallbackCache
		// Note: Success message logged inside NewFallbackCache (or warning if fallback disabled)
	} else {
		logger.Info("Certificate fallback cache disabled - using S3 only")
		cache = s3cache
	}

	// Wrap cache with cluster-aware wrapper if cluster is enabled
	var finalCache autocert.Cache = cache
	if m.clusterManager != nil {
		clusterCache := NewClusterAwareCache(cache, m.clusterManager)
		finalCache = NewFailoverAwareCache(clusterCache)
		logger.Info("Cluster-aware certificate cache enabled - only leader can request certificates", "leader",
			m.clusterManager.GetLeaderID())

		// Register callback for leadership changes
		m.clusterManager.OnLeaderChange(func(isLeader bool, newLeaderID string) {
			if isLeader {
				logger.Info("TLS Manager: This node became the cluster leader - can now request certificates")
			} else {
				logger.Info("TLS Manager: This node is no longer the cluster leader", "new_leader", newLeaderID)
			}
		})
	}

	// Parse renewal window if specified
	var renewBefore time.Duration
	if leCfg.RenewBefore != "" {
		var err error
		renewBefore, err = time.ParseDuration(leCfg.RenewBefore)
		if err != nil {
			return fmt.Errorf("invalid renew_before duration: %w", err)
		}
		logger.Info("Certificates will be renewed before expiry", "window", renewBefore)
	} else {
		logger.Info("Using default renewal window (30 days before expiry)")
	}

	// Create autocert manager
	m.autocertMgr = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Email:       leCfg.Email,
		HostPolicy:  autocert.HostWhitelist(leCfg.Domains...),
		Cache:       finalCache,
		RenewBefore: renewBefore, // 0 = default 30 days
		// Use Let's Encrypt production directory by default
		Client: &acme.Client{
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		},
	}

	// Determine default domain for SNI-less connections
	defaultDomain := leCfg.DefaultDomain
	if defaultDomain == "" && len(leCfg.Domains) > 0 {
		// If not specified, use the first configured domain
		defaultDomain = leCfg.Domains[0]
	}

	// Create TLS config with autocert and logging wrapper
	baseTLSConfig := m.autocertMgr.TLSConfig()
	m.tlsConfig = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := hello.ServerName

			// Handle missing SNI by using default domain
			if serverName == "" {
				if defaultDomain != "" {
					logger.Debug("TLS: Missing SNI - using default domain", "domain", defaultDomain)
					serverName = defaultDomain
				} else {
					logger.Debug("TLS: Rejected certificate request - missing SNI and no default domain")
					return nil, ErrMissingServerName
				}
			}

			// Normalize server name to lowercase for case-insensitive comparison
			// RFC 4343: DNS names are case-insensitive
			serverName = strings.ToLower(serverName)

			// Check if the server name matches our configured domains using the HostPolicy
			if err := m.autocertMgr.HostPolicy(nil, serverName); err != nil {
				logger.Info("TLS: Rejected certificate request for unconfigured domain", "domain", serverName, "error", err)
				return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
			}

			// Create a modified ClientHelloInfo with the resolved server name
			modifiedHello := *hello
			modifiedHello.ServerName = serverName

			// Check if certificate exists in cache first (to log whether we're serving from cache or requesting new)
			ctx := context.Background()
			_, cacheErr := m.autocertMgr.Cache.Get(ctx, serverName)

			if cacheErr == autocert.ErrCacheMiss {
				logger.Info("TLS: Certificate not in cache - requesting NEW certificate from Let's Encrypt", "domain", serverName)
			} else if cacheErr != nil {
				logger.Info("TLS: Cache check failed - attempting certificate retrieval", "domain", serverName, "error", cacheErr)
			} else {
				logger.Debug("TLS: Serving certificate from cache", "domain", serverName)
			}

			cert, err := baseTLSConfig.GetCertificate(&modifiedHello)
			if err != nil {
				// Certificate retrieval failures are often transient (S3 down, ACME rate limits, network issues)
				// Wrap as ErrCertificateUnavailable so the server logs but doesn't crash
				// This allows the server to continue serving cached certificates for other domains
				logger.Error("TLS: Failed to get certificate", "server_name", serverName, "error", err)
				return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
			}

			if cacheErr == autocert.ErrCacheMiss {
				logger.Info("TLS: NEW certificate successfully obtained from Let's Encrypt", "domain", serverName)
			} else {
				logger.Debug("TLS: Certificate provided for domain", "domain", serverName)
			}
			return cert, nil
		},
		MinVersion:    tls.VersionTLS12,
		NextProtos:    []string{"imap", "pop3", "sieve", "lmtp", "http/1.1", "h2"},
		Renegotiation: tls.RenegotiateNever,
	}

	logger.Info("Let's Encrypt autocert initialized", "domains", leCfg.Domains)
	if defaultDomain != "" {
		logger.Info("Default domain for SNI-less connections", "domain", defaultDomain)
	}
	logger.Info("Certificates will be stored in S3 bucket", "bucket", leCfg.S3.Bucket)

	// Start certificate sync worker if configured
	if leCfg.SyncInterval != "" && leCfg.SyncInterval != "0" {
		syncInterval, err := time.ParseDuration(leCfg.SyncInterval)
		if err != nil {
			return fmt.Errorf("invalid sync_interval duration: %w", err)
		}
		if syncInterval > 0 {
			m.startCertificateSyncWorker(syncInterval)
		}
	} else if leCfg.SyncInterval == "" {
		// Default to 5 minutes if not specified
		m.startCertificateSyncWorker(5 * time.Minute)
	}

	return nil
}

// GetTLSConfig returns the TLS configuration for use with servers
func (m *Manager) GetTLSConfig() *tls.Config {
	return m.tlsConfig
}

// HTTPHandler returns an HTTP handler for ACME HTTP-01 challenges.
// This should be run on port 80 for Let's Encrypt certificate issuance.
// Returns nil if not using Let's Encrypt.
//
// In cluster mode, all nodes run this handler on port 80. Here's how it works:
// 1. Leader node requests certificate from Let's Encrypt
// 2. autocert stores challenge token in cache (S3)
// 3. Let's Encrypt makes HTTP request to domain (may hit any node via load balancer)
// 4. Any node can respond because challenge token is in shared S3 cache
// 5. autocert.HTTPHandler reads token from cache and responds correctly
func (m *Manager) HTTPHandler() http.Handler {
	if m.autocertMgr == nil {
		return nil
	}

	autocertHandler := m.autocertMgr.HTTPHandler(nil)

	// Wrap with cluster-aware handler for better logging
	if m.clusterManager != nil {
		return NewClusterHTTPHandler(autocertHandler, m.clusterManager)
	}

	return autocertHandler
}

// GetAutocertManager returns the underlying autocert.Manager if using Let's Encrypt.
// Returns nil if using file-based certificates.
func (m *Manager) GetAutocertManager() *autocert.Manager {
	return m.autocertMgr
}

// WrapTLSConfigWithDefaultDomain creates a new TLS config that wraps the base config
// with a server-specific default domain for SNI-less connections.
// If serverDefaultDomain is empty, returns the base config unchanged.
func WrapTLSConfigWithDefaultDomain(baseCfg *tls.Config, serverDefaultDomain string) *tls.Config {
	if serverDefaultDomain == "" || baseCfg == nil {
		return baseCfg
	}

	// Clone the base config to avoid modifying the original
	wrapped := baseCfg.Clone()

	// Save the original GetCertificate function
	originalGetCert := baseCfg.GetCertificate

	// If there's no GetCertificate function in the base config, just return the clone
	if originalGetCert == nil {
		return wrapped
	}

	// Wrap the GetCertificate function with server-specific default domain handling
	wrapped.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		// If no SNI provided, use server-specific default domain
		if hello.ServerName == "" {
			logger.Debug("TLS: Missing SNI - using server-specific default domain", "domain", serverDefaultDomain)
			modifiedHello := *hello
			modifiedHello.ServerName = serverDefaultDomain
			return originalGetCert(&modifiedHello)
		}
		// Otherwise use the original function as-is
		return originalGetCert(hello)
	}

	return wrapped
}

// Shutdown gracefully stops the TLS manager and its background workers
func (m *Manager) Shutdown() {
	if m.stopCertSync != nil {
		close(m.stopCertSync)
	}
	logger.Info("TLS manager shutdown complete")
}
