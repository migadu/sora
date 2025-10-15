package tlsmanager

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Manager handles TLS certificate management for Sora.
// It supports both file-based certificates and automatic Let's Encrypt certificates.
type Manager struct {
	config         config.TLSConfig
	autocertMgr    *autocert.Manager
	tlsConfig      *tls.Config
	clusterManager *cluster.Manager
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
	}

	// Log cluster integration status
	if clusterMgr != nil {
		logger.Infof("TLS manager integrated with cluster (node: %s, leader: %v)",
			clusterMgr.GetNodeID(), clusterMgr.IsLeader())
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

	logger.Infof("TLS manager initialized with provider: %s", cfg.Provider)
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
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	logger.Infof("Loaded TLS certificate from files: cert=%s, key=%s", m.config.CertFile, m.config.KeyFile)
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
		logger.Infof("Certificate fallback cache disabled - using S3 only")
		cache = s3cache
	}

	// Wrap cache with cluster-aware wrapper if cluster is enabled
	var finalCache autocert.Cache = cache
	if m.clusterManager != nil {
		clusterCache := NewClusterAwareCache(cache, m.clusterManager)
		finalCache = NewFailoverAwareCache(clusterCache)
		logger.Infof("Cluster-aware certificate cache enabled - only leader %s can request certificates",
			m.clusterManager.GetLeaderID())

		// Register callback for leadership changes
		m.clusterManager.OnLeaderChange(func(isLeader bool, newLeaderID string) {
			if isLeader {
				logger.Infof("TLS Manager: This node became the cluster leader - can now request certificates")
			} else {
				logger.Infof("TLS Manager: This node is no longer the cluster leader - certificate requests will be handled by %s", newLeaderID)
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
		logger.Infof("Certificates will be renewed %v before expiry", renewBefore)
	} else {
		logger.Infof("Using default renewal window (30 days before expiry)")
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

	// Create TLS config with autocert
	m.tlsConfig = m.autocertMgr.TLSConfig()
	m.tlsConfig.MinVersion = tls.VersionTLS12

	logger.Infof("Let's Encrypt autocert initialized for domains: %v", leCfg.Domains)
	logger.Infof("Certificates will be stored in S3 bucket: %s", leCfg.S3.Bucket)

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
