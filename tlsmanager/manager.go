package tlsmanager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
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

// clusterCoordinator is the part of the cluster manager the TLS manager depends on:
// which node is the leader, and therefore which node may issue certificates.
type clusterCoordinator interface {
	IsLeader() bool
	GetNodeID() string
	GetLeaderID() string
	OnLeaderChange(callback func(isLeader bool, newLeaderID string))
}

// Manager handles TLS certificate management for Sora.
// It supports both file-based certificates and automatic Let's Encrypt certificates.
type Manager struct {
	config         config.TLSConfig
	autocertMgr    *autocert.Manager
	tlsConfig      *tls.Config
	clusterManager clusterCoordinator   // nil outside cluster mode
	stopCertSync   chan struct{}        // Signal to stop certificate sync worker
	rateLimitMap   map[string]time.Time // Track rate-limited domains and their retry-after times
	rateLimitMu    sync.RWMutex         // Protect rateLimitMap
	issuanceWait   time.Duration        // How long a handshake waits for a certificate issued elsewhere
	issuancePoll   time.Duration        // Interval between shared-cache reads during that wait

	// issuanceFence is the authority on which node orders a certificate, when one is
	// available. Gossip leadership alone is not an authority: electLeader picks the
	// smallest node id among the members THIS node can see, with no quorum, so a network
	// partition elects a leader on both sides and each believes it is the only one.
	certFence      CertificateFence
	claimMu        sync.Mutex
	issuanceClaims map[string]issuanceClaim // claims held here, by domain
}

// issuanceClaim is a claim this node holds on the certificate fence.
type issuanceClaim struct {
	release func(context.Context)
	expires time.Time // when the fence lets the claim go by itself; no later than its own expiry
}

// CertificateFence is a store that cannot be partitioned into two writable copies, used
// to decide which node runs an ACME order. Implemented over the database.
type CertificateFence interface {
	// TryHoldIssuance claims the right to order a certificate for domain. It returns the
	// release for a granted claim, and a nil release when another node already holds it.
	TryHoldIssuance(ctx context.Context, domain string, ttl time.Duration) (release func(context.Context), err error)
}

const (
	// issuanceClaimTTL bounds a claim whose holder died mid-order. It has to exceed a
	// whole ACME exchange - order, challenge, validation, finalize - or the claim lapses
	// while its holder is still working and a second node starts a duplicate order.
	issuanceClaimTTL = 10 * time.Minute
	// issuanceFenceTimeout bounds the fence query itself. A TLS handshake is waiting on
	// it, so it must fail fast rather than hold the handshake open.
	issuanceFenceTimeout = 3 * time.Second
)

// SetCertificateFence installs the cluster-wide issuance fence. It must be called before
// StartRenewals and the first TLS handshake; a nil fence leaves gossip leadership as the
// only gate, which is all a node without a database can do.
func (m *Manager) SetCertificateFence(fence CertificateFence) {
	m.claimMu.Lock()
	defer m.claimMu.Unlock()
	m.certFence = fence
}

// holdIssuance reports whether this node may order a certificate for domain, taking the
// cluster-wide claim if one is available.
func (m *Manager) holdIssuance(domain string) error {
	if m.certFence == nil {
		// No shared store - a proxy-only node has no database. Gossip leadership is then
		// the only fence there is, which is the behavior this deployment already had.
		return nil
	}

	m.claimMu.Lock()
	defer m.claimMu.Unlock()

	// Re-entrant: concurrent handshakes for one domain all reach here, and the second
	// must not read this node's own claim as somebody else's. Only until the fence lets
	// the claim go, though. It is given back when the certificate is stored, and an order
	// that fails stores none: autocert retries a failed renewal 30-60 minutes later, by
	// which time another node may hold the claim, so the retry has to ask the fence.
	if claim, held := m.issuanceClaims[domain]; held {
		if time.Now().Before(claim.expires) {
			return nil
		}
		delete(m.issuanceClaims, domain)
	}

	ctx, cancel := context.WithTimeout(context.Background(), issuanceFenceTimeout)
	defer cancel()

	// Taken before the fence is asked, so the claim is never thought held past its expiry.
	asked := time.Now()
	release, err := m.certFence.TryHoldIssuance(ctx, domain, issuanceClaimTTL)
	if err != nil {
		// The fence is unreachable. Allow the order: an expired certificate takes the
		// whole node's TLS down, while the worst case here is a duplicate order that
		// costs rate-limit budget. Availability is the right side to fail to.
		logger.Warn("TLS: Certificate issuance fence unavailable - ordering without it",
			"domain", domain, "error", err)
		return nil
	}
	if release == nil {
		logger.Info("TLS: Another node is ordering this certificate", "domain", domain)
		return fmt.Errorf("%w: %s (claimed by another node)", errIssuanceDeferred, domain)
	}

	if m.issuanceClaims == nil {
		m.issuanceClaims = make(map[string]issuanceClaim)
	}
	m.issuanceClaims[domain] = issuanceClaim{release: release, expires: asked.Add(issuanceClaimTTL)}
	return nil
}

// releaseIssuance gives up this node's claim once the order has produced a certificate,
// so a renewal does not have to wait out issuanceClaimTTL.
func (m *Manager) releaseIssuance(domain string) {
	m.claimMu.Lock()
	claim, held := m.issuanceClaims[domain]
	delete(m.issuanceClaims, domain)
	m.claimMu.Unlock()

	if !held {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), issuanceFenceTimeout)
	defer cancel()
	claim.release(ctx)
}

// New creates a new TLS manager based on the provided configuration.
// If clusterMgr is provided, only the cluster leader will request new certificates.
func New(cfg config.TLSConfig, clusterMgr *cluster.Manager) (*Manager, error) {
	// A nil *cluster.Manager must not be passed on as a non-nil interface value: every
	// cluster-mode decision tests the coordinator against nil.
	if clusterMgr == nil {
		return newManager(cfg, nil)
	}
	return newManager(cfg, clusterMgr)
}

func newManager(cfg config.TLSConfig, clusterMgr clusterCoordinator) (*Manager, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("TLS is not enabled in configuration")
	}

	m := &Manager{
		config:         cfg,
		clusterManager: clusterMgr,
		stopCertSync:   make(chan struct{}),
		rateLimitMap:   make(map[string]time.Time),
		issuanceWait:   defaultIssuanceWait,
		issuancePoll:   defaultIssuancePoll,
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

// applicationProtocols are the protocols Sora itself serves, in the order the server
// prefers them. Go picks the first entry the client also offers, so anything appended
// after these can only be chosen by a client that offers nothing else.
var applicationProtocols = []string{"imap", "pop3", "sieve", "lmtp", "http/1.1", "h2"}

// acmeCapableProtocols is applicationProtocols with acme.ALPNProto last, for the
// listeners that may have to answer a tls-alpn-01 validation. Last is what keeps it
// safe: an ACME validator offers acme-tls/1 alone, while a mail client that offers
// "imap" gets "imap" because the server's preference is consulted in order.
func acmeCapableProtocols() []string {
	protocols := make([]string, 0, len(applicationProtocols)+1)
	protocols = append(protocols, applicationProtocols...)
	return append(protocols, acme.ALPNProto)
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
		NextProtos:    applicationProtocols,
		Renegotiation: tls.RenegotiateNever,
	}

	logger.Info("Loaded TLS certificate from files", "cert", m.config.CertFile, "key", m.config.KeyFile)
	return nil
}

// acmeDirectoryURL is where certificates are ordered: Let's Encrypt production. A variable
// only so that tests can point a manager at a local ACME server before it is built.
var acmeDirectoryURL = autocert.DefaultACMEDirectory

// DefaultFallbackDir is where certificates are mirrored locally when fallback_dir is unset.
const DefaultFallbackDir = "/var/lib/sora/certs"

// resolveFallbackDir returns the directory that mirrors the S3 certificate cache locally,
// or "" when the operator has explicitly disabled the mirror.
//
// Only an explicit enable_fallback = false disables it. An absent key means enabled: S3-only
// mode puts an S3 GET on every TLS handshake and fails handshakes for certificates that
// exist whenever S3 is unavailable, so it must be chosen, never inherited from a zero value.
func resolveFallbackDir(leCfg *config.TLSLetsEncryptConfig) string {
	if leCfg.EnableFallback != nil && !*leCfg.EnableFallback {
		return ""
	}
	if leCfg.FallbackDir != "" {
		return leCfg.FallbackDir
	}
	return DefaultFallbackDir
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
	s3cache, err := NewS3Cache(leCfg.S3, encryptionOptions(leCfg.S3)...)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 cache: %w", err)
	}

	// Mirror the S3 cache on local disk. NewFallbackCache returns an S3-only cache if the
	// directory cannot be created, so a permission problem degrades instead of crashing.
	var cache autocert.Cache = s3cache
	if fallbackDir := resolveFallbackDir(leCfg); fallbackDir != "" {
		cache, err = NewFallbackCache(s3cache, fallbackDir)
		if err != nil {
			return fmt.Errorf("failed to initialize fallback cache: %w", err)
		}
	} else {
		logger.Warn("TLS: Certificate fallback cache explicitly disabled - serving from S3 only; handshakes will fail while S3 is unavailable")
	}

	// Wrap cache with cluster-aware wrapper if cluster is enabled
	var finalCache autocert.Cache = cache
	if m.clusterManager != nil {
		finalCache = NewClusterAwareCache(cache, m.clusterManager)
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

	// The gate is autocert's view of the cache and must stay outermost: it answers the
	// read autocert makes immediately before it orders a certificate.
	finalCache = newIssuanceGate(finalCache, m)

	// Parse renewal window if specified
	var renewBefore time.Duration
	if leCfg.RenewBefore != "" {
		var err error
		renewBefore, err = helpers.ParseDuration(leCfg.RenewBefore)
		if err != nil {
			return fmt.Errorf("invalid renew_before duration: %w", err)
		}
		logger.Info("Certificates will be renewed before expiry", "window", renewBefore)
	} else {
		logger.Info("Using default renewal window (30 days before expiry)")
	}

	// Create autocert manager
	hostAllowed := autocert.HostWhitelist(leCfg.Domains...)
	m.autocertMgr = &autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Email:       leCfg.Email,
		HostPolicy:  hostAllowed,
		Cache:       finalCache,
		RenewBefore: renewBefore, // 0 = default 30 days
		// Use Let's Encrypt production directory by default
		Client: &acme.Client{
			DirectoryURL: acmeDirectoryURL,
			HTTPClient:   &http.Client{Transport: &issuanceFence{manager: m, base: http.DefaultTransport}},
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
			if err := hostAllowed(context.Background(), serverName); err != nil {
				logger.Info("TLS: Rejected certificate request for unconfigured domain", "domain", serverName, "error", err)
				return nil, fmt.Errorf("%w: %s", ErrHostNotAllowed, serverName)
			}

			// Create a modified ClientHelloInfo with the resolved server name
			modifiedHello := *hello
			modifiedHello.ServerName = serverName

			// Everything below is autocert's: it answers from memory, then from the shared
			// cache, and reaches Let's Encrypt only past the issuance gate. Reading the cache
			// here as well would put an S3 GET on every handshake for a certificate autocert
			// already holds.
			cert, err := baseTLSConfig.GetCertificate(&modifiedHello)
			if errors.Is(err, errIssuanceDeferred) {
				cert, err = m.awaitIssuedCertificate(&modifiedHello, baseTLSConfig.GetCertificate, err)
			}
			if err != nil {
				m.noteRateLimitError(serverName, err)

				// Certificate retrieval failures are often transient (S3 down, ACME rate limits, network issues)
				// Wrap as ErrCertificateUnavailable so the server logs but doesn't crash
				// This allows the server to continue serving cached certificates for other domains
				logger.Error("TLS: Failed to get certificate", "server_name", serverName, "error", err)
				return nil, fmt.Errorf("%w for %s: %v", ErrCertificateUnavailable, serverName, err)
			}

			// Clear rate limit on successful certificate retrieval
			m.clearRateLimit(serverName)

			logger.Debug("TLS: Certificate provided for domain", "domain", serverName)
			return cert, nil
		},
		MinVersion: tls.VersionTLS12,
		// acme.ALPNProto is advertised last so only an ACME validator, which offers it
		// alone, can negotiate it. autocert tries tls-alpn-01 first on a fresh order and
		// there is no way to take it out of its challenge list, so a config that cannot
		// negotiate acme-tls/1 spends an extra order and a failed validation, against
		// Let's Encrypt's 5 failures per hostname per hour, on every issuance.
		NextProtos:    acmeCapableProtocols(),
		Renegotiation: tls.RenegotiateNever,
	}

	logger.Info("Let's Encrypt autocert initialized", "domains", leCfg.Domains)
	if defaultDomain != "" {
		logger.Info("Default domain for SNI-less connections", "domain", defaultDomain)
	}
	logger.Info("Certificates will be stored in S3 bucket", "bucket", leCfg.S3.Bucket)

	// Certificates already in the cache are loaded by StartRenewals, not here: loading
	// one that is due renews it at once, and the caller has not yet installed the
	// issuance fence or enabled HTTP-01.

	// Start certificate sync worker if configured
	if leCfg.SyncInterval != "" && leCfg.SyncInterval != "0" {
		syncInterval, err := helpers.ParseDuration(leCfg.SyncInterval)
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

// isRateLimited checks if a domain is currently rate-limited by Let's Encrypt
func (m *Manager) isRateLimited(domain string) (bool, time.Time) {
	m.rateLimitMu.RLock()
	defer m.rateLimitMu.RUnlock()

	retryAfter, exists := m.rateLimitMap[domain]
	if !exists {
		return false, time.Time{}
	}

	// Check if the rate limit has expired
	if time.Now().After(retryAfter) {
		return false, time.Time{}
	}

	return true, retryAfter
}

// noteRateLimitError records the retry-after time carried by a Let's Encrypt 429, so the
// issuance gate stops ordering for that domain until it passes. Other errors are ignored.
func (m *Manager) noteRateLimitError(domain string, err error) {
	errStr := err.Error()
	if !strings.Contains(errStr, "429") || !strings.Contains(errStr, "rateLimited") {
		return
	}

	// Parse retry-after time from error message
	// Example: "retry after 2026-01-25 12:42:05 UTC: see https://..."
	retryAfter := time.Now().Add(24 * time.Hour) // Default: retry after 24 hours
	if strings.Contains(errStr, "retry after") {
		// Try to parse the retry time from the error message
		parts := strings.Split(errStr, "retry after ")
		if len(parts) > 1 {
			// Split on ": " to get just the timestamp
			timeParts := strings.SplitN(parts[1], ": ", 2)
			if len(timeParts) > 0 {
				timeStr := strings.TrimSpace(timeParts[0])
				if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05 MST", timeStr); parseErr == nil {
					retryAfter = parsedTime
					logger.Info("TLS: Parsed rate limit retry-after time", "domain", domain, "retry_after", retryAfter)
				}
			}
		}
	}

	m.markRateLimited(domain, retryAfter)
}

// markRateLimited records that a domain is rate-limited until the specified time
func (m *Manager) markRateLimited(domain string, retryAfter time.Time) {
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()

	m.rateLimitMap[domain] = retryAfter
	logger.Warn("TLS: Domain marked as rate-limited", "domain", domain, "retry_after", retryAfter)
}

// clearRateLimit removes a domain from the rate limit map
func (m *Manager) clearRateLimit(domain string) {
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()

	delete(m.rateLimitMap, domain)
}

// StartRenewals loads every certificate the cache holds for a configured domain into
// autocert. Loading a certificate is what starts autocert's renewal timer for it, and on
// its own autocert loads one only inside a handshake for that domain: a node that serves
// no handshake for a domain - the leader, when clients are sent to other nodes - would
// never renew it.
//
// A certificate past its renewal point is renewed as soon as it is loaded, by the node
// that may issue. On the others the order is refused at the issuance fence and autocert
// retries, picking up the renewed certificate once it has reached their cache. Domains
// without a certificate in the cache are left to their first handshake, as before.
//
// Call it once this node can complete an order: after SetCertificateFence, so that the
// order takes the cluster-wide claim, and after HTTPHandler, without which autocert
// tries tls-alpn-01 only. It does nothing for a manager that does not use Let's Encrypt.
func (m *Manager) StartRenewals() {
	if m.autocertMgr == nil || m.autocertMgr.Cache == nil || m.config.LetsEncrypt == nil {
		return
	}

	logger.Info("Pre-warm: Checking certificates in cache")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Read beneath the issuance gate: a miss here is not about to order anything, so it
	// must not take the issuance claim.
	cache := m.autocertMgr.Cache
	if gate, ok := cache.(*issuanceGate); ok {
		cache = gate.unwrap()
	}

	var load []*tls.ClientHelloInfo
	for _, domain := range m.config.LetsEncrypt.Domains {
		// autocert keeps an ECDSA certificate under the domain and, for clients without
		// ECDSA, an RSA one under domain+"+rsa"; a hello selects which one it loads.
		variants := []struct {
			key   string
			hello *tls.ClientHelloInfo
		}{
			{domain, &tls.ClientHelloInfo{ServerName: domain, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}}},
			{domain + "+rsa", &tls.ClientHelloInfo{ServerName: domain, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}}},
		}
		for _, v := range variants {
			data, err := cache.Get(ctx, v.key)
			if err != nil || len(data) == 0 {
				logger.Debug("Pre-warm: Certificate not in cache", "key", v.key, "error", err)
				continue
			}
			logger.Info("Pre-warm: Certificate found in cache", "key", v.key, "size", len(data))
			load = append(load, v.hello)
		}
	}

	logger.Info("Pre-warm: Completed", "found", len(load), "domains", len(m.config.LetsEncrypt.Domains))
	if len(load) == 0 {
		return
	}

	// Off the startup path: an expired certificate is ordered anew on the node that may
	// issue, and an ACME exchange takes minutes at worst.
	go func() {
		for _, hello := range load {
			if _, err := m.autocertMgr.GetCertificate(hello); err != nil {
				logger.Warn("Pre-warm: Could not load certificate for renewal", "domain", hello.ServerName, "error", err)
			}
		}
	}()
}

// Shutdown gracefully stops the TLS manager and its background workers
func (m *Manager) Shutdown() {
	if m.stopCertSync != nil {
		close(m.stopCertSync)
	}
	logger.Info("TLS manager shutdown complete")
}
