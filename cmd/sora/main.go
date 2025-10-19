package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/cluster"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/errors"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/uploader"
	mailapi "github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/tlsmanager"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version information, injected at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// serverManager tracks running servers for coordinated shutdown
type serverManager struct {
	wg sync.WaitGroup
	mu sync.Mutex
}

func (sm *serverManager) Add() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.wg.Add(1)
}

func (sm *serverManager) Done() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.wg.Done()
}

func (sm *serverManager) Wait() {
	sm.wg.Wait()
}

// serverDependencies encapsulates all shared services and dependencies needed by servers
type serverDependencies struct {
	storage           *storage.S3Storage
	resilientDB       *resilient.ResilientDatabase
	uploadWorker      *uploader.UploadWorker
	cacheInstance     *cache.Cache
	cleanupWorker     *cleaner.CleanupWorker
	healthIntegration *health.HealthIntegration
	metricsCollector  *metrics.Collector
	clusterManager    *cluster.Manager
	tlsManager        *tlsmanager.Manager
	affinityManager   *serverPkg.AffinityManager
	hostname          string
	config            config.Config
	serverManager     *serverManager
}

func main() {
	errorHandler := errors.NewErrorHandler()
	cfg := config.NewDefaultConfig()

	// Parse command-line flags
	showVersion := flag.Bool("version", false, "Show version information and exit")
	flag.BoolVar(showVersion, "v", false, "Show version information and exit")
	configPath := flag.String("config", "config.toml", "Path to TOML configuration file")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sora version %s (commit: %s, built at: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Load and validate configuration
	loadAndValidateConfig(*configPath, &cfg, errorHandler)

	// Initialize logging with zap logger
	logFile, err := logger.Initialize(cfg.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SORA: Warning initializing logger: %v\n", err)
	}
	if logFile != nil {
		defer func(f *os.File) {
			logger.Sync() // Flush any buffered log entries
			fmt.Fprintf(os.Stderr, "SORA: Closing log file %s\n", f.Name())
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "SORA: Error closing log file %s: %v\n", f.Name(), err)
			}
		}(logFile)
	} else {
		defer logger.Sync() // Still sync even without a log file
	}

	// Print startup banner
	logger.Println("")
	logger.Println(" ▗▄▄▖ ▗▄▖ ▗▄▄▖  ▗▄▖  ")
	logger.Println("▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ")
	logger.Println(" ▝▀▚▖▐▌ ▐▌▐▛▀▚▖▐▛▀▜▌ ")
	logger.Println("▗▄▄▞▘▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌ ")
	logger.Println("")
	logger.Infof("SORA application starting (version %s, commit: %s, built: %s)", version, commit, date)
	logger.Infof("Logging format: %s, level: %s", cfg.Logging.Format, cfg.Logging.Level)

	// Set up context and signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChan
		logger.Infof("Received signal: %s, shutting down...", sig)
		cancel()
	}()

	// Initialize all core services
	deps, initErr := initializeServices(ctx, cfg, errorHandler)
	if initErr != nil {
		errorHandler.FatalError("initialize services", initErr)
		os.Exit(errorHandler.WaitForExit())
	}

	// Clean up resources on exit
	if deps.resilientDB != nil {
		defer deps.resilientDB.Close()
	}
	if deps.cacheInstance != nil {
		defer deps.cacheInstance.Close()
	}
	if deps.clusterManager != nil {
		defer deps.clusterManager.Shutdown()
	}
	if deps.healthIntegration != nil {
		defer deps.healthIntegration.Stop()
	}
	if deps.metricsCollector != nil {
		defer deps.metricsCollector.Stop()
	}
	if deps.cleanupWorker != nil {
		defer deps.cleanupWorker.Stop()
	}
	if deps.uploadWorker != nil {
		defer deps.uploadWorker.Stop()
	}

	// Start all configured servers
	errChan := startServers(ctx, deps)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		errorHandler.Shutdown(ctx)
		// Wait for all servers to finish shutting down gracefully before releasing resources
		logger.Infof("Waiting for all servers to stop gracefully...")

		// Wait for server functions to return (listeners closed, Serve() calls returned)
		done := make(chan struct{})
		go func() {
			deps.serverManager.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.Infof("All server listeners closed")
		case <-time.After(10 * time.Second):
			logger.Warn("Server shutdown timeout reached after 10 seconds")
		}

		// Give additional time for connection goroutines to finish and release database resources
		// This ensures advisory locks are released and no goroutines are accessing the database
		logger.Infof("Waiting for active connections to finish...")
		time.Sleep(3 * time.Second)
		logger.Infof("Shutdown grace period complete, releasing database resources...")
	case err := <-errChan:
		errorHandler.FatalError("server operation", err)
		os.Exit(errorHandler.WaitForExit())
	}
}

// loadAndValidateConfig loads configuration from file and validates all server configurations
func loadAndValidateConfig(configPath string, cfg *config.Config, errorHandler *errors.ErrorHandler) {
	// Load configuration from TOML file
	if err := config.LoadConfigFromFile(configPath, cfg); err != nil {
		if os.IsNotExist(err) {
			// If default config doesn't exist, that's okay - use defaults
			if configPath == "config.toml" {
				logger.Infof("WARNING: default configuration file '%s' not found. Using application defaults.", configPath)
			} else {
				// User specified a config file that doesn't exist - that's an error
				errorHandler.ConfigError(configPath, err)
				os.Exit(errorHandler.WaitForExit())
			}
		} else {
			errorHandler.ConfigError(configPath, err)
			os.Exit(errorHandler.WaitForExit())
		}
	} else {
		logger.Infof("loaded configuration from %s", configPath)
	}

	// Get all configured servers
	allServers := cfg.GetAllServers()

	// Validate all server configurations
	for _, server := range allServers {
		if err := server.Validate(); err != nil {
			errorHandler.ValidationError(fmt.Sprintf("server '%s'", server.Name), err)
			os.Exit(errorHandler.WaitForExit())
		}
	}

	// Check for server name conflicts
	serverNames := make(map[string]bool)
	serverAddresses := make(map[string]string) // addr -> server name
	for _, server := range allServers {
		if serverNames[server.Name] {
			errorHandler.ValidationError("server configuration", fmt.Errorf("duplicate server name '%s' found. Each server must have a unique name", server.Name))
			os.Exit(errorHandler.WaitForExit())
		}
		serverNames[server.Name] = true

		// Check for address conflicts
		if existingServerName, exists := serverAddresses[server.Addr]; exists {
			errorHandler.ValidationError("server configuration", fmt.Errorf("duplicate server address '%s' found. Server '%s' and '%s' cannot bind to the same address", server.Addr, existingServerName, server.Name))
			os.Exit(errorHandler.WaitForExit())
		}
		serverAddresses[server.Addr] = server.Name
	}

	// Check if any server is configured
	if len(allServers) == 0 {
		errorHandler.ValidationError("servers", fmt.Errorf("no servers configured. Please configure at least one server in the [[servers]] section"))
		os.Exit(errorHandler.WaitForExit())
	}

	logger.Infof("Found %d configured servers", len(allServers))
}

// initializeServices initializes all core services (S3, database, cache, workers) if storage services are needed
func initializeServices(ctx context.Context, cfg config.Config, errorHandler *errors.ErrorHandler) (*serverDependencies, error) {
	hostname, _ := os.Hostname()

	// Determine if any mail storage services are enabled
	allServers := cfg.GetAllServers()
	storageServicesNeeded := false
	for _, server := range allServers {
		if server.Type == "imap" || server.Type == "lmtp" || server.Type == "pop3" {
			storageServicesNeeded = true
			break
		}
	}

	deps := &serverDependencies{
		hostname:      hostname,
		config:        cfg,
		serverManager: &serverManager{}, // Initialize server manager for coordinated shutdown
	}

	// Initialize S3 storage if needed
	if storageServicesNeeded {
		// Ensure required S3 arguments are provided only if needed
		if cfg.S3.AccessKey == "" || cfg.S3.SecretKey == "" || cfg.S3.Bucket == "" {
			errorHandler.ValidationError("S3 credentials", fmt.Errorf("missing required S3 credentials for mail services (IMAP, LMTP, POP3)"))
			os.Exit(errorHandler.WaitForExit())
		}

		// Initialize S3 storage
		s3EndpointToUse := cfg.S3.Endpoint
		if s3EndpointToUse == "" {
			errorHandler.ValidationError("S3 endpoint", fmt.Errorf("S3 endpoint not specified"))
			os.Exit(errorHandler.WaitForExit())
		}
		logger.Infof("Connecting to S3 endpoint '%s', bucket '%s'", s3EndpointToUse, cfg.S3.Bucket)
		var err error
		deps.storage, err = storage.New(s3EndpointToUse, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.GetDebug())
		if err != nil {
			errorHandler.FatalError(fmt.Sprintf("initialize S3 storage at endpoint '%s'", s3EndpointToUse), err)
			os.Exit(errorHandler.WaitForExit())
		}

		// Enable encryption if configured
		if cfg.S3.Encrypt {
			if err := deps.storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
				errorHandler.FatalError("enable S3 encryption", err)
				os.Exit(errorHandler.WaitForExit())
			}
		}
	}

	// Initialize the resilient database with runtime failover
	logger.Infof("Connecting to database with resilient failover configuration")
	var err error
	deps.resilientDB, err = resilient.NewResilientDatabase(ctx, &cfg.Database, true, true)
	if err != nil {
		logger.Infof("Failed to initialize resilient database: %v", err)
		os.Exit(1)
	}

	// Start the new aggregated metrics and health monitoring for all managed pools
	deps.resilientDB.StartPoolMetrics(ctx)
	deps.resilientDB.StartPoolHealthMonitoring(ctx)
	logger.Infof("Database resilience features initialized: failover, circuit breakers, pool monitoring")

	// Initialize health monitoring
	logger.Infof("Initializing health monitoring...")
	deps.healthIntegration = health.NewHealthIntegration(deps.resilientDB)

	if storageServicesNeeded {
		logger.Info("Mail storage services are enabled. Starting cache, uploader, and cleaner.")

		// Register S3 health check
		deps.healthIntegration.RegisterS3Check(deps.storage)

		// Initialize the local cache using configuration defaulting methods
		cacheSizeBytes := cfg.LocalCache.GetCapacityWithDefault()
		maxObjectSizeBytes := cfg.LocalCache.GetMaxObjectSizeWithDefault()
		purgeInterval := cfg.LocalCache.GetPurgeIntervalWithDefault()
		orphanCleanupAge := cfg.LocalCache.GetOrphanCleanupAgeWithDefault()

		deps.cacheInstance, err = cache.New(cfg.LocalCache.Path, cacheSizeBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, deps.resilientDB)
		if err != nil {
			errorHandler.FatalError("initialize cache", err)
			os.Exit(errorHandler.WaitForExit())
		}
		if err := deps.cacheInstance.SyncFromDisk(); err != nil {
			errorHandler.FatalError("sync cache from disk", err)
			os.Exit(errorHandler.WaitForExit())
		}
		deps.cacheInstance.StartPurgeLoop(ctx)

		// Register cache health check
		deps.healthIntegration.RegisterCustomCheck(&health.HealthCheck{
			Name:     "cache",
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Critical: false,
			Check: func(ctx context.Context) error {
				stats, err := deps.cacheInstance.GetStats()
				if err != nil {
					return fmt.Errorf("cache error: %w", err)
				}
				if stats.TotalSize < 0 {
					return fmt.Errorf("cache stats unavailable")
				}
				return nil
			},
		})

		// Register database failover health check
		deps.healthIntegration.RegisterCustomCheck(&health.HealthCheck{
			Name:     "database_failover",
			Interval: 45 * time.Second,
			Timeout:  5 * time.Second,
			Critical: true,
			Check: func(ctx context.Context) error {
				var errorMessages []string
				row := deps.resilientDB.QueryRowWithRetry(ctx, "SELECT 1")
				var result int
				if err := row.Scan(&result); err != nil {
					errorMessages = append(errorMessages, fmt.Sprintf("database connectivity check failed: %v", err))
				}
				if len(errorMessages) > 0 {
					return fmt.Errorf("%s", strings.Join(errorMessages, "; "))
				}
				return nil
			},
		})

		// Start cache metrics collection
		metricsInterval := cfg.LocalCache.GetMetricsIntervalWithDefault()
		metricsRetention := cfg.LocalCache.GetMetricsRetentionWithDefault()

		logger.Infof("[CACHE] starting metrics collection with interval: %v", metricsInterval)
		go func() {
			metricsTicker := time.NewTicker(metricsInterval)
			cleanupTicker := time.NewTicker(24 * time.Hour)
			defer metricsTicker.Stop()
			defer cleanupTicker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-metricsTicker.C:
					metrics := deps.cacheInstance.GetMetrics(hostname)
					uptimeSeconds := int64(time.Since(metrics.StartTime).Seconds())

					if err := deps.resilientDB.StoreCacheMetricsWithRetry(ctx, hostname, hostname, metrics.Hits, metrics.Misses, uptimeSeconds); err != nil {
						logger.Infof("[CACHE] WARNING: failed to store metrics: %v", err)
					}
				case <-cleanupTicker.C:
					if deleted, err := deps.resilientDB.CleanupOldCacheMetricsWithRetry(ctx, metricsRetention); err != nil {
						logger.Infof("[CACHE] WARNING: failed to cleanup old metrics: %v", err)
					} else if deleted > 0 {
						logger.Infof("[CACHE] cleaned up %d old cache metrics records", deleted)
					}
				}
			}
		}()

		// Initialize and start the cleanup worker using configuration defaulting methods
		gracePeriod := cfg.Cleanup.GetGracePeriodWithDefault()
		wakeInterval := cfg.Cleanup.GetWakeIntervalWithDefault()
		maxAgeRestriction := cfg.Cleanup.GetMaxAgeRestrictionWithDefault()
		ftsRetention := cfg.Cleanup.GetFTSRetentionWithDefault()
		authAttemptsRetention := cfg.Cleanup.GetAuthAttemptsRetentionWithDefault()
		healthStatusRetention := cfg.Cleanup.GetHealthStatusRetentionWithDefault()

		deps.cleanupWorker = cleaner.New(deps.resilientDB, deps.storage, deps.cacheInstance, wakeInterval, gracePeriod, maxAgeRestriction, ftsRetention, authAttemptsRetention, healthStatusRetention)
		deps.cleanupWorker.Start(ctx)

		// Initialize and start the upload worker
		retryInterval := cfg.Uploader.GetRetryIntervalWithDefault()
		errChan := make(chan error, 1)
		deps.uploadWorker, err = uploader.New(ctx, cfg.Uploader.Path, cfg.Uploader.BatchSize, cfg.Uploader.Concurrency, cfg.Uploader.MaxAttempts, retryInterval, hostname, deps.resilientDB, deps.storage, deps.cacheInstance, errChan)
		if err != nil {
			errorHandler.FatalError("create upload worker", err)
			os.Exit(errorHandler.WaitForExit())
		}
		deps.uploadWorker.Start(ctx)
	} else {
		logger.Info("Skipping startup of cache, uploader, and cleaner services as no mail storage services (IMAP, POP3, LMTP) are enabled.")
	}

	// Initialize cluster manager if enabled
	if cfg.Cluster.Enabled {
		logger.Infof("Initializing cluster manager")
		deps.clusterManager, err = cluster.New(cfg.Cluster)
		if err != nil {
			errorHandler.FatalError("initialize cluster manager", err)
			os.Exit(errorHandler.WaitForExit())
		}
		logger.Infof("Cluster manager initialized: node_id=%s, members=%d, leader=%s",
			deps.clusterManager.GetNodeID(),
			deps.clusterManager.GetMemberCount(),
			deps.clusterManager.GetLeaderID())

		// Initialize affinity manager for cluster-wide user-to-backend affinity
		// Default TTL: 1 hour, Cleanup interval: 10 minutes
		deps.affinityManager = serverPkg.NewAffinityManager(deps.clusterManager, true, 1*time.Hour, 10*time.Minute)
		logger.Infof("Affinity manager initialized for cluster-wide user routing")
	}

	// Initialize TLS manager if TLS is enabled
	if cfg.TLS.Enabled {
		logger.Infof("Initializing TLS manager with provider: %s", cfg.TLS.Provider)
		deps.tlsManager, err = tlsmanager.New(cfg.TLS, deps.clusterManager)
		if err != nil {
			errorHandler.FatalError("initialize TLS manager", err)
			os.Exit(errorHandler.WaitForExit())
		}
		logger.Infof("TLS manager initialized successfully")
	}

	// Start health monitoring
	deps.healthIntegration.Start(ctx)
	logger.Infof("Health monitoring started - collecting metrics every 30-60 seconds")

	// Start metrics collector for database statistics
	deps.metricsCollector = metrics.NewCollector(deps.resilientDB, 60*time.Second)
	go deps.metricsCollector.Start(ctx)

	return deps, nil
}

// startServers starts all configured servers and returns an error channel for monitoring
func startServers(ctx context.Context, deps *serverDependencies) chan error {
	errChan := make(chan error, 1)
	allServers := deps.config.GetAllServers()

	// Start HTTP-01 challenge server for Let's Encrypt if using autocert
	if deps.tlsManager != nil {
		handler := deps.tlsManager.HTTPHandler()
		if handler != nil {
			go func() {
				logger.Infof("Starting HTTP-01 challenge server on :80 for Let's Encrypt")
				httpServer := &http.Server{
					Addr:    ":80",
					Handler: handler,
				}

				// Graceful shutdown handler
				go func() {
					<-ctx.Done()
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := httpServer.Shutdown(shutdownCtx); err != nil {
						logger.Warn("HTTP-01 challenge server shutdown error: %v", err)
					}
				}()

				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Error("HTTP-01 challenge server error", err)
					errChan <- fmt.Errorf("HTTP-01 challenge server failed: %w", err)
				}
			}()
		}
	}

	// Start all configured servers dynamically
	for _, server := range allServers {
		// Warn about unused config options
		server.WarnUnusedConfigOptions(logger.Infof)

		switch server.Type {
		case "imap":
			go startDynamicIMAPServer(ctx, deps, server, errChan)
		case "lmtp":
			go startDynamicLMTPServer(ctx, deps, server, errChan)
		case "pop3":
			go startDynamicPOP3Server(ctx, deps, server, errChan)
		case "managesieve":
			go startDynamicManageSieveServer(ctx, deps, server, errChan)
		case "metrics":
			// Configure metrics collection settings
			metrics.Configure(
				server.EnableUserMetrics,
				server.EnableDomainMetrics,
				server.UserMetricsThreshold,
				server.MaxTrackedUsers,
				server.HashUsernames,
			)
			go startDynamicMetricsServer(ctx, deps, server, errChan)
		case "imap_proxy":
			go startDynamicIMAPProxyServer(ctx, deps, server, errChan)
		case "pop3_proxy":
			go startDynamicPOP3ProxyServer(ctx, deps, server, errChan)
		case "managesieve_proxy":
			go startDynamicManageSieveProxyServer(ctx, deps, server, errChan)
		case "lmtp_proxy":
			go startDynamicLMTPProxyServer(ctx, deps, server, errChan)
		case "http_admin_api":
			go startDynamicHTTPAdminAPIServer(ctx, deps, server, errChan)
		case "http_user_api":
			go startDynamicHTTPUserAPIServer(ctx, deps, server, errChan)
		default:
			logger.Infof("WARNING: Unknown server type '%s' for server '%s', skipping", server.Type, server.Name)
		}
	}

	return errChan
}

// startConnectionTrackerForProxy initializes and starts a connection tracker for a given proxy protocol.
func startConnectionTrackerForProxy(protocol string, serverName string, rdb *resilient.ResilientDatabase, hostname string, trackingConfig *config.ConnectionTrackingConfig, server interface {
	SetConnectionTracker(*proxy.ConnectionTracker)
}) *proxy.ConnectionTracker {
	if !trackingConfig.Enabled {
		return nil
	}

	updateInterval, err := trackingConfig.GetUpdateInterval()
	if err != nil {
		logger.Infof("WARNING: invalid connection_tracking update_interval '%s' for %s proxy [%s]: %v. Using default.", trackingConfig.UpdateInterval, protocol, serverName, err)
		updateInterval = 10 * time.Second
	}

	terminationPollInterval, err := trackingConfig.GetTerminationPollInterval()
	if err != nil {
		logger.Infof("WARNING: invalid connection_tracking termination_poll_interval '%s' for %s proxy [%s]: %v. Using default.", trackingConfig.TerminationPollInterval, protocol, serverName, err)
		terminationPollInterval = 30 * time.Second
	}

	logger.Infof("%s Proxy [%s] Starting connection tracker.", protocol, serverName)
	tracker := proxy.NewConnectionTracker(
		protocol,
		rdb,
		hostname,
		updateInterval,
		terminationPollInterval,
		trackingConfig.PersistToDB,
		trackingConfig.BatchUpdates,
		trackingConfig.Enabled,
	)
	server.SetConnectionTracker(tracker)
	tracker.Start()
	return tracker
}

// Dynamic server functions
func startDynamicIMAPServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	appendLimit := serverConfig.GetAppendLimitWithDefault()
	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	// Parse search rate limit window
	searchRateLimitWindow, err := serverConfig.GetSearchRateLimitWindow()
	if err != nil {
		logger.Infof("IMAP [%s] Invalid search rate limit window: %v, using default (1 minute)", serverConfig.Name, err)
		searchRateLimitWindow = time.Minute
	}

	// Parse session memory limit
	sessionMemoryLimit, err := serverConfig.GetSessionMemoryLimit()
	if err != nil {
		logger.Infof("IMAP [%s] Invalid session memory limit: %v, using default (100MB)", serverConfig.Name, err)
		sessionMemoryLimit = 100 * 1024 * 1024
	}

	// Parse command timeout
	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("IMAP [%s] Invalid command timeout: %v, using default (5 minutes)", serverConfig.Name, err)
		commandTimeout = 5 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("IMAP [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	s, err := imap.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, deps.cacheInstance,
		imap.IMAPServerOptions{
			Debug:                        serverConfig.Debug,
			TLS:                          serverConfig.TLS,
			TLSCertFile:                  serverConfig.TLSCertFile,
			TLSKeyFile:                   serverConfig.TLSKeyFile,
			TLSVerify:                    serverConfig.TLSVerify,
			MasterUsername:               []byte(serverConfig.MasterUsername),
			MasterPassword:               []byte(serverConfig.MasterPassword),
			MasterSASLUsername:           []byte(serverConfig.MasterSASLUsername),
			MasterSASLPassword:           []byte(serverConfig.MasterSASLPassword),
			AppendLimit:                  appendLimit,
			MaxConnections:               serverConfig.MaxConnections,
			MaxConnectionsPerIP:          serverConfig.MaxConnectionsPerIP,
			ProxyProtocol:                serverConfig.ProxyProtocol,
			ProxyProtocolTimeout:         proxyProtocolTimeout,
			TrustedNetworks:              deps.config.Servers.TrustedNetworks,
			AuthRateLimit:                authRateLimit,
			SearchRateLimitPerMin:        serverConfig.GetSearchRateLimitPerMin(),
			SearchRateLimitWindow:        searchRateLimitWindow,
			SessionMemoryLimit:           sessionMemoryLimit,
			CommandTimeout:               commandTimeout,
			AbsoluteSessionTimeout:       absoluteSessionTimeout,
			MinBytesPerMinute:            serverConfig.GetMinBytesPerMinute(),
			EnableWarmup:                 deps.config.LocalCache.EnableWarmup,
			WarmupMessageCount:           deps.config.LocalCache.WarmupMessageCount,
			WarmupMailboxes:              deps.config.LocalCache.WarmupMailboxes,
			WarmupAsync:                  deps.config.LocalCache.WarmupAsync,
			WarmupTimeout:                deps.config.LocalCache.WarmupTimeout,
			FTSRetention:                 ftsRetention,
			CapabilityFilters:            serverConfig.ClientFilters,
			DisabledCaps:                 serverConfig.DisabledCaps,
			Version:                      version,
			MetadataMaxEntrySize:         deps.config.Metadata.MaxEntrySize,
			MetadataMaxEntriesPerMailbox: deps.config.Metadata.MaxEntriesPerMailbox,
			MetadataMaxEntriesPerServer:  deps.config.Metadata.MaxEntriesPerServer,
			MetadataMaxTotalSize:         deps.config.Metadata.MaxTotalSize,
			Config:                       &deps.config,
		})
	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	if err := s.Serve(serverConfig.Addr); err != nil {
		errChan <- err
	}
}

func startDynamicLMTPServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()
	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	maxMessageSize, err := serverConfig.GetMaxMessageSize()
	if err != nil {
		logger.Infof("LMTP [%s] Invalid max_message_size: %v, using default (50MB)",
			serverConfig.Name, err)
		maxMessageSize = 50 * 1024 * 1024
	}

	lmtpServer, err := lmtp.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, lmtp.LMTPServerOptions{
		ExternalRelay:        serverConfig.ExternalRelay,
		TLSVerify:            serverConfig.TLSVerify,
		TLS:                  serverConfig.TLS,
		TLSCertFile:          serverConfig.TLSCertFile,
		TLSKeyFile:           serverConfig.TLSKeyFile,
		TLSUseStartTLS:       serverConfig.TLSUseStartTLS,
		Debug:                serverConfig.Debug,
		MaxConnections:       serverConfig.MaxConnections,
		MaxConnectionsPerIP:  serverConfig.MaxConnectionsPerIP,
		ProxyProtocol:        serverConfig.ProxyProtocol,
		ProxyProtocolTimeout: proxyProtocolTimeout,
		TrustedNetworks:      deps.config.Servers.TrustedNetworks,
		FTSRetention:         ftsRetention,
		MaxMessageSize:       maxMessageSize,
	})

	if err != nil {
		errChan <- fmt.Errorf("failed to create LMTP server: %w", err)
		return
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down LMTP server %s...", serverConfig.Name)
		if err := lmtpServer.Close(); err != nil {
			logger.Infof("Error closing LMTP server: %v", err)
		}
	}()

	lmtpServer.Start(errChan)
}

func startDynamicPOP3Server(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	sessionMemoryLimit, err := serverConfig.GetSessionMemoryLimit()
	if err != nil {
		logger.Infof("POP3 [%s] Invalid session memory limit: %v, using default (100MB)",
			serverConfig.Name, err)
		sessionMemoryLimit = 100 * 1024 * 1024
	}

	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("POP3 [%s] Invalid command timeout: %v, using default (2 minutes)",
			serverConfig.Name, err)
		commandTimeout = 2 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("POP3 [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	s, err := pop3.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, deps.cacheInstance, pop3.POP3ServerOptions{
		Debug:                  serverConfig.Debug,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		ProxyProtocol:          serverConfig.ProxyProtocol,
		ProxyProtocolTimeout:   proxyProtocolTimeout,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		AuthRateLimit:          authRateLimit,
		SessionMemoryLimit:     sessionMemoryLimit,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
	})

	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down POP3 server %s...", serverConfig.Name)
		s.Close()
	}()

	s.Start(errChan)
}

func startDynamicManageSieveServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	maxSize := serverConfig.GetMaxScriptSizeWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("ManageSieve [%s] Invalid command timeout: %v, using default (3 minutes)",
			serverConfig.Name, err)
		commandTimeout = 3 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("ManageSieve [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	s, err := managesieve.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.resilientDB, managesieve.ManageSieveServerOptions{
		InsecureAuth:           serverConfig.InsecureAuth,
		TLSVerify:              serverConfig.TLSVerify,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSUseStartTLS:         serverConfig.TLSUseStartTLS,
		Debug:                  serverConfig.Debug,
		MaxScriptSize:          maxSize,
		SupportedExtensions:    serverConfig.SupportedExtensions,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		ProxyProtocol:          serverConfig.ProxyProtocol,
		ProxyProtocolTimeout:   proxyProtocolTimeout,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		AuthRateLimit:          authRateLimit,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
	})

	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down ManageSieve server %s...", serverConfig.Name)
		s.Close()
	}()

	s.Start(errChan)
}

func startDynamicMetricsServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	mux := http.NewServeMux()
	mux.Handle(serverConfig.Path, promhttp.Handler())

	server := &http.Server{
		Addr:    serverConfig.Addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down metrics server %s...", serverConfig.Name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Infof("Error shutting down metrics server: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		errChan <- fmt.Errorf("metrics server failed: %w", err)
	}
}

func startDynamicIMAPProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	sessionTimeout := serverConfig.GetSessionTimeoutWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for IMAP proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Parse timeout configurations
	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("IMAP proxy [%s] Invalid command timeout: %v, using default (5 minutes)", serverConfig.Name, err)
		commandTimeout = 5 * time.Minute
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("IMAP proxy [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
	}

	server, err := imapproxy.New(ctx, deps.resilientDB, deps.hostname, imapproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		TLSConfig:              tlsConfig,
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseIDCommand:     serverConfig.RemoteUseIDCommand,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		EnableAffinity:         serverConfig.EnableAffinity,
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		Debug:                  serverConfig.Debug,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create IMAP proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Infof("IMAP Proxy [%s] Affinity manager attached to connection manager", serverConfig.Name)
		}

		// Register prelookup health check if prelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.PrelookupHealthChecker); ok {
				deps.healthIntegration.RegisterPrelookupCheck(healthChecker, serverConfig.Name)
				logger.Infof("Registered prelookup health check for IMAP proxy %s", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("IMAP", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down IMAP proxy server %s...", serverConfig.Name)
		server.Stop()
	}()

	if err := server.Start(); err != nil && ctx.Err() == nil {
		errChan <- fmt.Errorf("IMAP proxy server error: %w", err)
	}
}

func startDynamicPOP3ProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	sessionTimeout := serverConfig.GetSessionTimeoutWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for POP3 proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Parse timeout configurations
	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("POP3 proxy [%s] Invalid command timeout: %v, using default (5 minutes)", serverConfig.Name, err)
		commandTimeout = 5 * time.Minute
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("POP3 proxy [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
	}

	server, err := pop3proxy.New(ctx, deps.hostname, serverConfig.Addr, deps.resilientDB, pop3proxy.POP3ProxyServerOptions{
		Name:                   serverConfig.Name,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		TLSConfig:              tlsConfig,
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseXCLIENT:       serverConfig.RemoteUseXCLIENT,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		Debug:                  serverConfig.Debug,
		EnableAffinity:         serverConfig.EnableAffinity,
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create POP3 proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Infof("POP3 Proxy [%s] Affinity manager attached to connection manager", serverConfig.Name)
		}

		// Register prelookup health check if prelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.PrelookupHealthChecker); ok {
				deps.healthIntegration.RegisterPrelookupCheck(healthChecker, serverConfig.Name)
				logger.Infof("Registered prelookup health check for POP3 proxy %s", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("POP3", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down POP3 proxy server %s...", serverConfig.Name)
		server.Stop()
	}()

	server.Start()
}

func startDynamicManageSieveProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	sessionTimeout := serverConfig.GetSessionTimeoutWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for ManageSieve proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Parse timeout configurations
	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Infof("ManageSieve proxy [%s] Invalid command timeout: %v, using default (5 minutes)", serverConfig.Name, err)
		commandTimeout = 5 * time.Minute
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Infof("ManageSieve proxy [%s] Invalid absolute session timeout: %v, using default (30 minutes)", serverConfig.Name, err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
	}

	server, err := managesieveproxy.New(ctx, deps.resilientDB, deps.hostname, managesieveproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		TLS:                    serverConfig.TLS,
		TLSUseStartTLS:         serverConfig.TLSUseStartTLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		TLSConfig:              tlsConfig,
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSUseStartTLS:   serverConfig.RemoteTLSUseStartTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		EnableAffinity:         serverConfig.EnableAffinity,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		Debug:                  serverConfig.Debug,
		SupportedExtensions:    serverConfig.SupportedExtensions,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create ManageSieve proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Infof("ManageSieve Proxy [%s] Affinity manager attached to connection manager", serverConfig.Name)
		}

		// Register prelookup health check if prelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.PrelookupHealthChecker); ok {
				deps.healthIntegration.RegisterPrelookupCheck(healthChecker, serverConfig.Name)
				logger.Infof("Registered prelookup health check for ManageSieve proxy %s", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("ManageSieve", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down ManageSieve proxy server %s...", serverConfig.Name)
		server.Stop()
	}()

	server.Start()
}

func startDynamicLMTPProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	sessionTimeout := serverConfig.GetSessionTimeoutWithDefault()
	maxMessageSize := serverConfig.GetMaxMessageSizeWithDefault()

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for LMTP proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Get global TLS config if available
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
	}

	server, err := lmtpproxy.New(ctx, deps.resilientDB, deps.hostname, lmtpproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		TLS:                    serverConfig.TLS,
		TLSUseStartTLS:         serverConfig.TLSUseStartTLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		TLSConfig:              tlsConfig,
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSUseStartTLS:   serverConfig.RemoteTLSUseStartTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseXCLIENT:       serverConfig.RemoteUseXCLIENT,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		EnableAffinity:         serverConfig.EnableAffinity,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxMessageSize:         maxMessageSize,
		MaxConnections:         serverConfig.MaxConnections,
		Debug:                  serverConfig.Debug,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create LMTP proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Infof("LMTP Proxy [%s] Affinity manager attached to connection manager", serverConfig.Name)
		}

		// Register prelookup health check if prelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.PrelookupHealthChecker); ok {
				deps.healthIntegration.RegisterPrelookupCheck(healthChecker, serverConfig.Name)
				logger.Infof("Registered prelookup health check for LMTP proxy %s", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("LMTP", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		logger.Infof("Shutting down LMTP proxy server %s...", serverConfig.Name)
		server.Stop()
	}()

	server.Start()
}

func startDynamicHTTPAdminAPIServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	if serverConfig.APIKey == "" {
		logger.Infof("WARNING: HTTP Admin API server '%s' enabled but no API key configured, skipping", serverConfig.Name)
		return
	}

	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()

	options := adminapi.ServerOptions{
		Name:          serverConfig.Name,
		Addr:          serverConfig.Addr,
		APIKey:        serverConfig.APIKey,
		AllowedHosts:  serverConfig.AllowedHosts,
		Cache:         deps.cacheInstance,
		Uploader:      deps.uploadWorker,
		Storage:       deps.storage,
		ExternalRelay: serverConfig.ExternalRelay,
		TLS:           serverConfig.TLS,
		TLSCertFile:   serverConfig.TLSCertFile,
		TLSKeyFile:    serverConfig.TLSKeyFile,
		TLSVerify:     serverConfig.TLSVerify,
		Hostname:      deps.hostname,
		FTSRetention:  ftsRetention,
	}

	adminapi.Start(ctx, deps.resilientDB, options, errChan)
}

func startDynamicHTTPUserAPIServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	if serverConfig.JWTSecret == "" {
		logger.Infof("WARNING: HTTP User API server '%s' enabled but no JWT secret configured, skipping", serverConfig.Name)
		return
	}

	// Parse token duration
	tokenDuration := 24 * time.Hour // Default
	if serverConfig.TokenDuration != "" {
		if dur, err := time.ParseDuration(serverConfig.TokenDuration); err == nil {
			tokenDuration = dur
		} else {
			logger.Infof("WARNING: Invalid token_duration '%s' for HTTP User API server '%s', using default 24h", serverConfig.TokenDuration, serverConfig.Name)
		}
	}

	// Use mailapi package (need to add import)
	options := mailapi.ServerOptions{
		Name:           serverConfig.Name,
		Addr:           serverConfig.Addr,
		JWTSecret:      serverConfig.JWTSecret,
		TokenDuration:  tokenDuration,
		TokenIssuer:    serverConfig.TokenIssuer,
		AllowedOrigins: serverConfig.AllowedOrigins,
		AllowedHosts:   serverConfig.AllowedHosts,
		Storage:        deps.storage,
		Cache:          deps.cacheInstance,
		TLS:            serverConfig.TLS,
		TLSCertFile:    serverConfig.TLSCertFile,
		TLSKeyFile:     serverConfig.TLSKeyFile,
		TLSVerify:      serverConfig.TLSVerify,
	}

	mailapi.Start(ctx, deps.resilientDB, options, errChan)
}
