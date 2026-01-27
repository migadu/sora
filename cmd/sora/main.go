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
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/adminapi"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/managesieveproxy"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/relayqueue"
	"github.com/migadu/sora/server/uploader"
	mailapi "github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
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
	storage               *storage.S3Storage
	resilientDB           *resilient.ResilientDatabase
	uploadWorker          *uploader.UploadWorker
	cacheInstance         *cache.Cache
	cleanupWorker         *cleaner.CleanupWorker
	relayQueue            *relayqueue.DiskQueue
	relayWorker           *relayqueue.Worker
	healthIntegration     *health.HealthIntegration
	metricsCollector      *metrics.Collector
	clusterManager        *cluster.Manager
	tlsManager            *tlsmanager.Manager
	affinityManager       *server.AffinityManager
	hostname              string
	config                config.Config
	serverManager         *serverManager
	connectionTrackers    map[string]*server.ConnectionTracker // protocol -> tracker (for admin API kick)
	connectionTrackersMux sync.Mutex                           // protects connectionTrackers map
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

	// Clean up default database config if user explicitly set empty sections
	// This allows proxy-only mode without database
	cleanupDatabaseDefaults(&cfg)

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
	logger.Info("SORA application starting", "version", version, "commit", commit, "built", date)
	logger.Info("Logging configuration", "format", cfg.Logging.Format, "level", cfg.Logging.Level)

	// Initialize global timeout scheduler with configured shard count
	shardCount := cfg.TimeoutScheduler.ShardCount
	if err := server.InitializeGlobalTimeoutScheduler(shardCount); err != nil {
		errorHandler.FatalError("initialize timeout scheduler", err)
		os.Exit(errorHandler.WaitForExit())
	}
	switch shardCount {
	case 0:
		logger.Info("Timeout scheduler initialized", "mode", "default", "shards", "runtime.NumCPU()")
	case -1:
		logger.Info("Timeout scheduler initialized", "mode", "physical_cores", "shards", "runtime.NumCPU()/2")
	default:
		logger.Info("Timeout scheduler initialized", "mode", "custom", "shards", shardCount)
	}

	// Set up context and signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChan
		logger.Info("Received signal - shutting down", "signal", sig)
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
	if deps.relayWorker != nil {
		defer deps.relayWorker.Stop()
	}

	// Start all configured servers
	errChan := startServers(ctx, deps)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		errorHandler.Shutdown(ctx)
		// Wait for all servers to finish shutting down gracefully before releasing resources
		logger.Info("Waiting for all servers to stop gracefully")

		// Wait for server functions to return (listeners closed, Serve() calls returned)
		done := make(chan struct{})
		go func() {
			deps.serverManager.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.Info("All server listeners closed")
		case <-time.After(10 * time.Second):
			logger.Warn("Server shutdown timeout reached after 10 seconds")
		}

		// Give additional time for connection goroutines to finish and release database resources
		// This ensures advisory locks are released and no goroutines are accessing the database
		logger.Info("Waiting for active connections to finish")
		time.Sleep(3 * time.Second)
		logger.Info("Shutdown grace period complete - releasing database resources")
	case err := <-errChan:
		errorHandler.FatalError("server operation", err)
		os.Exit(errorHandler.WaitForExit())
	}
}

// cleanupDatabaseDefaults clears default database config if the TOML explicitly has empty sections
// This allows proxy-only deployments without database
func cleanupDatabaseDefaults(cfg *config.Config) {
	// If database.write section exists but has default "localhost", clear it
	// This happens when user has [database.write] but no hosts specified
	if cfg.Database.Write != nil {
		if len(cfg.Database.Write.Hosts) == 1 && cfg.Database.Write.Hosts[0] == "localhost" &&
			cfg.Database.Write.User == "postgres" && cfg.Database.Write.Name == "sora_mail_db" {
			// This looks like unmodified defaults - user probably wants no database
			logger.Debug("Detected default database.write config - clearing for proxy-only mode")
			cfg.Database.Write = nil
		}
	}

	// Same for read config
	if cfg.Database.Read != nil {
		if len(cfg.Database.Read.Hosts) == 1 && cfg.Database.Read.Hosts[0] == "localhost" &&
			cfg.Database.Read.User == "postgres" && cfg.Database.Read.Name == "sora_mail_db" {
			logger.Debug("Detected default database.read config - clearing for proxy-only mode")
			cfg.Database.Read = nil
		}
	}
}

// loadAndValidateConfig loads configuration from file and validates all server configurations
func loadAndValidateConfig(configPath string, cfg *config.Config, errorHandler *errors.ErrorHandler) {
	// Load configuration from TOML file
	if err := config.LoadConfigFromFile(configPath, cfg); err != nil {
		if os.IsNotExist(err) {
			// If default config doesn't exist, that's okay - use defaults
			if configPath == "config.toml" {
				logger.Info("Default configuration file not found - using application defaults", "path", configPath)
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
		logger.Info("Loaded configuration", "path", configPath)
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

	logger.Info("Found configured servers", "count", len(allServers))
}

// initializeServices initializes all core services (S3, database, cache, workers) if storage services are needed
func initializeServices(ctx context.Context, cfg config.Config, errorHandler *errors.ErrorHandler) (*serverDependencies, error) {
	hostname, _ := os.Hostname()

	// Determine if any mail storage services are enabled
	allServers := cfg.GetAllServers()
	storageServicesNeeded := false
	databaseNeeded := false

	// Check if database is actually configured
	// Database is configured if either write or read has valid hosts
	databaseConfigured := (cfg.Database.Write != nil && len(cfg.Database.Write.Hosts) > 0) ||
		(cfg.Database.Read != nil && len(cfg.Database.Read.Hosts) > 0)

	for _, server := range allServers {
		if server.Type == "imap" || server.Type == "lmtp" || server.Type == "pop3" {
			storageServicesNeeded = true
			databaseNeeded = true
			break
		}
		// Check if proxy servers need database (when lookup_local_users=true)
		if server.Type == "imap_proxy" || server.Type == "pop3_proxy" || server.Type == "managesieve_proxy" || server.Type == "lmtp_proxy" || server.Type == "user_api_proxy" {
			if server.RemoteLookup != nil && server.RemoteLookup.ShouldLookupLocalUsers() {
				databaseNeeded = true
			}
		}
		// Admin API and User API need database for account management
		if server.Type == "http_admin_api" || server.Type == "http_user_api" {
			databaseNeeded = true
		}
	}

	// If database is needed but not configured, that's an error
	if databaseNeeded && !databaseConfigured {
		errorHandler.ValidationError("database configuration", fmt.Errorf("database is required for configured servers but not configured in [database.write] or [database.read]"))
		os.Exit(errorHandler.WaitForExit())
	}

	// Override: if database is not configured at all, force databaseNeeded to false
	// This allows proxy-only mode without database config
	if !databaseConfigured {
		databaseNeeded = false
		logger.Info("Database not configured - forcing proxy-only mode (lookup_local_users will be treated as false)")
	}

	deps := &serverDependencies{
		hostname:           hostname,
		config:             cfg,
		serverManager:      &serverManager{}, // Initialize server manager for coordinated shutdown
		connectionTrackers: make(map[string]*server.ConnectionTracker),
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
		logger.Info("Connecting to S3", "endpoint", s3EndpointToUse, "bucket", cfg.S3.Bucket)
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

	// Initialize the resilient database with runtime failover (if needed)
	var err error
	if databaseNeeded {
		logger.Info("Connecting to database with resilient failover configuration")
		deps.resilientDB, err = resilient.NewResilientDatabase(ctx, &cfg.Database, true, true)
		if err != nil {
			logger.Info("Failed to initialize resilient database", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("Skipping database initialization - running in proxy-only mode with remote_lookup")
	}

	// Start database metrics and health monitoring if database is available
	if deps.resilientDB != nil {
		deps.resilientDB.StartPoolMetrics(ctx)
		deps.resilientDB.StartPoolHealthMonitoring(ctx)
		logger.Info("Database resilience features initialized: failover, circuit breakers, pool monitoring")
	}

	// Initialize health monitoring
	logger.Info("Initializing health monitoring")
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

		logger.Info("Cache: Starting metrics collection", "interval", metricsInterval)
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
						logger.Info("Cache: Failed to store metrics", "error", err)
					}
				case <-cleanupTicker.C:
					if deleted, err := deps.resilientDB.CleanupOldCacheMetricsWithRetry(ctx, metricsRetention); err != nil {
						logger.Info("Cache: Failed to cleanup old metrics", "error", err)
					} else if deleted > 0 {
						logger.Info("Cache: Cleaned up old metrics records", "count", deleted)
					}
				}
			}
		}()

		// Initialize and start the cleanup worker using configuration defaulting methods
		gracePeriod := cfg.Cleanup.GetGracePeriodWithDefault()
		wakeInterval := cfg.Cleanup.GetWakeIntervalWithDefault()
		maxAgeRestriction := cfg.Cleanup.GetMaxAgeRestrictionWithDefault()
		ftsRetention := cfg.Cleanup.GetFTSRetentionWithDefault()
		healthStatusRetention := cfg.Cleanup.GetHealthStatusRetentionWithDefault()

		cleanupErrChan := make(chan error, 1)
		deps.cleanupWorker = cleaner.New(deps.resilientDB, deps.storage, deps.cacheInstance, wakeInterval, gracePeriod, maxAgeRestriction, ftsRetention, healthStatusRetention, cleanupErrChan)

		// Start error listener for cleanup worker
		go func() {
			for err := range cleanupErrChan {
				logger.Error("Cleanup worker error", "error", err)
			}
		}()

		if err := deps.cleanupWorker.Start(ctx); err != nil {
			errorHandler.FatalError("start cleanup worker", err)
			os.Exit(errorHandler.WaitForExit())
		}

		// Initialize and start the upload worker
		retryInterval := cfg.Uploader.GetRetryIntervalWithDefault()
		uploadErrChan := make(chan error, 1)
		deps.uploadWorker, err = uploader.New(ctx, cfg.Uploader.Path, cfg.Uploader.BatchSize, cfg.Uploader.Concurrency, cfg.Uploader.MaxAttempts, retryInterval, hostname, deps.resilientDB, deps.storage, deps.cacheInstance, uploadErrChan)
		if err != nil {
			errorHandler.FatalError("create upload worker", err)
			os.Exit(errorHandler.WaitForExit())
		}

		// Start error listener for upload worker
		go func() {
			for err := range uploadErrChan {
				logger.Error("Upload worker error", "error", err)
			}
		}()

		if err := deps.uploadWorker.Start(ctx); err != nil {
			errorHandler.FatalError("start upload worker", err)
			os.Exit(errorHandler.WaitForExit())
		}
	} else {
		logger.Info("Skipping startup of cache, uploader, and cleaner services as no mail storage services (IMAP, POP3, LMTP) are enabled.")
	}

	// Initialize relay queue and worker if enabled
	if cfg.Relay.IsQueueEnabled() {
		logger.Info("Initializing relay queue and worker")

		// Parse configuration
		backoff, err := cfg.Relay.Queue.GetRetryBackoff()
		if err != nil {
			logger.Warn("Invalid relay queue backoff configuration - using defaults", "error", err)
			backoff = nil // Will use defaults in NewDiskQueue
		}

		workerInterval, err := cfg.Relay.Queue.GetWorkerInterval()
		if err != nil {
			logger.Warn("Invalid relay queue worker interval - using default (1m)", "error", err)
			workerInterval = 1 * time.Minute
		}

		// Create disk queue
		queuePath := cfg.Relay.GetQueuePath()
		deps.relayQueue, err = relayqueue.NewDiskQueue(
			queuePath,
			cfg.Relay.Queue.MaxAttempts,
			backoff,
		)
		if err != nil {
			errorHandler.FatalError("create relay queue", err)
			os.Exit(errorHandler.WaitForExit())
		}

		logger.Info("Relay queue initialized", "path", queuePath, "max_attempts", cfg.Relay.Queue.MaxAttempts)

		// Create relay handler from global relay config if configured
		if cfg.Relay.IsConfigured() {
			var relayHandler delivery.RelayHandler
			var relayType string

			// Parse circuit breaker configuration
			cbThreshold := cfg.Relay.Queue.GetCircuitBreakerThreshold()
			cbTimeout, err := cfg.Relay.Queue.GetCircuitBreakerTimeout()
			if err != nil {
				errorHandler.FatalError("parse circuit breaker timeout", err)
				os.Exit(errorHandler.WaitForExit())
			}
			cbMaxRequests := cfg.Relay.Queue.GetCircuitBreakerMaxRequests()

			cbConfig := delivery.CircuitBreakerConfig{
				Threshold:   cbThreshold,
				Timeout:     cbTimeout,
				MaxRequests: cbMaxRequests,
			}

			if cfg.Relay.IsSMTP() {
				relayType = "smtp"
				relayHandler = delivery.NewRelayHandlerFromConfig(
					relayType,
					cfg.Relay.SMTPHost,
					"",
					"",
					"relay_queue",
					cfg.Relay.SMTPTLS,
					cfg.Relay.SMTPTLSVerify,
					cfg.Relay.SMTPUseStartTLS,
					cfg.Relay.SMTPTLSCertFile,
					cfg.Relay.SMTPTLSKeyFile,
					&serverLogger{},
					cbConfig,
				)
				logger.Info("Relay handler configured: type=smtp", "host", cfg.Relay.SMTPHost, "tls", cfg.Relay.SMTPTLS, "starttls", cfg.Relay.SMTPUseStartTLS, "cb_threshold", cbThreshold, "cb_timeout", cbTimeout, "cb_max_requests", cbMaxRequests)
			} else if cfg.Relay.IsHTTP() {
				relayType = "http"
				relayHandler = delivery.NewRelayHandlerFromConfig(
					relayType,
					"",
					cfg.Relay.HTTPURL,
					cfg.Relay.AuthToken,
					"relay_queue",
					false,
					false,
					false,
					"",
					"",
					&serverLogger{},
					cbConfig,
				)
				logger.Info("Relay handler configured: type=http", "url", cfg.Relay.HTTPURL, "cb_threshold", cbThreshold, "cb_timeout", cbTimeout, "cb_max_requests", cbMaxRequests)
			}

			if relayHandler != nil {
				batchSize := cfg.Relay.Queue.BatchSize
				if batchSize <= 0 {
					batchSize = 100 // Default
				}

				concurrency := cfg.Relay.Queue.Concurrency
				if concurrency <= 0 {
					concurrency = 5 // Default concurrency for concurrent message processing
				}

				cleanupInterval, err := cfg.Relay.Queue.GetCleanupInterval()
				if err != nil {
					errorHandler.FatalError("parse cleanup interval", err)
					os.Exit(errorHandler.WaitForExit())
				}

				failedRetention, err := cfg.Relay.Queue.GetFailedRetention()
				if err != nil {
					errorHandler.FatalError("parse failed retention", err)
					os.Exit(errorHandler.WaitForExit())
				}

				errCh := make(chan error, 10) // Buffered error channel

				// Start error listener
				go func() {
					for err := range errCh {
						logger.Error("Relay worker error", "error", err)
					}
				}()

				deps.relayWorker = relayqueue.NewWorker(
					deps.relayQueue,
					relayHandler,
					workerInterval,
					batchSize,
					concurrency,
					cleanupInterval,
					failedRetention,
					errCh,
				)

				if err := deps.relayWorker.Start(ctx); err != nil {
					errorHandler.FatalError("start relay worker", err)
					os.Exit(errorHandler.WaitForExit())
				}

				logger.Info("Relay worker started", "interval", workerInterval, "batch_size", batchSize, "concurrency", concurrency, "cleanup_interval", cleanupInterval, "failed_retention", failedRetention)

				// Register relay queue health check
				deps.healthIntegration.RegisterRelayQueueCheck(deps.relayQueue)
				logger.Info("Registered relay queue health check")

				// Register circuit breaker health check for the relay handler
				if smtpHandler, ok := relayHandler.(*delivery.SMTPRelayHandler); ok {
					if cb := smtpHandler.GetCircuitBreaker(); cb != nil {
						deps.healthIntegration.RegisterCircuitBreakerCheck("smtp_relay", cb)
						logger.Info("Registered SMTP relay circuit breaker health check")
					}
				} else if httpHandler, ok := relayHandler.(*delivery.HTTPRelayHandler); ok {
					if cb := httpHandler.GetCircuitBreaker(); cb != nil {
						deps.healthIntegration.RegisterCircuitBreakerCheck("http_relay", cb)
						logger.Info("Registered HTTP relay circuit breaker health check")
					}
				}
			} else {
				logger.Warn("Relay queue enabled but no valid relay handler configured")
			}
		} else {
			logger.Warn("Relay queue enabled but global [relay] configuration is missing")
		}
	}

	// Initialize cluster manager if enabled
	if cfg.Cluster.Enabled {
		logger.Info("Initializing cluster manager")
		deps.clusterManager, err = cluster.New(cfg.Cluster)
		if err != nil {
			errorHandler.FatalError("initialize cluster manager", err)
			os.Exit(errorHandler.WaitForExit())
		}
		logger.Info("Cluster manager initialized", "node_id", deps.clusterManager.GetNodeID(), "members", deps.clusterManager.GetMemberCount(), "leader", deps.clusterManager.GetLeaderID())

		// Initialize affinity manager for cluster-wide user-to-backend affinity
		// Default TTL: 1 hour, Cleanup interval: 10 minutes
		deps.affinityManager = server.NewAffinityManager(deps.clusterManager, true, 1*time.Hour, 10*time.Minute)
		logger.Info("Affinity manager initialized for cluster-wide user routing")
	}

	// Initialize TLS manager if TLS is enabled
	if cfg.TLS.Enabled {
		logger.Info("Initializing TLS manager", "provider", cfg.TLS.Provider)
		deps.tlsManager, err = tlsmanager.New(cfg.TLS, deps.clusterManager)
		if err != nil {
			errorHandler.FatalError("initialize TLS manager", err)
			os.Exit(errorHandler.WaitForExit())
		}
		logger.Info("TLS manager initialized successfully")
	}

	// Start health monitoring
	deps.healthIntegration.Start(ctx)
	logger.Info("Health monitoring started - collecting metrics every 30-60 seconds")

	// Start metrics collector for database statistics (if database is available)
	if deps.resilientDB != nil {
		deps.metricsCollector = metrics.NewCollector(deps.resilientDB, 60*time.Second)
		go deps.metricsCollector.Start(ctx)
	}

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
				logger.Info("Starting HTTP-01 challenge server on :80 for Let's Encrypt")
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
						logger.Warn("HTTP-01 challenge server shutdown error", "error", err)
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
		server.WarnUnusedConfigOptions(func(format string, args ...any) { logger.Info(fmt.Sprintf(format, args...)) })

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
		case "user_api_proxy":
			go startDynamicUserAPIProxyServer(ctx, deps, server, errChan)
		default:
			logger.Info("Unknown server type - skipping", "type", server.Type, "name", server.Name)
		}
	}

	return errChan
}

// startConnectionTrackerForProxy initializes and starts a connection tracker for a proxy server (with gossip).
// Returns both the tracker and the map key to use for registration.
func startConnectionTrackerForProxy(protocol string, serverName string, hostname string, maxConnectionsPerUser int, maxConnectionsPerUserPerIP int, clusterMgr *cluster.Manager, clusterCfg *config.ClusterConfig, srv interface {
	SetConnectionTracker(*server.ConnectionTracker)
}) (*server.ConnectionTracker, string) {
	instanceID := fmt.Sprintf("%s-%s", hostname, serverName)

	// LMTP proxy connections are short-lived (often seconds) and typically originate from
	// trusted internal infrastructure.
	//
	// Cluster-wide gossip tracking (especially snapshot-only at 60s intervals) is not useful
	// and can add overhead and complexity for little gain.
	//
	// For LMTP we keep a local-only tracker for monitoring/visibility, and we force limits
	// to 0 to ensure tracking never rejects delivery connections.
	if protocol == "LMTP" {
		logger.Info("Proxy: Starting local LMTP connection tracker (no gossip)",
			"protocol", protocol,
			"name", serverName,
			"instance", instanceID,
			"max_per_user", 0,
			"max_per_user_per_ip", 0,
		)

		tracker := server.NewConnectionTracker(protocol, instanceID, nil, 0, 0, 0, false)
		if tracker != nil {
			srv.SetConnectionTracker(tracker)
		}
		mapKey := protocol + "-" + instanceID
		return tracker, mapKey
	}

	// Other proxy protocols use cluster-wide gossip tracking.
	if clusterMgr == nil {
		logger.Debug("Proxy: Connection tracking disabled (requires cluster mode)", "protocol", protocol, "name", serverName)
		return nil, ""
	}

	// Get queue size from config (or use default)
	maxEventQueueSize := 0
	if clusterCfg != nil {
		maxEventQueueSize = clusterCfg.GetMaxEventQueueSize()
	}

	logger.Info("Proxy: Starting gossip connection tracker", "protocol", protocol, "name", serverName, "instance", instanceID, "max_per_user", maxConnectionsPerUser, "max_per_user_per_ip", maxConnectionsPerUserPerIP)

	tracker := server.NewConnectionTracker(protocol, instanceID, clusterMgr, maxConnectionsPerUser, maxConnectionsPerUserPerIP, maxEventQueueSize, false)
	if tracker != nil {
		srv.SetConnectionTracker(tracker)
	}

	// Return tracker and the map key (protocol-instanceID for uniqueness across cluster)
	mapKey := protocol + "-" + instanceID
	return tracker, mapKey
}

// Dynamic server functions
func startDynamicIMAPServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	appendLimit := serverConfig.GetAppendLimitWithDefault()
	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	// Parse search rate limit window
	searchRateLimitWindow, err := serverConfig.GetSearchRateLimitWindow()
	if err != nil {
		logger.Info("IMAP: Invalid search rate limit window - using default (1 minute)", "name", serverConfig.Name, "error", err)
		searchRateLimitWindow = time.Minute
	}

	// Parse session memory limit
	sessionMemoryLimit, err := serverConfig.GetSessionMemoryLimit()
	if err != nil {
		logger.Info("IMAP: Invalid session memory limit - using default (100MB)", "name", serverConfig.Name, "error", err)
		sessionMemoryLimit = 100 * 1024 * 1024
	}

	// Parse auth idle timeout
	authIdleTimeout, err := serverConfig.GetAuthIdleTimeout()
	if err != nil {
		logger.Info("IMAP: Invalid auth idle timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		authIdleTimeout = 0
	}

	// Parse command timeout
	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Info("IMAP: Invalid command timeout - using default (5 minutes)", "name", serverConfig.Name, "error", err)
		commandTimeout = 5 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("IMAP: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
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
			ListenBacklog:                serverConfig.ListenBacklog,
			ProxyProtocol:                serverConfig.ProxyProtocol,
			ProxyProtocolTimeout:         proxyProtocolTimeout,
			TrustedNetworks:              deps.config.Servers.TrustedNetworks,
			AuthRateLimit:                authRateLimit,
			LookupCache:                  serverConfig.LookupCache,
			SearchRateLimitPerMin:        serverConfig.GetSearchRateLimitPerMin(),
			SearchRateLimitWindow:        searchRateLimitWindow,
			SessionMemoryLimit:           sessionMemoryLimit,
			AuthIdleTimeout:              authIdleTimeout,
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

	// Start local connection tracker for backend server
	if serverConfig.MaxConnectionsPerUser > 0 {
		instanceID := fmt.Sprintf("%s-%s", deps.hostname, serverConfig.Name)
		tracker := server.NewConnectionTracker("IMAP", instanceID, nil, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, 0, false)
		if tracker != nil {
			s.SetConnTracker(tracker)
			defer tracker.Stop()
			// Store in deps for admin API access
			if deps.connectionTrackers != nil {
				deps.connectionTrackersMux.Lock()
				deps.connectionTrackers["IMAP-"+serverConfig.Name] = tracker
				deps.connectionTrackersMux.Unlock()
			}
		}
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
		logger.Info("LMTP: Invalid max_message_size - using default (50MB)", "name",
			serverConfig.Name, err)
		maxMessageSize = 50 * 1024 * 1024
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	lmtpServer, err := lmtp.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, lmtp.LMTPServerOptions{
		RelayQueue:           deps.relayQueue,  // Global relay queue
		RelayWorker:          deps.relayWorker, // Global relay worker for immediate processing
		TLSVerify:            serverConfig.TLSVerify,
		TLS:                  serverConfig.TLS,
		TLSCertFile:          serverConfig.TLSCertFile,
		TLSKeyFile:           serverConfig.TLSKeyFile,
		TLSUseStartTLS:       serverConfig.TLSUseStartTLS,
		TLSConfig:            tlsConfig,
		Debug:                serverConfig.Debug,
		MaxConnections:       serverConfig.MaxConnections,
		MaxConnectionsPerIP:  serverConfig.MaxConnectionsPerIP,
		ListenBacklog:        serverConfig.ListenBacklog,
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
		logger.Info("Shutting down LMTP server", "name", serverConfig.Name)
		if err := lmtpServer.Close(); err != nil {
			logger.Info("Error closing LMTP server", "error", err)
		}
	}()

	lmtpServer.Start(errChan)
}

func startDynamicPOP3Server(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	sessionMemoryLimit, err := serverConfig.GetSessionMemoryLimit()
	if err != nil {
		logger.Info("POP3: Invalid session memory limit - using default (100MB)", "name",
			serverConfig.Name, err)
		sessionMemoryLimit = 100 * 1024 * 1024
	}

	// Parse auth idle timeout
	authIdleTimeout, err := serverConfig.GetAuthIdleTimeout()
	if err != nil {
		logger.Info("POP3: Invalid auth idle timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		authIdleTimeout = 0
	}

	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Info("POP3: Invalid command timeout - using default (2 minutes)", "name",
			serverConfig.Name, err)
		commandTimeout = 2 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("POP3: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
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
		ListenBacklog:          serverConfig.ListenBacklog,
		ProxyProtocol:          serverConfig.ProxyProtocol,
		ProxyProtocolTimeout:   proxyProtocolTimeout,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		AuthRateLimit:          authRateLimit,
		LookupCache:            serverConfig.LookupCache,
		SessionMemoryLimit:     sessionMemoryLimit,
		AuthIdleTimeout:        authIdleTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		Config:                 &deps.config,
	})

	if err != nil {
		errChan <- err
		return
	}

	// Start local connection tracker for backend server
	if serverConfig.MaxConnectionsPerUser > 0 {
		instanceID := fmt.Sprintf("%s-%s", deps.hostname, serverConfig.Name)
		tracker := server.NewConnectionTracker("POP3", instanceID, nil, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, 0, false)
		if tracker != nil {
			s.SetConnTracker(tracker)
			defer tracker.Stop()
			// Store in deps for admin API access
			if deps.connectionTrackers != nil {
				deps.connectionTrackersMux.Lock()
				deps.connectionTrackers["POP3-"+serverConfig.Name] = tracker
				deps.connectionTrackersMux.Unlock()
			}
		}
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down POP3 server", "name", serverConfig.Name)
		s.Close()
	}()

	s.Start(errChan)
}

func startDynamicManageSieveServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	maxSize := serverConfig.GetMaxScriptSizeWithDefault()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	authIdleTimeout, err := serverConfig.GetAuthIdleTimeout()
	if err != nil {
		logger.Info("ManageSieve: Invalid auth idle timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		authIdleTimeout = 0
	}

	commandTimeout, err := serverConfig.GetCommandTimeout()
	if err != nil {
		logger.Info("ManageSieve: Invalid command timeout - using default (3 minutes)", "name",
			serverConfig.Name, err)
		commandTimeout = 3 * time.Minute
	}

	// Parse absolute session timeout
	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("ManageSieve: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	s, err := managesieve.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.resilientDB, managesieve.ManageSieveServerOptions{
		InsecureAuth:           serverConfig.InsecureAuth,
		TLSVerify:              serverConfig.TLSVerify,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSUseStartTLS:         serverConfig.TLSUseStartTLS,
		TLSConfig:              tlsConfig,
		Debug:                  serverConfig.Debug,
		MaxScriptSize:          maxSize,
		SupportedExtensions:    serverConfig.SupportedExtensions,
		MasterSASLUsername:     serverConfig.MasterSASLUsername,
		MasterSASLPassword:     serverConfig.MasterSASLPassword,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		ListenBacklog:          serverConfig.ListenBacklog,
		ProxyProtocol:          serverConfig.ProxyProtocol,
		ProxyProtocolTimeout:   proxyProtocolTimeout,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		AuthRateLimit:          authRateLimit,
		LookupCache:            serverConfig.LookupCache,
		AuthIdleTimeout:        authIdleTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		Config:                 &deps.config,
	})

	if err != nil {
		errChan <- err
		return
	}

	// Start local connection tracker for backend server
	if serverConfig.MaxConnectionsPerUser > 0 {
		instanceID := fmt.Sprintf("%s-%s", deps.hostname, serverConfig.Name)
		tracker := server.NewConnectionTracker("ManageSieve", instanceID, nil, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, 0, false)
		if tracker != nil {
			s.SetConnTracker(tracker)
			defer tracker.Stop()
			// Store in deps for admin API access
			if deps.connectionTrackers != nil {
				deps.connectionTrackersMux.Lock()
				deps.connectionTrackers["ManageSieve-"+serverConfig.Name] = tracker
				deps.connectionTrackersMux.Unlock()
			}
		}
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down ManageSieve server", "name", serverConfig.Name)
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
		logger.Info("Shutting down metrics server", "name", serverConfig.Name)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Info("Error shutting down metrics server", "error", err)
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
	authIdleTimeout := serverConfig.GetAuthIdleTimeoutWithDefault()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
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
		logger.Info("IMAP proxy: Invalid command timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		commandTimeout = 0 // IMAP proxy cannot detect IDLE commands, so command_timeout must be disabled
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("IMAP proxy: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	server, err := imapproxy.New(ctx, deps.resilientDB, deps.hostname, imapproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		MasterUsername:         serverConfig.MasterUsername,
		MasterPassword:         serverConfig.MasterPassword,
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
		AuthIdleTimeout:        authIdleTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		EnableAffinity:         serverConfig.EnableAffinity,
		AuthRateLimit:          authRateLimit,
		LookupCache:            serverConfig.LookupCache,
		RemoteLookup:           serverConfig.RemoteLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		ListenBacklog:          serverConfig.ListenBacklog,
		MaxAuthErrors:          serverConfig.GetMaxAuthErrors(),
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
			logger.Info("IMAP Proxy: Affinity manager attached to connection manager", "name", serverConfig.Name)
		}

		// Register remotelookup health check if remotelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.RemoteLookupHealthChecker); ok {
				deps.healthIntegration.RegisterRemoteLookupCheck(healthChecker, serverConfig.Name)
				logger.Info("Registered remotelookup health check for IMAP proxy", "name", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker, mapKey := startConnectionTrackerForProxy("IMAP", serverConfig.Name, deps.hostname, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, deps.clusterManager, &deps.config.Cluster, server); tracker != nil {
		defer tracker.Stop()
		deps.connectionTrackersMux.Lock()
		deps.connectionTrackers[mapKey] = tracker
		deps.connectionTrackersMux.Unlock()
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down IMAP proxy server", "name", serverConfig.Name)
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
	authIdleTimeout := serverConfig.GetAuthIdleTimeoutWithDefault()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
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
		logger.Info("POP3 proxy: Invalid command timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		commandTimeout = 0 // Proxies should use auth_idle_timeout and absolute_session_timeout
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("POP3 proxy: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	server, err := pop3proxy.New(ctx, deps.hostname, serverConfig.Addr, deps.resilientDB, pop3proxy.POP3ProxyServerOptions{
		Name:                   serverConfig.Name,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		MasterUsername:         serverConfig.MasterUsername,
		MasterPassword:         serverConfig.MasterPassword,
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
		AuthIdleTimeout:        authIdleTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		Debug:                  serverConfig.Debug,
		EnableAffinity:         serverConfig.EnableAffinity,
		AuthRateLimit:          authRateLimit,
		RemoteLookup:           serverConfig.RemoteLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		ListenBacklog:          serverConfig.ListenBacklog,
		LookupCache:            serverConfig.LookupCache,
		MaxAuthErrors:          serverConfig.GetMaxAuthErrors(),
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create POP3 proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Info("POP3 Proxy: Affinity manager attached to connection manager", "name", serverConfig.Name)
		}

		// Register remotelookup health check if remotelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.RemoteLookupHealthChecker); ok {
				deps.healthIntegration.RegisterRemoteLookupCheck(healthChecker, serverConfig.Name)
				logger.Info("Registered remotelookup health check for POP3 proxy", "name", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker, mapKey := startConnectionTrackerForProxy("POP3", serverConfig.Name, deps.hostname, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, deps.clusterManager, &deps.config.Cluster, server); tracker != nil {
		defer tracker.Stop()
		deps.connectionTrackersMux.Lock()
		deps.connectionTrackers[mapKey] = tracker
		deps.connectionTrackersMux.Unlock()
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down POP3 proxy server", "name", serverConfig.Name)
		server.Stop()
	}()

	server.Start()
}

func startDynamicManageSieveProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	authIdleTimeout := serverConfig.GetAuthIdleTimeoutWithDefault()

	authRateLimit := server.DefaultAuthRateLimiterConfig()
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
		logger.Info("ManageSieve proxy: Invalid command timeout - using default (0 = disabled)", "name", serverConfig.Name, "error", err)
		commandTimeout = 0 // Proxies should use auth_idle_timeout and absolute_session_timeout
	}

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("ManageSieve proxy: Invalid absolute session timeout - using default (30 minutes)", "name", serverConfig.Name, "error", err)
		absoluteSessionTimeout = 30 * time.Minute
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	server, err := managesieveproxy.New(ctx, deps.resilientDB, deps.hostname, managesieveproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		InsecureAuth:           serverConfig.InsecureAuth,
		MasterUsername:         serverConfig.MasterUsername,
		MasterPassword:         serverConfig.MasterPassword,
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
		AuthIdleTimeout:        authIdleTimeout,
		CommandTimeout:         commandTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		MinBytesPerMinute:      serverConfig.GetMinBytesPerMinute(),
		AuthRateLimit:          authRateLimit,
		RemoteLookup:           serverConfig.RemoteLookup,
		EnableAffinity:         serverConfig.EnableAffinity,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxConnections:         serverConfig.MaxConnections,
		MaxConnectionsPerIP:    serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:        deps.config.Servers.TrustedNetworks,
		ListenBacklog:          serverConfig.ListenBacklog,
		Debug:                  serverConfig.Debug,
		SupportedExtensions:    serverConfig.SupportedExtensions,
		LookupCache:            serverConfig.LookupCache,
		MaxAuthErrors:          serverConfig.GetMaxAuthErrors(),
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create ManageSieve proxy server: %w", err)
		return
	}

	// Set affinity manager on connection manager if cluster is enabled
	if connMgr := server.GetConnectionManager(); connMgr != nil {
		if deps.affinityManager != nil {
			connMgr.SetAffinityManager(deps.affinityManager)
			logger.Info("ManageSieve Proxy: Affinity manager attached to connection manager", "name", serverConfig.Name)
		}

		// Register remotelookup health check if remotelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.RemoteLookupHealthChecker); ok {
				deps.healthIntegration.RegisterRemoteLookupCheck(healthChecker, serverConfig.Name)
				logger.Info("Registered remotelookup health check for ManageSieve proxy", "name", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker, mapKey := startConnectionTrackerForProxy("ManageSieve", serverConfig.Name, deps.hostname, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, deps.clusterManager, &deps.config.Cluster, server); tracker != nil {
		defer tracker.Stop()
		deps.connectionTrackersMux.Lock()
		deps.connectionTrackers[mapKey] = tracker
		deps.connectionTrackersMux.Unlock()
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down ManageSieve proxy server", "name", serverConfig.Name)
		server.Stop()
	}()

	server.Start()
}

func startDynamicLMTPProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	// Warn if user configured connection limits (they will be ignored for LMTP)
	if serverConfig.MaxConnectionsPerUser > 0 {
		logger.Warn("LMTP proxy: max_connections_per_user configured but will be ignored (LMTP uses local-only tracking with limits disabled)",
			"name", serverConfig.Name,
			"configured_value", serverConfig.MaxConnectionsPerUser)
	}
	if serverConfig.MaxConnectionsPerUserPerIP > 0 {
		logger.Warn("LMTP proxy: max_connections_per_user_per_ip configured but will be ignored (LMTP uses local-only tracking with limits disabled)",
			"name", serverConfig.Name,
			"configured_value", serverConfig.MaxConnectionsPerUserPerIP)
	}

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	authIdleTimeout := serverConfig.GetAuthIdleTimeoutWithDefault()
	maxMessageSize := serverConfig.GetMaxMessageSizeWithDefault()

	absoluteSessionTimeout, err := serverConfig.GetAbsoluteSessionTimeout()
	if err != nil {
		logger.Info("LMTP proxy: Invalid absolute session timeout - using default (5 minutes)", "name", serverConfig.Name, "error", err)
		absoluteSessionTimeout = 5 * time.Minute
	}
	// Override default 24h with 5m for LMTP since connections should be short-lived
	// LMTP is a delivery protocol - messages should be delivered in seconds/minutes, not hours
	// Check if timeout is the default 24h value (either Timeouts is nil or AbsoluteSessionTimeout is empty)
	if absoluteSessionTimeout == 24*time.Hour && (serverConfig.Timeouts == nil || serverConfig.Timeouts.AbsoluteSessionTimeout == "") {
		logger.Info("LMTP proxy: Using LMTP-specific default (5 minutes) instead of generic default (24 hours)", "name", serverConfig.Name)
		absoluteSessionTimeout = 5 * time.Minute
	}

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for LMTP proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Get global TLS config if available and wrap with server-specific default domain
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
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
		AuthIdleTimeout:        authIdleTimeout,
		AbsoluteSessionTimeout: absoluteSessionTimeout,
		EnableAffinity:         serverConfig.EnableAffinity,
		LookupCache:            serverConfig.LookupCache,
		RemoteLookup:           serverConfig.RemoteLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxMessageSize:         maxMessageSize,
		MaxConnections:         serverConfig.MaxConnections,
		ListenBacklog:          serverConfig.ListenBacklog,
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
			logger.Info("LMTP Proxy: Affinity manager attached to connection manager", "name", serverConfig.Name)
		}

		// Register remotelookup health check if remotelookup is enabled
		if routingLookup := connMgr.GetRoutingLookup(); routingLookup != nil {
			if healthChecker, ok := routingLookup.(health.RemoteLookupHealthChecker); ok {
				deps.healthIntegration.RegisterRemoteLookupCheck(healthChecker, serverConfig.Name)
				logger.Info("Registered remotelookup health check for LMTP proxy", "name", serverConfig.Name)
			}
		}
	}

	// Start connection tracker if enabled.
	if tracker, mapKey := startConnectionTrackerForProxy("LMTP", serverConfig.Name, deps.hostname, serverConfig.MaxConnectionsPerUser, serverConfig.MaxConnectionsPerUserPerIP, deps.clusterManager, &deps.config.Cluster, server); tracker != nil {
		defer tracker.Stop()
		deps.connectionTrackersMux.Lock()
		deps.connectionTrackers[mapKey] = tracker
		deps.connectionTrackersMux.Unlock()
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down LMTP proxy server", "name", serverConfig.Name)
		server.Stop()
	}()

	if err := server.Start(); err != nil && ctx.Err() == nil {
		errChan <- fmt.Errorf("LMTP proxy server error: %w", err)
	}
}

func startDynamicHTTPAdminAPIServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	if serverConfig.APIKey == "" {
		logger.Info("HTTP Admin API server enabled but no API key configured - skipping", "name", serverConfig.Name)
		return
	}

	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()

	// Collect valid backends from all proxy server configs
	validBackends := make(map[string][]string)

	// Collect IMAP proxy backends
	if deps.config.Servers.IMAPProxy.Start && len(deps.config.Servers.IMAPProxy.RemoteAddrs) > 0 {
		validBackends["imap"] = append(validBackends["imap"], deps.config.Servers.IMAPProxy.RemoteAddrs...)
	}

	// Collect POP3 proxy backends
	if deps.config.Servers.POP3Proxy.Start && len(deps.config.Servers.POP3Proxy.RemoteAddrs) > 0 {
		validBackends["pop3"] = append(validBackends["pop3"], deps.config.Servers.POP3Proxy.RemoteAddrs...)
	}

	// Collect ManageSieve proxy backends
	if deps.config.Servers.ManageSieveProxy.Start && len(deps.config.Servers.ManageSieveProxy.RemoteAddrs) > 0 {
		validBackends["managesieve"] = append(validBackends["managesieve"], deps.config.Servers.ManageSieveProxy.RemoteAddrs...)
	}

	// Get TLS config from manager if TLS is enabled
	var tlsConfig *tls.Config
	if serverConfig.TLS && deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		if serverConfig.TLSDefaultDomain != "" {
			tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
		}
	}

	options := adminapi.ServerOptions{
		Name:               serverConfig.Name,
		Addr:               serverConfig.Addr,
		APIKey:             serverConfig.APIKey,
		AllowedHosts:       serverConfig.AllowedHosts,
		Cache:              deps.cacheInstance,
		Uploader:           deps.uploadWorker,
		Storage:            deps.storage,
		RelayQueue:         deps.relayQueue, // Global relay queue
		TLS:                serverConfig.TLS,
		TLSConfig:          tlsConfig, // From TLS manager (if available)
		TLSCertFile:        serverConfig.TLSCertFile,
		TLSKeyFile:         serverConfig.TLSKeyFile,
		TLSVerify:          serverConfig.TLSVerify,
		Hostname:           deps.hostname,
		FTSRetention:       ftsRetention,
		AffinityManager:    deps.affinityManager,
		ValidBackends:      validBackends,
		ConnectionTrackers: deps.connectionTrackers,
	}

	adminapi.Start(ctx, deps.resilientDB, options, errChan)
}

func startDynamicHTTPUserAPIServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	if serverConfig.JWTSecret == "" {
		logger.Info("HTTP User API server enabled but no JWT secret configured - skipping", "name", serverConfig.Name)
		return
	}

	// Parse token duration
	tokenDuration := 24 * time.Hour // Default
	if serverConfig.TokenDuration != "" {
		if dur, err := time.ParseDuration(serverConfig.TokenDuration); err == nil {
			tokenDuration = dur
		} else {
			logger.Info("Invalid token_duration for HTTP User API server - using default 24h", "duration", serverConfig.TokenDuration, "name", serverConfig.Name)
		}
	}

	// Get auth rate limit config
	authRateLimit := server.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	// Get TLS config from manager if TLS is enabled
	var tlsConfig *tls.Config
	if serverConfig.TLS && deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		if serverConfig.TLSDefaultDomain != "" {
			tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
		}
	}

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
		AuthRateLimit:  authRateLimit,
		LookupCache:    serverConfig.LookupCache,
		TLS:            serverConfig.TLS,
		TLSConfig:      tlsConfig, // From TLS manager (if available)
		TLSCertFile:    serverConfig.TLSCertFile,
		TLSKeyFile:     serverConfig.TLSKeyFile,
		TLSVerify:      serverConfig.TLSVerify,
	}

	mailapi.Start(ctx, deps.resilientDB, options, errChan)
}

func startDynamicUserAPIProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	deps.serverManager.Add()
	defer deps.serverManager.Done()

	if serverConfig.JWTSecret == "" {
		logger.Info("User API proxy server enabled but no JWT secret configured - skipping", "name", serverConfig.Name)
		return
	}

	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for User API proxy %s: %w", serverConfig.Name, err)
		return
	}

	// Get global TLS config if available
	var tlsConfig *tls.Config
	if deps.tlsManager != nil {
		tlsConfig = deps.tlsManager.GetTLSConfig()
		// Wrap with server-specific default domain if specified
		tlsConfig = tlsmanager.WrapTLSConfigWithDefaultDomain(tlsConfig, serverConfig.TLSDefaultDomain)
	}

	server, err := userapiproxy.New(ctx, deps.resilientDB, userapiproxy.ServerOptions{
		Name:                serverConfig.Name,
		Addr:                serverConfig.Addr,
		RemoteAddrs:         serverConfig.RemoteAddrs,
		RemotePort:          remotePort,
		JWTSecret:           serverConfig.JWTSecret,
		TLS:                 serverConfig.TLS,
		TLSCertFile:         serverConfig.TLSCertFile,
		TLSKeyFile:          serverConfig.TLSKeyFile,
		TLSVerify:           serverConfig.TLSVerify,
		TLSConfig:           tlsConfig,
		RemoteTLS:           serverConfig.RemoteTLS,
		RemoteTLSVerify:     serverConfig.RemoteTLSVerify,
		ConnectTimeout:      connectTimeout,
		MaxConnections:      serverConfig.MaxConnections,
		MaxConnectionsPerIP: serverConfig.MaxConnectionsPerIP,
		TrustedNetworks:     deps.config.Servers.TrustedNetworks,
		TrustedProxies:      deps.config.Servers.TrustedNetworks,
		RemoteLookup:        serverConfig.RemoteLookup,
		LookupCache:         serverConfig.LookupCache,
		AffinityManager:     deps.affinityManager,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create User API proxy server: %w", err)
		return
	}

	go func() {
		<-ctx.Done()
		logger.Info("Shutting down User API proxy server", "name", serverConfig.Name)
		server.Stop()
	}()

	if err := server.Start(); err != nil && ctx.Err() == nil {
		errChan <- fmt.Errorf("user API proxy server error: %w", err)
	}
}

// serverLogger implements delivery.Logger interface using the global logger
type serverLogger struct{}

func (l *serverLogger) Log(format string, args ...any) {
	logger.Info(fmt.Sprintf(format, args...))
}
