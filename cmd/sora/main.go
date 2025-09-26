package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/errors"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/server/httpapi"
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
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Version information, injected at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// serverDependencies encapsulates all shared services and dependencies needed by servers
type serverDependencies struct {
	storage       *storage.S3Storage
	resilientDB   *resilient.ResilientDatabase
	uploadWorker  *uploader.UploadWorker
	cacheInstance *cache.Cache
	cleanupWorker *cleaner.CleanupWorker
	hostname      string
	config        config.Config
}

func main() {
	errorHandler := errors.NewErrorHandler()
	cfg := config.NewDefaultConfig()

	// Parse command-line flags
	showVersion := flag.Bool("version", false, "Show version information and exit")
	flag.BoolVar(showVersion, "v", false, "Show version information and exit")
	configPath := flag.String("config", "config.toml", "Path to TOML configuration file")
	fLogOutput := flag.String("logoutput", cfg.LogOutput, "Log output destination: 'syslog', 'stderr', 'stdout', or file path")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sora version %s (commit: %s, built at: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Load and validate configuration
	loadAndValidateConfig(*configPath, &cfg, errorHandler)

	// Apply command-line flag overrides
	finalLogOutput := cfg.LogOutput
	if isFlagSet("logoutput") {
		finalLogOutput = *fLogOutput
	}

	// Initialize logging
	logFile := initializeLogging(finalLogOutput)
	if logFile != nil {
		defer func(f *os.File) {
			fmt.Fprintf(os.Stderr, "SORA: Closing log file %s\n", f.Name())
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "SORA: Error closing log file %s: %v\n", f.Name(), err)
			}
		}(logFile)
	}

	// Set up context and signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChan
		log.Printf("Received signal: %s, shutting down...", sig)
		cancel()
	}()

	// Initialize all core services
	deps, err := initializeServices(ctx, cfg, errorHandler)
	if err != nil {
		errorHandler.FatalError("initialize services", err)
		os.Exit(errorHandler.WaitForExit())
	}

	// Clean up resources on exit
	if deps.resilientDB != nil {
		defer deps.resilientDB.Close()
	}
	if deps.cacheInstance != nil {
		defer deps.cacheInstance.Close()
	}

	// Start all configured servers
	errChan := startServers(ctx, deps)

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		errorHandler.Shutdown(ctx)
	case err := <-errChan:
		errorHandler.FatalError("server operation", err)
		os.Exit(errorHandler.WaitForExit())
	}
}

// initializeLogging sets up the logging system based on the configuration
func initializeLogging(finalLogOutput string) *os.File {
	var logFile *os.File
	var initialLogMessage string

	switch finalLogOutput {
	case "stdout":
		log.SetOutput(os.Stdout)
		initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to standard output (selected by '%s').", finalLogOutput)
	case "syslog":
		if runtime.GOOS != "windows" {
			syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "sora")
			if err != nil {
				log.Printf("WARNING: failed to connect to syslog (specified by '%s'): %v. Logging will fall back to standard error.", finalLogOutput, err)
				initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (syslog connection failed, selected by '%s').", finalLogOutput)
			} else {
				log.SetOutput(syslogWriter)
				log.SetFlags(0) // syslog handles timestamps
				defer syslogWriter.Close()
				initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to syslog (selected by '%s').", finalLogOutput)
			}
		} else {
			log.Printf("WARNING: syslog logging is not supported on Windows (specified by '%s'). Logging will fall back to standard error.", finalLogOutput)
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (syslog not supported on this OS, selected by '%s').", finalLogOutput)
		}
	case "stderr":
		initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to standard error (selected by '%s').", finalLogOutput)
	default:
		// Assume it's a file path
		var openErr error
		logFile, openErr = os.OpenFile(finalLogOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if openErr != nil {
			log.Printf("WARNING: failed to open log file '%s' (specified by '%s'): %v. Logging will fall back to standard error.", finalLogOutput, finalLogOutput, openErr)
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (failed to open log file '%s', selected by '%s').", finalLogOutput, finalLogOutput)
			logFile = nil // Ensure logFile is nil if open failed
		} else {
			log.SetOutput(logFile)

			// Redirect both stdout and stderr to the log file
			// This ensures all output (including panics, direct writes, and error handler output) goes to the file
			os.Stdout = logFile
			os.Stderr = logFile

			// Keep standard log flags (date, time) for file logging
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to file '%s' (selected by '%s').", finalLogOutput, finalLogOutput)
		}
	}
	log.Println(initialLogMessage)

	log.Println("")
	log.Println(" ▗▄▄▖ ▗▄▖ ▗▄▄▖  ▗▄▖  ")
	log.Println("▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ")
	log.Println(" ▝▀▚▖▐▌ ▐▌▐▛▀▚▖▐▛▀▜▌ ")
	log.Println("▗▄▄▞▘▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌ ")
	log.Println("")

	return logFile
}

// loadAndValidateConfig loads configuration from file and validates all server configurations
func loadAndValidateConfig(configPath string, cfg *config.Config, errorHandler *errors.ErrorHandler) {
	// Load configuration from TOML file
	if err := config.LoadConfigFromFile(configPath, cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet("config") { // User explicitly set -config
				errorHandler.ConfigError(configPath, err)
				os.Exit(errorHandler.WaitForExit())
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using application defaults.", configPath)
			}
		} else {
			errorHandler.ConfigError(configPath, err)
			os.Exit(errorHandler.WaitForExit())
		}
	} else {
		log.Printf("loaded configuration from %s", configPath)
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

	log.Printf("Found %d configured servers", len(allServers))
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
		hostname: hostname,
		config:   cfg,
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
		log.Printf("Connecting to S3 endpoint '%s', bucket '%s'", s3EndpointToUse, cfg.S3.Bucket)
		var err error
		deps.storage, err = storage.New(s3EndpointToUse, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.Trace)
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
	log.Printf("Connecting to database with resilient failover configuration")
	var err error
	deps.resilientDB, err = resilient.NewResilientDatabase(ctx, &cfg.Database, true, true)
	if err != nil {
		log.Printf("Failed to initialize resilient database: %v", err)
		os.Exit(1)
	}

	// Start the new aggregated metrics and health monitoring for all managed pools
	deps.resilientDB.StartPoolMetrics(ctx)
	deps.resilientDB.StartPoolHealthMonitoring(ctx)
	log.Printf("Database resilience features initialized: failover, circuit breakers, pool monitoring")

	// Initialize health monitoring
	log.Printf("Initializing health monitoring...")
	healthIntegration := health.NewHealthIntegration(deps.resilientDB)

	if storageServicesNeeded {
		log.Println("Mail storage services are enabled. Starting cache, uploader, and cleaner.")

		// Register S3 health check
		healthIntegration.RegisterS3Check(deps.storage)

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
		healthIntegration.RegisterCustomCheck(&health.HealthCheck{
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
		healthIntegration.RegisterCustomCheck(&health.HealthCheck{
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

		log.Printf("[CACHE] starting metrics collection with interval: %v", metricsInterval)
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
						log.Printf("[CACHE] WARNING: failed to store metrics: %v", err)
					}
				case <-cleanupTicker.C:
					if deleted, err := deps.resilientDB.CleanupOldCacheMetricsWithRetry(ctx, metricsRetention); err != nil {
						log.Printf("[CACHE] WARNING: failed to cleanup old metrics: %v", err)
					} else if deleted > 0 {
						log.Printf("[CACHE] cleaned up %d old cache metrics records", deleted)
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
		log.Println("Skipping startup of cache, uploader, and cleaner services as no mail storage services (IMAP, POP3, LMTP) are enabled.")
	}

	// Start health monitoring
	healthIntegration.Start(ctx)
	log.Printf("Health monitoring started - collecting metrics every 30-60 seconds")

	return deps, nil
}

// startServers starts all configured servers and returns an error channel for monitoring
func startServers(ctx context.Context, deps *serverDependencies) chan error {
	errChan := make(chan error, 1)
	allServers := deps.config.GetAllServers()

	// Start all configured servers dynamically
	for _, server := range allServers {
		// Format server type name for display
		displayType := ""
		switch server.Type {
		case "imap":
			displayType = "IMAP"
		case "lmtp":
			displayType = "LMTP"
		case "pop3":
			displayType = "POP3"
		case "managesieve":
			displayType = "ManageSieve"
		case "metrics":
			displayType = "Metrics"
		case "imap_proxy":
			displayType = "IMAP proxy"
		case "pop3_proxy":
			displayType = "POP3 proxy"
		case "managesieve_proxy":
			displayType = "ManageSieve proxy"
		case "lmtp_proxy":
			displayType = "LMTP proxy"
		case "http_api":
			displayType = "HTTP API"
		default:
			displayType = strings.ToUpper(server.Type)
		}

		log.Printf(" * %s [%s] listening on %s", displayType, server.Name, server.Addr)
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
			go startDynamicMetricsServer(ctx, server, errChan)
		case "imap_proxy":
			go startDynamicIMAPProxyServer(ctx, deps, server, errChan)
		case "pop3_proxy":
			go startDynamicPOP3ProxyServer(ctx, deps, server, errChan)
		case "managesieve_proxy":
			go startDynamicManageSieveProxyServer(ctx, deps, server, errChan)
		case "lmtp_proxy":
			go startDynamicLMTPProxyServer(ctx, deps, server, errChan)
		case "http_api":
			go startDynamicHTTPAPIServer(ctx, deps, server, errChan)
		default:
			log.Printf("WARNING: Unknown server type '%s' for server '%s', skipping", server.Type, server.Name)
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
		log.Printf("WARNING: invalid connection_tracking update_interval '%s' for %s proxy [%s]: %v. Using default.", trackingConfig.UpdateInterval, protocol, serverName, err)
		updateInterval = 10 * time.Second
	}

	terminationPollInterval, err := trackingConfig.GetTerminationPollInterval()
	if err != nil {
		log.Printf("WARNING: invalid connection_tracking termination_poll_interval '%s' for %s proxy [%s]: %v. Using default.", trackingConfig.TerminationPollInterval, protocol, serverName, err)
		terminationPollInterval = 30 * time.Second
	}

	log.Printf("[%s Proxy %s] Starting connection tracker.", protocol, serverName)
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

// Helper function to check if a flag was explicitly set on the command line
func isFlagSet(name string) bool {
	isSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			isSet = true
		}
	})
	return isSet
}

// Dynamic server functions
func startDynamicIMAPServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	appendLimit := serverConfig.GetAppendLimitWithDefault()
	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	s, err := imap.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, deps.cacheInstance,
		imap.IMAPServerOptions{
			Debug:                serverConfig.Debug,
			TLS:                  serverConfig.TLS,
			TLSCertFile:          serverConfig.TLSCertFile,
			TLSKeyFile:           serverConfig.TLSKeyFile,
			TLSVerify:            serverConfig.TLSVerify,
			MasterUsername:       []byte(serverConfig.MasterUsername),
			MasterPassword:       []byte(serverConfig.MasterPassword),
			MasterSASLUsername:   []byte(serverConfig.MasterSASLUsername),
			MasterSASLPassword:   []byte(serverConfig.MasterSASLPassword),
			AppendLimit:          appendLimit,
			MaxConnections:       serverConfig.MaxConnections,
			MaxConnectionsPerIP:  serverConfig.MaxConnectionsPerIP,
			ProxyProtocol:        serverConfig.ProxyProtocol,
			ProxyProtocolTimeout: proxyProtocolTimeout,
			TrustedNetworks:      deps.config.Servers.TrustedNetworks,
			AuthRateLimit:        authRateLimit,
			EnableWarmup:         deps.config.LocalCache.EnableWarmup,
			WarmupMessageCount:   deps.config.LocalCache.WarmupMessageCount,
			WarmupMailboxes:      deps.config.LocalCache.WarmupMailboxes,
			WarmupAsync:          deps.config.LocalCache.WarmupAsync,
			WarmupTimeout:        deps.config.LocalCache.WarmupTimeout,
			FTSRetention:         ftsRetention,
			CapabilityFilters:    serverConfig.ClientFilters,
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
	ftsRetention := deps.config.Cleanup.GetFTSRetentionWithDefault()
	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

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
	})

	if err != nil {
		errChan <- fmt.Errorf("failed to create LMTP server: %w", err)
		return
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down LMTP server...")
		if err := lmtpServer.Close(); err != nil {
			log.Printf("Error closing LMTP server: %v", err)
		}
	}()

	lmtpServer.Start(errChan)
}

func startDynamicPOP3Server(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	s, err := pop3.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.storage, deps.resilientDB, deps.uploadWorker, deps.cacheInstance, pop3.POP3ServerOptions{
		Debug:                serverConfig.Debug,
		TLS:                  serverConfig.TLS,
		TLSCertFile:          serverConfig.TLSCertFile,
		TLSKeyFile:           serverConfig.TLSKeyFile,
		TLSVerify:            serverConfig.TLSVerify,
		MasterSASLUsername:   serverConfig.MasterSASLUsername,
		MasterSASLPassword:   serverConfig.MasterSASLPassword,
		MaxConnections:       serverConfig.MaxConnections,
		MaxConnectionsPerIP:  serverConfig.MaxConnectionsPerIP,
		ProxyProtocol:        serverConfig.ProxyProtocol,
		ProxyProtocolTimeout: proxyProtocolTimeout,
		TrustedNetworks:      deps.config.Servers.TrustedNetworks,
		AuthRateLimit:        authRateLimit,
	})

	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down POP3 server...")
		s.Close()
	}()

	s.Start(errChan)
}

func startDynamicManageSieveServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	maxSize := serverConfig.GetMaxScriptSizeWithDefault()

	authRateLimit := serverPkg.DefaultAuthRateLimiterConfig()
	if serverConfig.AuthRateLimit != nil {
		authRateLimit = *serverConfig.AuthRateLimit
	}

	proxyProtocolTimeout := serverConfig.GetProxyProtocolTimeoutWithDefault()

	s, err := managesieve.New(ctx, serverConfig.Name, deps.hostname, serverConfig.Addr, deps.resilientDB, managesieve.ManageSieveServerOptions{
		InsecureAuth:         serverConfig.InsecureAuth,
		TLSVerify:            serverConfig.TLSVerify,
		TLS:                  serverConfig.TLS,
		TLSCertFile:          serverConfig.TLSCertFile,
		TLSKeyFile:           serverConfig.TLSKeyFile,
		TLSUseStartTLS:       serverConfig.TLSUseStartTLS,
		Debug:                serverConfig.Debug,
		MaxScriptSize:        maxSize,
		SupportedExtensions:  serverConfig.SupportedExtensions,
		MasterSASLUsername:   serverConfig.MasterSASLUsername,
		MasterSASLPassword:   serverConfig.MasterSASLPassword,
		MaxConnections:       serverConfig.MaxConnections,
		MaxConnectionsPerIP:  serverConfig.MaxConnectionsPerIP,
		ProxyProtocol:        serverConfig.ProxyProtocol,
		ProxyProtocolTimeout: proxyProtocolTimeout,
		TrustedNetworks:      deps.config.Servers.TrustedNetworks,
		AuthRateLimit:        authRateLimit,
	})

	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down ManageSieve server...")
		s.Close()
	}()

	s.Start(errChan)
}

func startDynamicMetricsServer(ctx context.Context, serverConfig config.ServerConfig, errChan chan error) {

	mux := http.NewServeMux()
	mux.Handle(serverConfig.Path, promhttp.Handler())

	server := &http.Server{
		Addr:    serverConfig.Addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down metrics server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down metrics server: %v", err)
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		errChan <- fmt.Errorf("metrics server failed: %w", err)
	}
}

func startDynamicIMAPProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	affinityValidity := serverConfig.GetAffinityValidityWithDefault()
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
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseIDCommand:     serverConfig.RemoteUseIDCommand,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		EnableAffinity:         serverConfig.EnableAffinity,
		AffinityStickiness:     serverConfig.AffinityStickiness,
		AffinityValidity:       affinityValidity,
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create IMAP proxy server: %w", err)
		return
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("IMAP", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down IMAP proxy server...")
		server.Stop()
	}()

	if err := server.Start(); err != nil && ctx.Err() == nil {
		errChan <- fmt.Errorf("IMAP proxy server error: %w", err)
	}
}

func startDynamicPOP3ProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	affinityValidity := serverConfig.GetAffinityValidityWithDefault()
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
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseXCLIENT:       serverConfig.RemoteUseXCLIENT,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		Debug:                  serverConfig.Debug,
		EnableAffinity:         serverConfig.EnableAffinity,
		AffinityStickiness:     serverConfig.AffinityStickiness,
		AffinityValidity:       affinityValidity,
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create POP3 proxy server: %w", err)
		return
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("POP3", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down POP3 proxy server...")
		server.Stop()
	}()

	server.Start()
}

func startDynamicManageSieveProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	affinityValidity := serverConfig.GetAffinityValidityWithDefault()
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

	server, err := managesieveproxy.New(ctx, deps.resilientDB, deps.hostname, managesieveproxy.ServerOptions{
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
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		AuthRateLimit:          authRateLimit,
		PreLookup:              serverConfig.PreLookup,
		EnableAffinity:         serverConfig.EnableAffinity,
		AffinityStickiness:     serverConfig.AffinityStickiness,
		AffinityValidity:       affinityValidity,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create ManageSieve proxy server: %w", err)
		return
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("ManageSieve", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down ManageSieve proxy server...")
		server.Stop()
	}()

	server.Start()
}

func startDynamicLMTPProxyServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	connectTimeout := serverConfig.GetConnectTimeoutWithDefault()
	affinityValidity := serverConfig.GetAffinityValidityWithDefault()
	sessionTimeout := serverConfig.GetSessionTimeoutWithDefault()
	maxMessageSize := serverConfig.GetMaxMessageSizeWithDefault()

	remotePort, err := serverConfig.GetRemotePort()
	if err != nil {
		errChan <- fmt.Errorf("invalid remote_port for LMTP proxy %s: %w", serverConfig.Name, err)
		return
	}

	server, err := lmtpproxy.New(ctx, deps.resilientDB, deps.hostname, lmtpproxy.ServerOptions{
		Name:                   serverConfig.Name,
		Addr:                   serverConfig.Addr,
		RemoteAddrs:            serverConfig.RemoteAddrs,
		RemotePort:             remotePort,
		TLS:                    serverConfig.TLS,
		TLSCertFile:            serverConfig.TLSCertFile,
		TLSKeyFile:             serverConfig.TLSKeyFile,
		TLSVerify:              serverConfig.TLSVerify,
		RemoteTLS:              serverConfig.RemoteTLS,
		RemoteTLSVerify:        serverConfig.RemoteTLSVerify,
		RemoteUseProxyProtocol: serverConfig.RemoteUseProxyProtocol,
		RemoteUseXCLIENT:       serverConfig.RemoteUseXCLIENT,
		ConnectTimeout:         connectTimeout,
		SessionTimeout:         sessionTimeout,
		EnableAffinity:         serverConfig.EnableAffinity,
		AffinityStickiness:     serverConfig.AffinityStickiness,
		AffinityValidity:       affinityValidity,
		PreLookup:              serverConfig.PreLookup,
		TrustedProxies:         deps.config.Servers.TrustedNetworks,
		MaxMessageSize:         maxMessageSize,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create LMTP proxy server: %w", err)
		return
	}

	// Start connection tracker if enabled.
	if tracker := startConnectionTrackerForProxy("LMTP", serverConfig.Name, deps.resilientDB, deps.hostname, &deps.config.Servers.ConnectionTracking, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down LMTP proxy server...")
		server.Stop()
	}()

	server.Start()
}

func startDynamicHTTPAPIServer(ctx context.Context, deps *serverDependencies, serverConfig config.ServerConfig, errChan chan error) {
	if serverConfig.APIKey == "" {
		log.Printf("WARNING: HTTP API server '%s' enabled but no API key configured, skipping", serverConfig.Name)
		return
	}

	options := httpapi.ServerOptions{
		Addr:         serverConfig.Addr,
		APIKey:       serverConfig.APIKey,
		AllowedHosts: serverConfig.AllowedHosts,
		Cache:        deps.cacheInstance,
		TLS:          serverConfig.TLS,
		TLSCertFile:  serverConfig.TLSCertFile,
		TLSKeyFile:   serverConfig.TLSKeyFile,
		TLSVerify:    serverConfig.TLSVerify,
	}

	httpapi.Start(ctx, deps.resilientDB, options, errChan)
}
