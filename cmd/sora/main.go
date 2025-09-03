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
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/errors"
	"github.com/migadu/sora/pkg/health"
	"github.com/migadu/sora/pkg/metrics"
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
	"github.com/migadu/sora/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	errorHandler := errors.NewErrorHandler()
	cfg := newDefaultConfig()

	// --- Define Command-Line Flags ---
	// These flags will override values from the config file if set.
	// Their default values are set from the initial `cfg` for consistent -help messages.

	// Logging flag - its default comes from cfg.LogOutput
	fLogOutput := flag.String("logoutput", cfg.LogOutput, "Log output destination: 'syslog' or 'stderr' (overrides config)")

	configPath := flag.String("config", "config.toml", "Path to TOML configuration file")

	// Database flags - using new read/write split configuration
	fDbLogQueries := flag.Bool("dblogqueries", cfg.Database.LogQueries, "Log all database queries (overrides config)")

	// S3 flags
	fS3Endpoint := flag.String("s3endpoint", cfg.S3.Endpoint, "S3 endpoint (overrides config)")
	fS3AccessKey := flag.String("s3accesskey", cfg.S3.AccessKey, "S3 access key (overrides config)")
	fS3SecretKey := flag.String("s3secretkey", cfg.S3.SecretKey, "S3 secret key (overrides config)")
	fS3Bucket := flag.String("s3bucket", cfg.S3.Bucket, "S3 bucket name (overrides config)")
	fS3Trace := flag.Bool("s3trace", cfg.S3.Trace, "Trace S3 operations (overrides config)")

	// Server enable/address flags
	fDebug := flag.Bool("debug", cfg.Servers.Debug, "Print all commands and responses (overrides config)")
	fStartImap := flag.Bool("imap", cfg.Servers.IMAP.Start, "Start the IMAP server (overrides config)")
	fImapAddr := flag.String("imapaddr", cfg.Servers.IMAP.Addr, "IMAP server address (overrides config)")
	fStartLmtp := flag.Bool("lmtp", cfg.Servers.LMTP.Start, "Start the LMTP server (overrides config)")
	fLmtpAddr := flag.String("lmtpaddr", cfg.Servers.LMTP.Addr, "LMTP server address (overrides config)")
	fStartPop3 := flag.Bool("pop3", cfg.Servers.POP3.Start, "Start the POP3 server (overrides config)")
	fPop3Addr := flag.String("pop3addr", cfg.Servers.POP3.Addr, "POP3 server address (overrides config)")
	fStartManageSieve := flag.Bool("managesieve", cfg.Servers.ManageSieve.Start, "Start the ManageSieve server (overrides config)")
	fManagesieveAddr := flag.String("managesieveaddr", cfg.Servers.ManageSieve.Addr, "ManageSieve server address (overrides config)")
	fManagesieveInsecureAuth := flag.Bool("managesieveinsecureauth", cfg.Servers.ManageSieve.InsecureAuth, "Allow authentication without TLS (overrides config)")
	fManagesieveMaxScriptSize := flag.String("managesievescriptsize", cfg.Servers.ManageSieve.MaxScriptSize, "Maximum script size (overrides config)")

	fMasterUsername := flag.String("masterusername", cfg.Servers.IMAP.MasterUsername, "Master username (overrides config)")
	fMasterPassword := flag.String("masterpassword", cfg.Servers.IMAP.MasterPassword, "Master password (overrides config)")
	fMasterSASLUsername := flag.String("mastersaslusername", cfg.Servers.IMAP.MasterSASLUsername, "Master SASL username (overrides config)")
	fMasterSASLPassword := flag.String("mastersaslpassword", cfg.Servers.IMAP.MasterSASLPassword, "Master SASL password (overrides config)")

	// Uploader flags
	fUploaderPath := flag.String("uploaderpath", cfg.Uploader.Path, "Directory for pending uploads (overrides config)")
	fUploaderBatchSize := flag.Int("uploaderbatchsize", cfg.Uploader.BatchSize, "Number of files to upload in a single batch (overrides config)")
	fUploaderConcurrency := flag.Int("uploaderconcurrency", cfg.Uploader.Concurrency, "Number of concurrent upload workers (overrides config)")
	fUploaderMaxAttempts := flag.Int("uploadermaxattempts", cfg.Uploader.MaxAttempts, "Maximum number of attempts to upload a file (overrides config)")
	fUploaderRetryInterval := flag.String("uploaderretryinterval", cfg.Uploader.RetryInterval, "Retry interval for failed uploads")

	// Cache flags
	fCachePath := flag.String("cachedir", cfg.LocalCache.Path, "Local path for storing cached files (overrides config)")
	fCacheCapacity := flag.String("cachesize", cfg.LocalCache.Capacity, "Disk cache size in Megabytes (overrides config)")
	fCacheMaxObjectSize := flag.String("cachemaxobject", cfg.LocalCache.MaxObjectSize, "Maximum object size accepted in cache (overrides config)")
	fCacheMetricsInterval := flag.String("cachemetricsinterval", cfg.LocalCache.MetricsInterval, "Interval for storing cache metrics (overrides config)")

	// LMTP specific
	fExternalRelay := flag.String("externalrelay", cfg.Servers.LMTP.ExternalRelay, "External relay for LMTP (overrides config)")

	// TLS flags for IMAP
	fImapTLS := flag.Bool("imaptls", cfg.Servers.IMAP.TLS, "Enable TLS for IMAP (overrides config)")
	fImapTLSCert := flag.String("imaptlscert", cfg.Servers.IMAP.TLSCertFile, "TLS cert for IMAP (overrides config)")
	fImapTLSKey := flag.String("imaptlskey", cfg.Servers.IMAP.TLSKeyFile, "TLS key for IMAP (overrides config)")
	fImapTLSVerify := flag.Bool("imaptlsverify", cfg.Servers.IMAP.TLSVerify, "Verify TLS certificates for IMAP (overrides config)")

	// TLS flags for POP3
	fPop3TLS := flag.Bool("pop3tls", cfg.Servers.POP3.TLS, "Enable TLS for POP3 (overrides config)")
	fPop3TLSCert := flag.String("pop3tlscert", cfg.Servers.POP3.TLSCertFile, "TLS cert for POP3 (overrides config)")
	fPop3TLSKey := flag.String("pop3tlskey", cfg.Servers.POP3.TLSKeyFile, "TLS key for POP3 (overrides config)")
	fPop3TLSVerify := flag.Bool("pop3tlsverify", cfg.Servers.POP3.TLSVerify, "Verify TLS certificates for POP3 (overrides config)")

	// TLS flags for LMTP
	fLmtpTLS := flag.Bool("lmtptls", cfg.Servers.LMTP.TLS, "Enable TLS for LMTP (overrides config)")
	fLmtpTLSUseStartTLS := flag.Bool("lmtpstarttls", cfg.Servers.LMTP.TLSUseStartTLS, "Enable StartTLS for LMTP (overrides config)")
	fLmtpTLSCert := flag.String("lmtptlscert", cfg.Servers.LMTP.TLSCertFile, "TLS cert for LMTP (overrides config)")
	fLmtpTLSKey := flag.String("lmtptlskey", cfg.Servers.LMTP.TLSKeyFile, "TLS key for LMTP (overrides config)")
	fLmtpTLSVerify := flag.Bool("lmtptlsverify", cfg.Servers.LMTP.TLSVerify, "Verify TLS certificates for LMTP (overrides config)")

	// TLS flags for ManageSieve
	fManageSieveTLS := flag.Bool("managesievetls", cfg.Servers.ManageSieve.TLS, "Enable TLS for ManageSieve (overrides config)")
	fManageSieveTLSUseStartTLS := flag.Bool("managesievestarttls", cfg.Servers.ManageSieve.TLSUseStartTLS, "Enable StartTLS for ManageSieve (overrides config)")
	fManageSieveTLSCert := flag.String("managesievetlscert", cfg.Servers.ManageSieve.TLSCertFile, "TLS cert for ManageSieve (overrides config)")
	fManageSieveTLSKey := flag.String("managesievetlskey", cfg.Servers.ManageSieve.TLSKeyFile, "TLS key for ManageSieve (overrides config)")
	fManageSieveTLSVerify := flag.Bool("managesievetlsverify", cfg.Servers.ManageSieve.TLSVerify, "Verify TLS certificates for ManageSieve (overrides config)")

	// Proxy server flags
	fStartImapProxy := flag.Bool("imapproxy", cfg.Servers.IMAPProxy.Start, "Start the IMAP proxy server (overrides config)")
	fImapProxyAddr := flag.String("imapproxyaddr", cfg.Servers.IMAPProxy.Addr, "IMAP proxy server address (overrides config)")
	fStartPop3Proxy := flag.Bool("pop3proxy", cfg.Servers.POP3Proxy.Start, "Start the POP3 proxy server (overrides config)")
	fPop3ProxyAddr := flag.String("pop3proxyaddr", cfg.Servers.POP3Proxy.Addr, "POP3 proxy server address (overrides config)")
	fStartManageSieveProxy := flag.Bool("managesieveproxy", cfg.Servers.ManageSieveProxy.Start, "Start the ManageSieve proxy server (overrides config)")
	fManageSieveProxyAddr := flag.String("managesieveproxyaddr", cfg.Servers.ManageSieveProxy.Addr, "ManageSieve proxy server address (overrides config)")
	fStartLmtpProxy := flag.Bool("lmtpproxy", cfg.Servers.LMTPProxy.Start, "Start the LMTP proxy server (overrides config)")
	fLmtpProxyAddr := flag.String("lmtpproxyaddr", cfg.Servers.LMTPProxy.Addr, "LMTP proxy server address (overrides config)")

	// Metrics flags
	fMetricsEnabled := flag.Bool("metrics", cfg.Servers.Metrics.Enabled, "Enable metrics server (overrides config)")
	fMetricsAddr := flag.String("metricsaddr", cfg.Servers.Metrics.Addr, "Metrics server address (overrides config)")
	fMetricsPath := flag.String("metricspath", cfg.Servers.Metrics.Path, "Metrics endpoint path (overrides config)")

	flag.Parse()

	// --- Load Configuration from TOML File ---
	// Values from the TOML file will override the application defaults.
	// This is done *before* applying command-line flag overrides for logging,
	// so the TOML value for LogOutput can be used if the flag isn't set.
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet("config") { // User explicitly set -config
				errorHandler.ConfigError(*configPath, err)
				os.Exit(errorHandler.WaitForExit())
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using application defaults and command-line flags.", *configPath)
			}
		} else {
			errorHandler.ConfigError(*configPath, err)
			os.Exit(errorHandler.WaitForExit())
		}
	} else {
		log.Printf("loaded configuration from %s", *configPath)
	}

	// --- Determine Final Log Output ---
	// Precedence: 1. Command-line flag, 2. TOML config, 3. Default
	finalLogOutput := cfg.LogOutput // Start with config file value (or default if no config file)
	if isFlagSet("logoutput") {
		finalLogOutput = *fLogOutput // Command-line flag overrides
	}

	// --- Initialize Logging ---
	// This must be done *after* flags are parsed and config is loaded.
	var logFile *os.File // Declare here to manage its scope for deferred closing
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
			// At this point, log output might still be stderr or the default.
			log.Printf("WARNING: failed to open log file '%s' (specified by '%s'): %v. Logging will fall back to standard error.", finalLogOutput, finalLogOutput, openErr)
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (failed to open log file '%s', selected by '%s').", finalLogOutput, finalLogOutput)
			logFile = nil // Ensure logFile is nil if open failed
		} else {
			log.SetOutput(logFile)
			// Keep standard log flags (date, time) for file logging
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to file '%s' (selected by '%s').", finalLogOutput, finalLogOutput)
		}
	}
	log.Println(initialLogMessage)

	// If logFile was successfully opened, defer its closure.
	if logFile != nil {
		defer func(f *os.File) {
			fmt.Fprintf(os.Stderr, "SORA: Closing log file %s\n", f.Name())
			if err := f.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "SORA: Error closing log file %s: %v\n", f.Name(), err)
			}
		}(logFile)
	}

	log.Println("")
	log.Println(" ▗▄▄▖ ▗▄▖ ▗▄▄▖  ▗▄▖  ")
	log.Println("▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ")
	log.Println(" ▝▀▚▖▐▌ ▐▌▐▛▀▚▖▐▛▀▜▌ ")
	log.Println("▗▄▄▞▘▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌ ")
	log.Println("")

	// --- Apply Command-Line Flag Overrides (for flags other than logoutput) ---
	// If a flag was explicitly set on the command line, its value overrides both
	// application defaults and values from the TOML file.

	// --- Apply Command-Line Flag Overrides ---
	// If a flag was explicitly set on the command line, its value overrides both
	// application defaults and values from the TOML file.

	if isFlagSet("dblogqueries") {
		cfg.Database.LogQueries = *fDbLogQueries
	}

	// Cache
	if isFlagSet("cachesize") {
		cfg.LocalCache.Capacity = *fCacheCapacity
	}
	if isFlagSet("cachedir") {
		cfg.LocalCache.Path = *fCachePath
	}
	if isFlagSet("cachemaxobject") {
		cfg.LocalCache.MaxObjectSize = *fCacheMaxObjectSize
	}
	if isFlagSet("cachemetricsinterval") {
		cfg.LocalCache.MetricsInterval = *fCacheMetricsInterval
	}

	// S3 Config
	if isFlagSet("s3endpoint") {
		cfg.S3.Endpoint = *fS3Endpoint
	}
	if isFlagSet("s3accesskey") {
		cfg.S3.AccessKey = *fS3AccessKey
	}
	if isFlagSet("s3secretkey") {
		cfg.S3.SecretKey = *fS3SecretKey
	}
	if isFlagSet("s3bucket") {
		cfg.S3.Bucket = *fS3Bucket
	}
	if isFlagSet("s3trace") {
		cfg.S3.Trace = *fS3Trace
	}

	// Metrics
	if isFlagSet("metrics") {
		cfg.Servers.Metrics.Enabled = *fMetricsEnabled
	}
	if isFlagSet("metricsaddr") {
		cfg.Servers.Metrics.Addr = *fMetricsAddr
	}
	if isFlagSet("metricspath") {
		cfg.Servers.Metrics.Path = *fMetricsPath
	}

	// Servers
	if isFlagSet("debug") {
		cfg.Servers.Debug = *fDebug
	}

	if isFlagSet("imap") {
		cfg.Servers.IMAP.Start = *fStartImap
	}
	if isFlagSet("imapaddr") {
		cfg.Servers.IMAP.Addr = *fImapAddr
	}
	if isFlagSet("lmtp") {
		cfg.Servers.LMTP.Start = *fStartLmtp
	}
	if isFlagSet("lmtpaddr") {
		cfg.Servers.LMTP.Addr = *fLmtpAddr
	}
	if isFlagSet("pop3") {
		cfg.Servers.POP3.Start = *fStartPop3
	}
	if isFlagSet("pop3addr") {
		cfg.Servers.POP3.Addr = *fPop3Addr
	}
	if isFlagSet("managesieve") {
		cfg.Servers.ManageSieve.Start = *fStartManageSieve
	}
	if isFlagSet("managesievescriptsize") {
		cfg.Servers.ManageSieve.MaxScriptSize = *fManagesieveMaxScriptSize
	}
	if isFlagSet("managesieveaddr") {
		cfg.Servers.ManageSieve.Addr = *fManagesieveAddr
	}
	if isFlagSet("managesieveinnsecureauth") {
		cfg.Servers.ManageSieve.InsecureAuth = *fManagesieveInsecureAuth
	}

	if isFlagSet("masterusername") {
		cfg.Servers.IMAP.MasterUsername = *fMasterUsername
	}
	if isFlagSet("masterpassword") {
		cfg.Servers.IMAP.MasterPassword = *fMasterPassword
	}
	if isFlagSet("mastersaslusername") {
		cfg.Servers.IMAP.MasterSASLUsername = *fMasterSASLUsername
	}
	if isFlagSet("mastersaslpassword") {
		cfg.Servers.IMAP.MasterSASLPassword = *fMasterSASLPassword
	}

	// Upload worker
	if isFlagSet("uploaderpath") {
		cfg.Uploader.Path = *fUploaderPath
	}
	if isFlagSet("uploaderbatchsize") {
		cfg.Uploader.BatchSize = *fUploaderBatchSize
	}
	if isFlagSet("uploaderconcurrency") {
		cfg.Uploader.Concurrency = *fUploaderConcurrency
	}
	if isFlagSet("uploadermaxattempts") {
		cfg.Uploader.MaxAttempts = *fUploaderMaxAttempts
	}
	if isFlagSet("uploaderretryinterval") {
		cfg.Uploader.RetryInterval = *fUploaderRetryInterval
	}

	// LMTP
	if isFlagSet("externalrelay") {
		cfg.Servers.LMTP.ExternalRelay = *fExternalRelay
	}

	// IMAP TLS settings
	if isFlagSet("imaptls") {
		cfg.Servers.IMAP.TLS = *fImapTLS
	}
	if isFlagSet("imaptlscert") {
		cfg.Servers.IMAP.TLSCertFile = *fImapTLSCert
	}
	if isFlagSet("imaptlskey") {
		cfg.Servers.IMAP.TLSKeyFile = *fImapTLSKey
	}
	if isFlagSet("imaptlsverify") {
		cfg.Servers.IMAP.TLSVerify = *fImapTLSVerify
	}

	// POP3 TLS settings
	if isFlagSet("pop3tls") {
		cfg.Servers.POP3.TLS = *fPop3TLS
	}
	if isFlagSet("pop3tlscert") {
		cfg.Servers.POP3.TLSCertFile = *fPop3TLSCert
	}
	if isFlagSet("pop3tlskey") {
		cfg.Servers.POP3.TLSKeyFile = *fPop3TLSKey
	}
	if isFlagSet("pop3tlsverify") {
		cfg.Servers.POP3.TLSVerify = *fPop3TLSVerify
	}

	// LMTP TLS settings
	if isFlagSet("lmtptls") {
		cfg.Servers.LMTP.TLS = *fLmtpTLS
	}
	if isFlagSet("lmtpstarttls") {
		cfg.Servers.LMTP.TLSUseStartTLS = *fLmtpTLSUseStartTLS
	}
	if isFlagSet("lmtptlscert") {
		cfg.Servers.LMTP.TLSCertFile = *fLmtpTLSCert
	}
	if isFlagSet("lmtptlskey") {
		cfg.Servers.LMTP.TLSKeyFile = *fLmtpTLSKey
	}
	if isFlagSet("lmtptlsverify") {
		cfg.Servers.LMTP.TLSVerify = *fLmtpTLSVerify
	}

	// ManageSieve TLS settings
	if isFlagSet("managesievetls") {
		cfg.Servers.ManageSieve.TLS = *fManageSieveTLS
	}
	if isFlagSet("managesievestarttls") {
		cfg.Servers.ManageSieve.TLSUseStartTLS = *fManageSieveTLSUseStartTLS
	}
	if isFlagSet("managesievetlscert") {
		cfg.Servers.ManageSieve.TLSCertFile = *fManageSieveTLSCert
	}
	if isFlagSet("managesievetlskey") {
		cfg.Servers.ManageSieve.TLSKeyFile = *fManageSieveTLSKey
	}
	if isFlagSet("managesievetlsverify") {
		cfg.Servers.ManageSieve.TLSVerify = *fManageSieveTLSVerify
	}

	// Proxy server settings
	if isFlagSet("imapproxy") {
		cfg.Servers.IMAPProxy.Start = *fStartImapProxy
	}
	if isFlagSet("imapproxyaddr") {
		cfg.Servers.IMAPProxy.Addr = *fImapProxyAddr
	}
	if isFlagSet("pop3proxy") {
		cfg.Servers.POP3Proxy.Start = *fStartPop3Proxy
	}
	if isFlagSet("pop3proxyaddr") {
		cfg.Servers.POP3Proxy.Addr = *fPop3ProxyAddr
	}
	if isFlagSet("managesieveproxy") {
		cfg.Servers.ManageSieveProxy.Start = *fStartManageSieveProxy
	}
	if isFlagSet("managesieveproxyaddr") {
		cfg.Servers.ManageSieveProxy.Addr = *fManageSieveProxyAddr
	}
	if isFlagSet("lmtpproxy") {
		cfg.Servers.LMTPProxy.Start = *fStartLmtpProxy
	}
	if isFlagSet("lmtpproxyaddr") {
		cfg.Servers.LMTPProxy.Addr = *fLmtpProxyAddr
	}

	// --- Application Logic using cfg ---

	// Determine if any mail storage services are enabled, which require S3, cache, uploader, and cleaner.
	storageServicesNeeded := cfg.Servers.IMAP.Start || cfg.Servers.LMTP.Start || cfg.Servers.POP3.Start

	// Check if any server at all is configured to start.
	anyServerStarted := storageServicesNeeded || cfg.Servers.ManageSieve.Start ||
		cfg.Servers.IMAPProxy.Start || cfg.Servers.POP3Proxy.Start ||
		cfg.Servers.ManageSieveProxy.Start || cfg.Servers.LMTPProxy.Start

	if !anyServerStarted {
		errorHandler.ValidationError("servers", fmt.Errorf("no servers enabled. Please enable at least one server in your configuration"))
		os.Exit(errorHandler.WaitForExit())
	}

	var s3storage *storage.S3Storage
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
		s3storage, err = storage.New(s3EndpointToUse, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.Trace)
		if err != nil {
			errorHandler.FatalError(fmt.Sprintf("initialize S3 storage at endpoint '%s'", s3EndpointToUse), err)
			os.Exit(errorHandler.WaitForExit())
		}

		// Enable encryption if configured
		if cfg.S3.Encrypt {
			if err := s3storage.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
				errorHandler.FatalError("enable S3 encryption", err)
				os.Exit(errorHandler.WaitForExit())
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle SIGINT and SIGTERM for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChan
		log.Printf("Received signal: %s, shutting down...", sig)
		cancel()
	}()

	// Initialize the database connection with read/write split configuration
	log.Printf("Connecting to database with read/write split configuration")

	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		errorHandler.FatalError("connect to database", err)
		os.Exit(errorHandler.WaitForExit())
	}
	defer database.Close()

	// Start database pool monitoring
	database.StartPoolMetrics(ctx)

	hostname, _ := os.Hostname()

	errChan := make(chan error, 1)

	// Declare workers and cache, they will be initialized only if needed.
	var cacheInstance *cache.Cache
	var cleanupWorker *cleaner.CleanupWorker
	var uploadWorker *uploader.UploadWorker

	// Initialize health monitoring
	log.Printf("Initializing health monitoring...")
	healthIntegration := health.NewHealthIntegration(database)

	if storageServicesNeeded {
		log.Println("Mail storage services are enabled. Starting cache, uploader, and cleaner.")

		// Register S3 health check
		healthIntegration.RegisterS3Check(s3storage)

		// Initialize the local cache
		cacheSizeBytes, err := cfg.LocalCache.GetCapacity()
		if err != nil {
			errorHandler.ValidationError("cache size", err)
			os.Exit(errorHandler.WaitForExit())
		}
		maxObjectSizeBytes, err := cfg.LocalCache.GetMaxObjectSize()
		if err != nil {
			errorHandler.ValidationError("cache max object size", err)
			os.Exit(errorHandler.WaitForExit())
		}
		purgeInterval, err := cfg.LocalCache.GetPurgeInterval()
		if err != nil {
			errorHandler.ValidationError("cache purge interval", err)
			os.Exit(errorHandler.WaitForExit())
		}
		orphanCleanupAge, err := cfg.LocalCache.GetOrphanCleanupAge()
		if err != nil {
			errorHandler.ValidationError("cache orphan cleanup age", err)
			os.Exit(errorHandler.WaitForExit())
		}
		cacheInstance, err = cache.New(cfg.LocalCache.Path, cacheSizeBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, database)
		if err != nil {
			errorHandler.FatalError("initialize cache", err)
			os.Exit(errorHandler.WaitForExit())
		}
		defer cacheInstance.Close()
		if err := cacheInstance.SyncFromDisk(); err != nil {
			errorHandler.FatalError("sync cache from disk", err)
			os.Exit(errorHandler.WaitForExit())
		}
		cacheInstance.StartPurgeLoop(ctx)

		// Register cache health check
		healthIntegration.RegisterCustomCheck(&health.HealthCheck{
			Name:     "cache",
			Interval: 30 * time.Second,
			Timeout:  5 * time.Second,
			Critical: false,
			Check: func(ctx context.Context) error {
				// Check if cache directory is accessible
				stats, err := cacheInstance.GetStats()
				if err != nil {
					return fmt.Errorf("cache error: %w", err)
				}
				if stats.TotalSize < 0 {
					return fmt.Errorf("cache stats unavailable")
				}
				return nil
			},
		})

		// Start cache metrics collection
		metricsInterval, err := cfg.LocalCache.GetMetricsInterval()
		if err != nil {
			errorHandler.ValidationError("cache metrics_interval", err)
			os.Exit(errorHandler.WaitForExit())
		}
		metricsRetention, err := cfg.LocalCache.GetMetricsRetention()
		if err != nil {
			errorHandler.ValidationError("cache metrics_retention", err)
			os.Exit(errorHandler.WaitForExit())
		}

		log.Printf("[CACHE] starting metrics collection with interval: %v", metricsInterval)
		go func() {
			metricsTicker := time.NewTicker(metricsInterval) // Store metrics at configured interval
			cleanupTicker := time.NewTicker(24 * time.Hour)  // Cleanup old metrics daily
			defer metricsTicker.Stop()
			defer cleanupTicker.Stop()

			for {
				select {
				case <-ctx.Done():
					return
				case <-metricsTicker.C:
					metrics := cacheInstance.GetMetrics(hostname)
					uptimeSeconds := int64(time.Since(metrics.StartTime).Seconds())

					if err := database.StoreCacheMetrics(ctx, hostname, hostname, metrics.Hits, metrics.Misses, uptimeSeconds); err != nil {
						log.Printf("[CACHE] WARNING: failed to store metrics: %v", err)
					}
				case <-cleanupTicker.C:
					// Cleanup old cache metrics
					if deleted, err := database.CleanupOldCacheMetrics(ctx, metricsRetention); err != nil {
						log.Printf("[CACHE] WARNING: failed to cleanup old metrics: %v", err)
					} else if deleted > 0 {
						log.Printf("[CACHE] cleaned up %d old cache metrics records", deleted)
					}
				}
			}
		}()

		// Initialize and start the cleanup worker
		gracePeriod, err := cfg.Cleanup.GetGracePeriod()
		if err != nil {
			errorHandler.ValidationError("cleanup grace_period duration", err)
			os.Exit(errorHandler.WaitForExit())
		}
		wakeInterval, err := cfg.Cleanup.GetWakeInterval()
		if err != nil {
			errorHandler.ValidationError("cleanup wake_interval duration", err)
			os.Exit(errorHandler.WaitForExit())
		}
		maxAgeRestriction, err := cfg.Cleanup.GetMaxAgeRestriction()
		if err != nil {
			errorHandler.ValidationError("cleanup max_age_restriction duration", err)
			os.Exit(errorHandler.WaitForExit())
		}
		cleanupWorker = cleaner.New(database, s3storage, cacheInstance, wakeInterval, gracePeriod, maxAgeRestriction)
		cleanupWorker.Start(ctx)

		// Initialize and start the upload worker
		retryInterval, err := cfg.Uploader.GetRetryInterval()
		if err != nil {
			errorHandler.ValidationError("uploader retry_interval duration", err)
			os.Exit(errorHandler.WaitForExit())
		}
		uploadWorker, err = uploader.New(ctx, cfg.Uploader.Path, cfg.Uploader.BatchSize, cfg.Uploader.Concurrency, cfg.Uploader.MaxAttempts, retryInterval, hostname, database, s3storage, cacheInstance, errChan)
		if err != nil {
			errorHandler.FatalError("create upload worker", err)
			os.Exit(errorHandler.WaitForExit())
		}
		uploadWorker.Start(ctx)
	} else {
		log.Println("Skipping startup of cache, uploader, and cleaner services as no mail storage services (IMAP, POP3, LMTP) are enabled.")
	}

	// Start health monitoring (this begins writing to the database)
	healthIntegration.Start(ctx)
	defer healthIntegration.Stop()
	log.Printf("Health monitoring started - collecting metrics every 30-60 seconds")

	if cfg.Servers.LMTP.Start {
		go startLMTPServer(ctx, hostname, cfg.Servers.LMTP.Addr, s3storage, database, uploadWorker, errChan, cfg)
	}
	if cfg.Servers.IMAP.Start {
		go startIMAPServer(ctx, hostname, cfg.Servers.IMAP.Addr, s3storage, database, uploadWorker, cacheInstance, errChan, cfg)
	}
	if cfg.Servers.POP3.Start {
		go startPOP3Server(ctx, hostname, cfg.Servers.POP3.Addr, s3storage, database, uploadWorker, cacheInstance, errChan, cfg)
	}
	if cfg.Servers.ManageSieve.Start {
		go startManageSieveServer(ctx, hostname, cfg.Servers.ManageSieve.Addr, database, errChan, cfg)
	}

	// Start metrics server
	if cfg.Servers.Metrics.Enabled {
		// Configure metrics collection settings
		metrics.Configure(
			cfg.Servers.Metrics.EnableUserMetrics,
			cfg.Servers.Metrics.EnableDomainMetrics,
			cfg.Servers.Metrics.UserMetricsThreshold,
			cfg.Servers.Metrics.MaxTrackedUsers,
			cfg.Servers.Metrics.HashUsernames,
		)
		go startMetricsServer(ctx, cfg.Servers.Metrics, errChan)
	}

	// Start proxy servers
	if cfg.Servers.IMAPProxy.Start {
		go startIMAPProxyServer(ctx, hostname, database, errChan, cfg)
	}
	if cfg.Servers.POP3Proxy.Start {
		go startPOP3ProxyServer(ctx, hostname, database, errChan, cfg)
	}
	if cfg.Servers.ManageSieveProxy.Start {
		go startManageSieveProxyServer(ctx, hostname, database, errChan, cfg)
	}
	if cfg.Servers.LMTPProxy.Start {
		go startLMTPProxyServer(ctx, hostname, database, errChan, cfg)
	}

	select {
	case <-ctx.Done():
		errorHandler.Shutdown(ctx)
	case err := <-errChan:
		errorHandler.FatalError("server operation", err)
		os.Exit(errorHandler.WaitForExit())
	}
}

func startIMAPServer(ctx context.Context, hostname, addr string, s3storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cacheInstance *cache.Cache, errChan chan error, config Config) {

	appendLimit, err := config.Servers.IMAP.GetAppendLimit()
	if err != nil {
		log.Printf("WARNING: invalid APPENDLIMIT value '%s': %v. Using default of %d.", config.Servers.IMAP.AppendLimit, err, imap.DefaultAppendLimit)
		appendLimit = imap.DefaultAppendLimit
	}

	s, err := imap.New(ctx, hostname, addr, s3storage, database, uploadWorker, cacheInstance,
		imap.IMAPServerOptions{
			Debug:               config.Servers.Debug,
			TLS:                 config.Servers.IMAP.TLS,
			TLSCertFile:         config.Servers.IMAP.TLSCertFile,
			TLSKeyFile:          config.Servers.IMAP.TLSKeyFile,
			TLSVerify:           config.Servers.IMAP.TLSVerify,
			MasterUsername:      []byte(config.Servers.IMAP.MasterUsername),
			MasterPassword:      []byte(config.Servers.IMAP.MasterPassword),
			MasterSASLUsername:  []byte(config.Servers.IMAP.MasterSASLUsername),
			MasterSASLPassword:  []byte(config.Servers.IMAP.MasterSASLPassword),
			AppendLimit:         appendLimit,
			MaxConnections:      config.Servers.IMAP.MaxConnections,
			MaxConnectionsPerIP: config.Servers.IMAP.MaxConnectionsPerIP,
			ProxyProtocol:       config.Servers.IMAP.ProxyProtocol,
			AuthRateLimit:       config.Servers.IMAP.AuthRateLimit,
			EnableWarmup:        config.LocalCache.EnableWarmup,
			WarmupMessageCount:  config.LocalCache.WarmupMessageCount,
			WarmupMailboxes:     config.LocalCache.WarmupMailboxes,
			WarmupAsync:         config.LocalCache.WarmupAsync,
		})
	if err != nil {
		errChan <- err
		return
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down IMAP server...")
		s.Close()
	}()

	if err := s.Serve(addr); err != nil && ctx.Err() == nil {
		errChan <- err
	}
}

func startLMTPServer(ctx context.Context, hostname, addr string, s3storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, errChan chan error, config Config) {
	lmtpServer, err := lmtp.New(ctx, hostname, addr, s3storage, database, uploadWorker, lmtp.LMTPServerOptions{
		ExternalRelay:       config.Servers.LMTP.ExternalRelay,
		TLSVerify:           config.Servers.LMTP.TLSVerify,
		TLS:                 config.Servers.LMTP.TLS,
		TLSCertFile:         config.Servers.LMTP.TLSCertFile,
		TLSKeyFile:          config.Servers.LMTP.TLSKeyFile,
		TLSUseStartTLS:      config.Servers.LMTP.TLSUseStartTLS,
		Debug:               config.Servers.Debug,
		MaxConnections:      config.Servers.LMTP.MaxConnections,
		MaxConnectionsPerIP: config.Servers.LMTP.MaxConnectionsPerIP,
		ProxyProtocol:       config.Servers.LMTP.ProxyProtocol,
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

func startPOP3Server(ctx context.Context, hostname string, addr string, s3storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cacheInstance *cache.Cache, errChan chan error, config Config) {
	s, err := pop3.New(ctx, hostname, addr, s3storage, database, uploadWorker, cacheInstance, pop3.POP3ServerOptions{
		Debug:               config.Servers.Debug,
		TLS:                 config.Servers.POP3.TLS,
		TLSCertFile:         config.Servers.POP3.TLSCertFile,
		TLSKeyFile:          config.Servers.POP3.TLSKeyFile,
		TLSVerify:           config.Servers.POP3.TLSVerify,
		MasterSASLUsername:  config.Servers.POP3.MasterSASLUsername,
		MasterSASLPassword:  config.Servers.POP3.MasterSASLPassword,
		MaxConnections:      config.Servers.POP3.MaxConnections,
		MaxConnectionsPerIP: config.Servers.POP3.MaxConnectionsPerIP,
		ProxyProtocol:       config.Servers.POP3.ProxyProtocol,
		AuthRateLimit:       config.Servers.POP3.AuthRateLimit,
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

func startManageSieveServer(ctx context.Context, hostname string, addr string, database *db.Database, errChan chan error, config Config) {
	maxSize, err := config.Servers.ManageSieve.GetMaxScriptSize()
	if err != nil {
		log.Printf("WARNING: invalid MANAGESIEVE MAX_SCRIPT_SIZE value '%s': %v. Using default of %d.", config.Servers.ManageSieve.MaxScriptSize, err, managesieve.DefaultMaxScriptSize)
		maxSize = managesieve.DefaultMaxScriptSize
	}
	s, err := managesieve.New(ctx, hostname, addr, database, managesieve.ManageSieveServerOptions{
		InsecureAuth:        config.Servers.ManageSieve.InsecureAuth,
		TLSVerify:           config.Servers.ManageSieve.TLSVerify,
		TLS:                 config.Servers.ManageSieve.TLS,
		TLSCertFile:         config.Servers.ManageSieve.TLSCertFile,
		TLSKeyFile:          config.Servers.ManageSieve.TLSKeyFile,
		TLSUseStartTLS:      config.Servers.ManageSieve.TLSUseStartTLS,
		Debug:               config.Servers.Debug,
		MaxScriptSize:       maxSize,
		MasterSASLUsername:  config.Servers.ManageSieve.MasterSASLUsername,
		MasterSASLPassword:  config.Servers.ManageSieve.MasterSASLPassword,
		MaxConnections:      config.Servers.ManageSieve.MaxConnections,
		MaxConnectionsPerIP: config.Servers.ManageSieve.MaxConnectionsPerIP,
		ProxyProtocol:       config.Servers.ManageSieve.ProxyProtocol,
		AuthRateLimit:       config.Servers.ManageSieve.AuthRateLimit,
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

// startConnectionTrackerForProxy initializes and starts a connection tracker for a given proxy protocol if affinity is enabled.
func startConnectionTrackerForProxy(protocol string, database *db.Database, hostname string, trackingConfig *ConnectionTrackingConfig, affinityEnabled bool, server interface {
	SetConnectionTracker(*proxy.ConnectionTracker)
}) *proxy.ConnectionTracker {
	if !affinityEnabled || !trackingConfig.Enabled {
		return nil
	}

	updateInterval, err := trackingConfig.GetUpdateInterval()
	if err != nil {
		log.Printf("WARNING: invalid connection_tracking update_interval '%s': %v. Using default.", trackingConfig.UpdateInterval, err)
		updateInterval = 10 * time.Second
	}

	log.Printf("[%s Proxy] Starting connection tracker for affinity.", protocol)
	tracker := proxy.NewConnectionTracker(
		protocol,
		database,
		hostname,
		updateInterval,
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

func startIMAPProxyServer(ctx context.Context, hostname string, database *db.Database, errChan chan error, config Config) {
	// Parse connection timeout
	connectTimeout, err := config.Servers.IMAPProxy.GetConnectTimeout()
	if err != nil {
		log.Printf("WARNING: invalid IMAP proxy connect_timeout '%s': %v. Using default.", config.Servers.IMAPProxy.ConnectTimeout, err)
		connectTimeout = 30 * time.Second
	}

	// Parse affinity validity
	affinityValidity, err := config.Servers.IMAPProxy.GetAffinityValidity()
	if err != nil {
		log.Printf("WARNING: invalid IMAP proxy affinity_validity '%s': %v. Using default.", config.Servers.IMAPProxy.AffinityValidity, err)
		affinityValidity = 24 * time.Hour
	}

	server, err := imapproxy.New(ctx, database, hostname, imapproxy.ServerOptions{
		Addr:               config.Servers.IMAPProxy.Addr,
		RemoteAddrs:        config.Servers.IMAPProxy.RemoteAddrs,
		MasterSASLUsername: config.Servers.IMAPProxy.MasterSASLUsername,
		MasterSASLPassword: config.Servers.IMAPProxy.MasterSASLPassword,
		TLS:                config.Servers.IMAPProxy.TLS,
		TLSCertFile:        config.Servers.IMAPProxy.TLSCertFile,
		TLSKeyFile:         config.Servers.IMAPProxy.TLSKeyFile,
		TLSVerify:          config.Servers.IMAPProxy.TLSVerify,
		RemoteTLS:          config.Servers.IMAPProxy.RemoteTLS,
		RemoteTLSVerify:    config.Servers.IMAPProxy.RemoteTLSVerify,
		ConnectTimeout:     connectTimeout,
		EnableAffinity:     config.Servers.IMAPProxy.EnableAffinity,
		AffinityStickiness: config.Servers.IMAPProxy.AffinityStickiness,
		AffinityValidity:   affinityValidity,
		AuthRateLimit:      config.Servers.IMAPProxy.AuthRateLimit,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create IMAP proxy server: %w", err)
		return
	}

	// Start connection tracker if affinity is enabled for this proxy.
	if tracker := startConnectionTrackerForProxy("IMAP", database, hostname, &config.Servers.ConnectionTracking, config.Servers.IMAPProxy.EnableAffinity, server); tracker != nil {
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

func startPOP3ProxyServer(ctx context.Context, hostname string, database *db.Database, errChan chan error, config Config) {
	// Parse connection timeout
	connectTimeout, err := config.Servers.POP3Proxy.GetConnectTimeout()
	if err != nil {
		log.Printf("WARNING: invalid POP3 proxy connect_timeout '%s': %v. Using default.", config.Servers.POP3Proxy.ConnectTimeout, err)
		connectTimeout = 30 * time.Second
	}

	// Parse affinity validity
	affinityValidity, err := config.Servers.POP3Proxy.GetAffinityValidity()
	if err != nil {
		log.Printf("WARNING: invalid POP3 proxy affinity_validity '%s': %v. Using default.", config.Servers.POP3Proxy.AffinityValidity, err)
		affinityValidity = 24 * time.Hour
	}

	server, err := pop3proxy.New(ctx, hostname, config.Servers.POP3Proxy.Addr, database, pop3proxy.POP3ProxyServerOptions{
		RemoteAddrs:        config.Servers.POP3Proxy.RemoteAddrs,
		MasterSASLUsername: config.Servers.POP3Proxy.MasterSASLUsername,
		MasterSASLPassword: config.Servers.POP3Proxy.MasterSASLPassword,
		TLS:                config.Servers.POP3Proxy.TLS,
		TLSCertFile:        config.Servers.POP3Proxy.TLSCertFile,
		TLSKeyFile:         config.Servers.POP3Proxy.TLSKeyFile,
		TLSVerify:          config.Servers.POP3Proxy.TLSVerify,
		RemoteTLS:          config.Servers.POP3Proxy.RemoteTLS,
		RemoteTLSVerify:    config.Servers.POP3Proxy.RemoteTLSVerify,
		ConnectTimeout:     connectTimeout,
		Debug:              config.Servers.Debug,
		EnableAffinity:     config.Servers.POP3Proxy.EnableAffinity,
		AffinityStickiness: config.Servers.POP3Proxy.AffinityStickiness,
		AffinityValidity:   affinityValidity,
		AuthRateLimit:      config.Servers.POP3Proxy.AuthRateLimit,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create POP3 proxy server: %w", err)
		return
	}

	// Start connection tracker if affinity is enabled for this proxy.
	if tracker := startConnectionTrackerForProxy("POP3", database, hostname, &config.Servers.ConnectionTracking, config.Servers.POP3Proxy.EnableAffinity, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down POP3 proxy server...")
		server.Stop()
	}()

	server.Start()
}

func startManageSieveProxyServer(ctx context.Context, hostname string, database *db.Database, errChan chan error, config Config) {
	// Parse connection timeout
	connectTimeout, err := config.Servers.ManageSieveProxy.GetConnectTimeout()
	if err != nil {
		log.Printf("WARNING: invalid ManageSieve proxy connect_timeout '%s': %v. Using default.", config.Servers.ManageSieveProxy.ConnectTimeout, err)
		connectTimeout = 30 * time.Second
	}

	server, err := managesieveproxy.New(ctx, database, hostname, managesieveproxy.ServerOptions{
		Addr:               config.Servers.ManageSieveProxy.Addr,
		RemoteAddrs:        config.Servers.ManageSieveProxy.RemoteAddrs,
		MasterSASLUsername: config.Servers.ManageSieveProxy.MasterSASLUsername,
		MasterSASLPassword: config.Servers.ManageSieveProxy.MasterSASLPassword,
		TLS:                config.Servers.ManageSieveProxy.TLS,
		TLSCertFile:        config.Servers.ManageSieveProxy.TLSCertFile,
		TLSKeyFile:         config.Servers.ManageSieveProxy.TLSKeyFile,
		TLSVerify:          config.Servers.ManageSieveProxy.TLSVerify,
		RemoteTLS:          config.Servers.ManageSieveProxy.RemoteTLS,
		RemoteTLSVerify:    config.Servers.ManageSieveProxy.RemoteTLSVerify,
		ConnectTimeout:     connectTimeout,
		AuthRateLimit:      config.Servers.ManageSieveProxy.AuthRateLimit,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create ManageSieve proxy server: %w", err)
		return
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down ManageSieve proxy server...")
		server.Stop()
	}()

	server.Start()
}

func startLMTPProxyServer(ctx context.Context, hostname string, database *db.Database, errChan chan error, config Config) {
	// Parse connection timeout
	connectTimeout, err := config.Servers.LMTPProxy.GetConnectTimeout()
	if err != nil {
		log.Printf("WARNING: invalid LMTP proxy connect_timeout '%s': %v. Using default.", config.Servers.LMTPProxy.ConnectTimeout, err)
		connectTimeout = 30 * time.Second
	}

	// Parse affinity validity
	affinityValidity, err := config.Servers.LMTPProxy.GetAffinityValidity()
	if err != nil {
		log.Printf("WARNING: invalid LMTP proxy affinity_validity '%s': %v. Using default.", config.Servers.LMTPProxy.AffinityValidity, err)
		affinityValidity = 24 * time.Hour
	}

	server, err := lmtpproxy.New(ctx, database, hostname, lmtpproxy.ServerOptions{
		Addr:               config.Servers.LMTPProxy.Addr,
		RemoteAddrs:        config.Servers.LMTPProxy.RemoteAddrs,
		TLS:                config.Servers.LMTPProxy.TLS,
		TLSCertFile:        config.Servers.LMTPProxy.TLSCertFile,
		TLSKeyFile:         config.Servers.LMTPProxy.TLSKeyFile,
		TLSVerify:          config.Servers.LMTPProxy.TLSVerify,
		RemoteTLS:          config.Servers.LMTPProxy.RemoteTLS,
		RemoteTLSVerify:    config.Servers.LMTPProxy.RemoteTLSVerify,
		ConnectTimeout:     connectTimeout,
		EnableAffinity:     config.Servers.LMTPProxy.EnableAffinity,
		AffinityStickiness: config.Servers.LMTPProxy.AffinityStickiness,
		AffinityValidity:   affinityValidity,
	})
	if err != nil {
		errChan <- fmt.Errorf("failed to create LMTP proxy server: %w", err)
		return
	}

	// Start connection tracker if affinity is enabled for this proxy.
	if tracker := startConnectionTrackerForProxy("LMTP", database, hostname, &config.Servers.ConnectionTracking, config.Servers.LMTPProxy.EnableAffinity, server); tracker != nil {
		defer tracker.Stop()
	}

	go func() {
		<-ctx.Done()
		log.Println("Shutting down LMTP proxy server...")
		server.Stop()
	}()

	server.Start()
}

// startMetricsServer starts the Prometheus metrics HTTP server
func startMetricsServer(ctx context.Context, config MetricsConfig, errChan chan error) {
	log.Printf("Starting metrics server on %s%s", config.Addr, config.Path)

	mux := http.NewServeMux()
	mux.Handle(config.Path, promhttp.Handler())

	server := &http.Server{
		Addr:    config.Addr,
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
