package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog" // Added for syslog logging
	"os"
	"os/signal"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/cleaner"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

func main() {
	// Initialize with application defaults
	cfg := newDefaultConfig()

	// --- Define Command-Line Flags ---
	// These flags will override values from the config file if set.
	// Their default values are set from the initial `cfg` for consistent -help messages.

	// Logging flag - its default comes from cfg.LogOutput
	fLogOutput := flag.String("logoutput", cfg.LogOutput, "Log output destination: 'syslog' or 'stderr' (overrides config)")

	configPath := flag.String("config", "config.toml", "Path to TOML configuration file")

	// Database flags
	fDbHost := flag.String("dbhost", cfg.Database.Host, "Database host (overrides config)")
	fDbPort := flag.String("dbport", cfg.Database.Port, "Database port (overrides config)")
	fDbUser := flag.String("dbuser", cfg.Database.User, "Database user (overrides config)")
	fDbPassword := flag.String("dbpassword", cfg.Database.Password, "Database password (overrides config)")
	fDbName := flag.String("dbname", cfg.Database.Name, "Database name (overrides config)")
	fDbTLS := flag.Bool("dbtls", cfg.Database.TLSMode, "Enable TLS for database connection (overrides config)")
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

	flag.Parse()

	// --- Load Configuration from TOML File ---
	// Values from the TOML file will override the application defaults.
	// This is done *before* applying command-line flag overrides for logging,
	// so the TOML value for LogOutput can be used if the flag isn't set.
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet("config") { // User explicitly set -config
				log.Fatalf("Error: Specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: Default configuration file '%s' not found. Using application defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("Error parsing configuration file '%s': %v", *configPath, err)
		}
	} else {
		log.Printf("Loaded configuration from %s", *configPath)
	}

	// --- Determine Final Log Output ---
	// Precedence: 1. Command-line flag, 2. TOML config, 3. Default
	finalLogOutput := cfg.LogOutput // Start with config file value (or default if no config file)
	if isFlagSet("logoutput") {
		finalLogOutput = *fLogOutput // Command-line flag overrides
	}

	// --- Initialize Logging ---
	// This must be done *after* flags are parsed and config is loaded.
	var initialLogMessage string

	switch finalLogOutput {
	case "syslog":
		syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "sora")
		if err != nil {
			log.Printf("WARNING: Failed to connect to syslog (specified by '%s'): %v. Logging will fall back to standard error.", finalLogOutput, err)
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (syslog connection failed, selected by '%s').", finalLogOutput)
		} else {
			log.SetOutput(syslogWriter)
			log.SetFlags(0)
			defer syslogWriter.Close()
			initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to syslog (selected by '%s').", finalLogOutput)
		}
	case "stderr":
		initialLogMessage = fmt.Sprintf("SORA application starting. Logging initialized to standard error (selected by '%s').", finalLogOutput)
	default:
		log.Printf("WARNING: Invalid logoutput value '%s' (from config or flag). Application will log to standard error.", finalLogOutput)
		initialLogMessage = fmt.Sprintf("SORA application starting. Logging to standard error (invalid logoutput '%s').", finalLogOutput)
	}
	log.Println(initialLogMessage)

	// --- Apply Command-Line Flag Overrides (for flags other than logoutput) ---
	// If a flag was explicitly set on the command line, its value overrides both
	// application defaults and values from the TOML file.

	// --- Apply Command-Line Flag Overrides ---
	// If a flag was explicitly set on the command line, its value overrides both
	// application defaults and values from the TOML file.

	if isFlagSet("dbhost") {
		cfg.Database.Host = *fDbHost
	}
	if isFlagSet("dbport") {
		cfg.Database.Port = *fDbPort
	}
	if isFlagSet("dbuser") {
		cfg.Database.User = *fDbUser
	}
	if isFlagSet("dbpassword") {
		cfg.Database.Password = *fDbPassword
	}
	if isFlagSet("dbname") {
		cfg.Database.Name = *fDbName
	}
	if isFlagSet("dbtls") {
		cfg.Database.TLSMode = *fDbTLS
	}
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

	// --- Application Logic using cfg ---

	if !cfg.Servers.IMAP.Start && !cfg.Servers.LMTP.Start && !cfg.Servers.POP3.Start && !cfg.Servers.ManageSieve.Start {
		log.Fatal("No servers enabled. Please enable at least one server (IMAP, LMTP, POP3, or ManageSieve).")
	}

	// Ensure required arguments are provided
	if cfg.S3.AccessKey == "" || cfg.S3.SecretKey == "" || cfg.S3.Bucket == "" {
		log.Fatal("Missing required credentials. Ensure S3 access key, secret key, and bucket are provided.")
	}

	// Initialize S3 storage
	s3EndpointToUse := cfg.S3.Endpoint
	if s3EndpointToUse == "" {
		log.Fatal("S3 endpoint not specified")
	}
	log.Printf("Connecting to S3 endpoint '%s', bucket '%s'", s3EndpointToUse, cfg.S3.Bucket)
	// TLS is always enabled for S3
	s3storage, err := storage.New(s3EndpointToUse, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, true, cfg.S3.Trace)
	if err != nil {
		log.Fatalf("Failed to initialize S3 storage at endpoint '%s': %v", s3EndpointToUse, err)
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

	// Initialize the database connection
	log.Printf("Connecting to database at %s:%s as user %s, using database %s", cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Name)
	database, err := db.NewDatabase(ctx, cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.TLSMode, cfg.Database.LogQueries)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer database.Close()

	hostname, _ := os.Hostname()

	errChan := make(chan error, 1)

	// Initialize the local cache
	cacheSizeBytes, err := cfg.LocalCache.GetCapacity()
	if err != nil {
		log.Fatalf("Invalid cache size: %v", err)
	}
	maxObjectSizeBytes, err := cfg.LocalCache.GetMaxObjectSize()
	if err != nil {
		log.Fatalf("Invalid cache max object size: %v", err)
	}
	cacheInstance, err := cache.New(cfg.LocalCache.Path, cacheSizeBytes, maxObjectSizeBytes, database)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}
	defer cacheInstance.Close()
	if err := cacheInstance.SyncFromDisk(); err != nil {
		log.Fatalf("Failed to sync cache from disk: %v", err)
	}
	cacheInstance.StartPurgeLoop(ctx)

	gracePeriod, err := cfg.Cleanup.GetGracePeriod()
	if err != nil {
		log.Fatalf("Invalid cleanup grace_period duration: %v", err)
	}
	wakeInterval, err := cfg.Cleanup.GetWakeInterval()
	if err != nil {
		log.Fatalf("Invalid cleanup wake_interval duration: %v", err)
	}
	cleanupWorker := cleaner.New(database, s3storage, cacheInstance, wakeInterval, gracePeriod)
	cleanupWorker.Start(ctx)

	retryInterval, err := cfg.Uploader.GetRetryInterval()
	if err != nil {
		log.Fatalf("Invalid uploader retry_interval duration: %v", err)
	}
	uploadWorker, err := uploader.New(ctx, cfg.Uploader.Path, cfg.Uploader.BatchSize, cfg.Uploader.Concurrency, cfg.Uploader.MaxAttempts, retryInterval, hostname, database, s3storage, cacheInstance, errChan)
	if err != nil {
		log.Fatalf("Failed to create upload worker: %v", err)
	}
	uploadWorker.Start(ctx)

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

	select {
	case <-ctx.Done():
		log.Println("Shutting down SORA servers...")
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	}
}

func startIMAPServer(ctx context.Context, hostname, addr string, s3storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cacheInstance *cache.Cache, errChan chan error, config Config) {

	appendLimit, err := config.Servers.IMAP.GetAppendLimit()
	if err != nil {
		log.Printf("WARNING: Invalid APPENDLIMIT value '%s': %v. Using default of %d.", config.Servers.IMAP.AppendLimit, err, imap.DefaultAppendLimit)
		appendLimit = imap.DefaultAppendLimit
	}

	s, err := imap.New(ctx, hostname, addr, s3storage, database, uploadWorker, cacheInstance,
		imap.IMAPServerOptions{
			Debug:              config.Servers.Debug,
			TLS:                config.Servers.IMAP.TLS,
			TLSCertFile:        config.Servers.IMAP.TLSCertFile,
			TLSKeyFile:         config.Servers.IMAP.TLSKeyFile,
			TLSVerify:          config.Servers.IMAP.TLSVerify,
			MasterUsername:     config.Servers.IMAP.MasterUsername,
			MasterPassword:     config.Servers.IMAP.MasterPassword,
			MasterSASLUsername: config.Servers.IMAP.MasterSASLUsername,
			MasterSASLPassword: config.Servers.IMAP.MasterSASLPassword,
			AppendLimit:        appendLimit,
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
		ExternalRelay:  config.Servers.LMTP.ExternalRelay,
		TLSVerify:      config.Servers.LMTP.TLSVerify,
		TLS:            config.Servers.LMTP.TLS,
		TLSCertFile:    config.Servers.LMTP.TLSCertFile,
		TLSKeyFile:     config.Servers.LMTP.TLSKeyFile,
		TLSUseStartTLS: config.Servers.LMTP.TLSUseStartTLS,
		Debug:          config.Servers.Debug,
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
		Debug:       config.Servers.Debug,
		TLS:         config.Servers.POP3.TLS,
		TLSCertFile: config.Servers.POP3.TLSCertFile,
		TLSKeyFile:  config.Servers.POP3.TLSKeyFile,
		TLSVerify:   config.Servers.POP3.TLSVerify,
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
		log.Printf("WARNING: Invalid MANAGESIEVE MAX_SCRIPT_SIZE value '%s': %v. Using default of %d.", config.Servers.ManageSieve.MaxScriptSize, err, managesieve.DefaultMaxScriptSize)
		maxSize = managesieve.DefaultMaxScriptSize
	}
	s, err := managesieve.New(ctx, hostname, addr, database, managesieve.ManageSieveServerOptions{
		InsecureAuth:   config.Servers.ManageSieve.InsecureAuth,
		TLSVerify:      config.Servers.ManageSieve.TLSVerify,
		TLS:            config.Servers.ManageSieve.TLS,
		TLSCertFile:    config.Servers.ManageSieve.TLSCertFile,
		TLSKeyFile:     config.Servers.ManageSieve.TLSKeyFile,
		TLSUseStartTLS: config.Servers.ManageSieve.TLSUseStartTLS,
		Debug:          config.Servers.Debug,
		MaxScriptSize:  maxSize,
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
