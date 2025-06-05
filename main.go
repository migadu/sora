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

	// General flags
	fInsecureAuth := flag.Bool("insecure-auth", cfg.InsecureAuth, "Allow authentication without TLS (overrides config)")
	fDebug := flag.Bool("debug", cfg.Debug, "Print all commands and responses (overrides config)")

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
	fStartImap := flag.Bool("imap", cfg.Servers.StartImap, "Start the IMAP server (overrides config)")
	fImapAddr := flag.String("imapaddr", cfg.Servers.ImapAddr, "IMAP server address (overrides config)")
	fStartLmtp := flag.Bool("lmtp", cfg.Servers.StartLmtp, "Start the LMTP server (overrides config)")
	fLmtpAddr := flag.String("lmtpaddr", cfg.Servers.LmtpAddr, "LMTP server address (overrides config)")
	fStartPop3 := flag.Bool("pop3", cfg.Servers.StartPop3, "Start the POP3 server (overrides config)")
	fPop3Addr := flag.String("pop3addr", cfg.Servers.Pop3Addr, "POP3 server address (overrides config)")
	fStartManageSieve := flag.Bool("managesieve", cfg.Servers.StartManageSieve, "Start the ManageSieve server (overrides config)")
	fManagesieveAddr := flag.String("managesieveaddr", cfg.Servers.ManageSieveAddr, "ManageSieve server address (overrides config)")
	fMasterUsername := flag.String("masterusername", cfg.Servers.MasterUsername, "Master username (overrides config)")
	fMasterPassword := flag.String("masterpassword", cfg.Servers.MasterPassword, "Master password (overrides config)")
	fMasterSASLUsername := flag.String("mastersaslusername", cfg.Servers.MasterSASLUsername, "Master SASL username (overrides config)")
	fMasterSASLPassword := flag.String("mastersaslpassword", cfg.Servers.MasterSASLPassword, "Master SASL password (overrides config)")

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
	fExternalRelay := flag.String("externalrelay", cfg.LMTP.ExternalRelay, "External relay for LMTP (overrides config)")

	// TLS general
	fTlsInsecureSkipVerify := flag.Bool("tlsinsecureskipverify", cfg.TLS.InsecureSkipVerify, "Skip TLS cert verification (overrides config)")

	// TLS specific flags (enable, cert, key for each service)
	fImapTLS := flag.Bool("imaptls", cfg.TLS.IMAP.Enable, "Enable TLS for IMAP (overrides config)")
	fImapTLSCert := flag.String("imaptlscert", cfg.TLS.IMAP.CertFile, "TLS cert for IMAP (overrides config)")
	fImapTLSKey := flag.String("imaptlskey", cfg.TLS.IMAP.KeyFile, "TLS key for IMAP (overrides config)")

	fPop3TLS := flag.Bool("pop3tls", cfg.TLS.POP3.Enable, "Enable TLS for POP3 (overrides config)")
	fPop3TLSCert := flag.String("pop3tlscert", cfg.TLS.POP3.CertFile, "TLS cert for POP3 (overrides config)")
	fPop3TLSKey := flag.String("pop3tlskey", cfg.TLS.POP3.KeyFile, "TLS key for POP3 (overrides config)")

	fLmtpTLS := flag.Bool("lmtptls", cfg.TLS.LMTP.Enable, "Enable TLS for LMTP (overrides config)")
	fLmtpTLSCert := flag.String("lmtptlscert", cfg.TLS.LMTP.CertFile, "TLS cert for LMTP (overrides config)")
	fLmtpTLSKey := flag.String("lmtptlskey", cfg.TLS.LMTP.KeyFile, "TLS key for LMTP (overrides config)")

	fManageSieveTLS := flag.Bool("managesievetls", cfg.TLS.ManageSieve.Enable, "Enable TLS for ManageSieve (overrides config)")
	fManageSieveTLSCert := flag.String("managesievetlscert", cfg.TLS.ManageSieve.CertFile, "TLS cert for ManageSieve (overrides config)")
	fManageSieveTLSKey := flag.String("managesievetlskey", cfg.TLS.ManageSieve.KeyFile, "TLS key for ManageSieve (overrides config)")

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
	if isFlagSet("insecure-auth") {
		cfg.InsecureAuth = *fInsecureAuth
	}
	if isFlagSet("debug") {
		cfg.Debug = *fDebug
	}

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

	if isFlagSet("imap") {
		cfg.Servers.StartImap = *fStartImap
	}
	if isFlagSet("imapaddr") {
		cfg.Servers.ImapAddr = *fImapAddr
	}
	if isFlagSet("lmtp") {
		cfg.Servers.StartLmtp = *fStartLmtp
	}
	if isFlagSet("lmtpaddr") {
		cfg.Servers.LmtpAddr = *fLmtpAddr
	}
	if isFlagSet("pop3") {
		cfg.Servers.StartPop3 = *fStartPop3
	}
	if isFlagSet("pop3addr") {
		cfg.Servers.Pop3Addr = *fPop3Addr
	}
	if isFlagSet("managesieve") {
		cfg.Servers.StartManageSieve = *fStartManageSieve
	}
	if isFlagSet("managesieveaddr") {
		cfg.Servers.ManageSieveAddr = *fManagesieveAddr
	}

	if isFlagSet("masterusername") {
		cfg.Servers.MasterUsername = *fMasterUsername
	}
	if isFlagSet("masterpassword") {
		cfg.Servers.MasterPassword = *fMasterPassword
	}
	if isFlagSet("mastersaslusername") {
		cfg.Servers.MasterSASLUsername = *fMasterSASLUsername
	}
	if isFlagSet("mastersaslpassword") {
		cfg.Servers.MasterSASLPassword = *fMasterSASLPassword
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
		cfg.LMTP.ExternalRelay = *fExternalRelay
	}

	// TLS Setup
	if isFlagSet("tlsinsecureskipverify") {
		cfg.TLS.InsecureSkipVerify = *fTlsInsecureSkipVerify
	}

	if isFlagSet("imaptls") {
		cfg.TLS.IMAP.Enable = *fImapTLS
	}
	if isFlagSet("imaptlscert") {
		cfg.TLS.IMAP.CertFile = *fImapTLSCert
	}
	if isFlagSet("imaptlskey") {
		cfg.TLS.IMAP.KeyFile = *fImapTLSKey
	}

	if isFlagSet("pop3tls") {
		cfg.TLS.POP3.Enable = *fPop3TLS
	}
	if isFlagSet("pop3tlscert") {
		cfg.TLS.POP3.CertFile = *fPop3TLSCert
	}
	if isFlagSet("pop3tlskey") {
		cfg.TLS.POP3.KeyFile = *fPop3TLSKey
	}

	if isFlagSet("lmtptls") {
		cfg.TLS.LMTP.Enable = *fLmtpTLS
	}
	if isFlagSet("lmtptlscert") {
		cfg.TLS.LMTP.CertFile = *fLmtpTLSCert
	}
	if isFlagSet("lmtptlskey") {
		cfg.TLS.LMTP.KeyFile = *fLmtpTLSKey
	}

	if isFlagSet("managesievetls") {
		cfg.TLS.ManageSieve.Enable = *fManageSieveTLS
	}
	if isFlagSet("managesievetlscert") {
		cfg.TLS.ManageSieve.CertFile = *fManageSieveTLSCert
	}
	if isFlagSet("managesievetlskey") {
		cfg.TLS.ManageSieve.KeyFile = *fManageSieveTLSKey
	}

	// --- Application Logic using cfg ---

	if !cfg.Servers.StartImap && !cfg.Servers.StartLmtp && !cfg.Servers.StartPop3 && !cfg.Servers.StartManageSieve {
		log.Fatal("No servers enabled. Please enable at least one server (IMAP, LMTP, or POP3).")
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

	if cfg.Servers.StartLmtp {
		go startLMTPServer(ctx, hostname, cfg.Servers.LmtpAddr, s3storage, database, uploadWorker, errChan, cfg)
	}
	if cfg.Servers.StartImap {
		go startIMAPServer(ctx, hostname, cfg.Servers.ImapAddr, s3storage, database, uploadWorker, cacheInstance, errChan, cfg)
	}
	if cfg.Servers.StartPop3 {
		go startPOP3Server(ctx, hostname, cfg.Servers.Pop3Addr, s3storage, database, uploadWorker, cacheInstance, errChan, cfg)
	}
	if cfg.Servers.StartManageSieve {
		go startManageSieveServer(ctx, hostname, cfg.Servers.ManageSieveAddr, database, errChan, cfg)
	}

	select {
	case <-ctx.Done():
		log.Println("Shutting down SORA servers...")
	case err := <-errChan:
		log.Fatalf("Server error: %v", err)
	}
}

func startIMAPServer(ctx context.Context, hostname, addr string, s3storage *storage.S3Storage, database *db.Database, uploadWorker *uploader.UploadWorker, cacheInstance *cache.Cache, errChan chan error, config Config) {
	s, err := imap.New(ctx, hostname, addr, s3storage, database, uploadWorker, cacheInstance,
		imap.IMAPServerOptions{
			InsecureAuth:       config.InsecureAuth,
			Debug:              config.Debug,
			TLSCertFile:        config.TLS.IMAP.CertFile,
			TLSKeyFile:         config.TLS.IMAP.KeyFile,
			InsecureSkipVerify: config.TLS.InsecureSkipVerify,
			MasterUsername:     config.Servers.MasterUsername,
			MasterPassword:     config.Servers.MasterPassword,
			MasterSASLUsername: config.Servers.MasterSASLUsername,
			MasterSASLPassword: config.Servers.MasterSASLPassword,
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
		ExternalRelay:      config.LMTP.ExternalRelay,
		InsecureSkipVerify: config.TLS.InsecureSkipVerify,
		TLSCertFile:        config.TLS.LMTP.CertFile,
		TLSKeyFile:         config.TLS.LMTP.KeyFile,
		Debug:              config.Debug,
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
		InsecureAuth:       config.InsecureAuth,
		Debug:              config.Debug,
		TLSCertFile:        config.TLS.POP3.CertFile,
		TLSKeyFile:         config.TLS.POP3.KeyFile,
		InsecureSkipVerify: config.TLS.InsecureSkipVerify,
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
	s, err := managesieve.New(ctx, hostname, addr, database, managesieve.ManageSieveServerOptions{
		InsecureSkipVerify: config.TLS.InsecureSkipVerify,
		TLSCertFile:        config.TLS.ManageSieve.CertFile,
		TLSKeyFile:         config.TLS.ManageSieve.KeyFile,
		Debug:              config.Debug,
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
