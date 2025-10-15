package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/migadu/sora/logger"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
)

// Version information, injected at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// AdminConfig holds minimal configuration needed for admin operations
type AdminConfig struct {
	Database   config.DatabaseConfig   `toml:"database"`
	S3         config.S3Config         `toml:"s3"`
	LocalCache config.LocalCacheConfig `toml:"local_cache"`
	Uploader   config.UploaderConfig   `toml:"uploader"`
	Cleanup    config.CleanupConfig    `toml:"cleanup"`
}

func newDefaultAdminConfig() AdminConfig {
	return AdminConfig{
		Database: config.DatabaseConfig{
			LogQueries: false,
			Write: &config.DatabaseEndpointConfig{
				Hosts:    []string{"localhost"},
				Port:     "5432",
				User:     "postgres",
				Password: "",
				Name:     "sora_mail_db",
				TLSMode:  false,
			},
			Read: &config.DatabaseEndpointConfig{
				Hosts:    []string{"localhost"},
				Port:     "5432",
				User:     "postgres",
				Password: "",
				Name:     "sora_mail_db",
				TLSMode:  false,
			},
		},
		S3: config.S3Config{
			Endpoint:      "",
			AccessKey:     "",
			SecretKey:     "",
			Bucket:        "",
			Encrypt:       false,
			EncryptionKey: "",
		},
		LocalCache: config.LocalCacheConfig{
			Path:               "/tmp/sora/cache",
			Capacity:           "1gb",
			MaxObjectSize:      "5mb",
			MetricsInterval:    "5m",
			PurgeInterval:      "12h",
			OrphanCleanupAge:   "30d",
			EnableWarmup:       true,
			WarmupMessageCount: 50,
			WarmupMailboxes:    []string{"INBOX"},
			WarmupAsync:        true,
		},
		Uploader: config.UploaderConfig{
			Path:          "/tmp/sora/uploads",
			BatchSize:     20,
			Concurrency:   10,
			MaxAttempts:   5,
			RetryInterval: "30s",
		},
		Cleanup: config.CleanupConfig{
			GracePeriod:           "14d",  // 14 days
			WakeInterval:          "1h",   // 1 hour
			FTSRetention:          "730d", // 2 years default
			AuthAttemptsRetention: "7d",   // 7 days
			HealthStatusRetention: "30d",  // 30 days
		},
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Create a context that is cancelled on an interrupt signal (Ctrl+C).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Allow 'sora-admin -v' and 'sora-admin --version' as shortcuts
	if os.Args[1] == "-v" || os.Args[1] == "--version" {
		printVersion()
		os.Exit(0)
	}

	command := os.Args[1]

	switch command {
	case "accounts":
		handleAccountsCommand(ctx)
	case "credentials":
		handleCredentialsCommand(ctx)
	case "cache":
		handleCacheCommand(ctx)
	case "stats":
		handleStatsCommand(ctx)
	case "connections":
		handleConnectionsCommand(ctx)
	case "health":
		handleHealthCommand(ctx)
	case "config":
		handleConfigCommand(ctx)
	case "migrate":
		handleMigrateCommand(ctx)
	case "version":
		printVersion()
	case "import":
		handleImportCommand(ctx)
	case "export":
		handleExportCommand(ctx)
	case "uploader":
		handleUploaderCommand(ctx)
	case "messages":
		handleMessagesCommand(ctx)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func handleAccountsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printAccountsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "create":
		handleCreateAccount(ctx)
	case "list":
		handleListAccounts(ctx)
	case "show":
		handleShowAccount(ctx)
	case "update":
		handleUpdateAccount(ctx)
	case "delete":
		handleDeleteAccount(ctx)
	case "restore":
		handleRestoreAccount(ctx)
	case "help", "--help", "-h":
		printAccountsUsage()
	default:
		fmt.Printf("Unknown accounts subcommand: %s\n\n", subcommand)
		printAccountsUsage()
		os.Exit(1)
	}
}

func handleCredentialsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printCredentialsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "add":
		handleAddCredential(ctx)
	case "list":
		handleListCredentials(ctx)
	case "show":
		handleShowCredential(ctx)
	case "delete":
		handleDeleteCredential(ctx)
	case "help", "--help", "-h":
		printCredentialsUsage()
	default:
		fmt.Printf("Unknown credentials subcommand: %s\n\n", subcommand)
		printCredentialsUsage()
		os.Exit(1)
	}
}

func handleCacheCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printCacheUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "stats":
		handleCacheStats(ctx)
	case "metrics":
		handleCacheMetrics(ctx)
	case "purge":
		handleCachePurge(ctx)
	case "help", "--help", "-h":
		printCacheUsage()
	default:
		fmt.Printf("Unknown cache subcommand: %s\n\n", subcommand)
		printCacheUsage()
		os.Exit(1)
	}
}

func handleStatsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printStatsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "auth":
		handleAuthStats(ctx)
	case "connection":
		handleConnectionStats(ctx)
	case "help", "--help", "-h":
		printStatsUsage()
	default:
		fmt.Printf("Unknown stats subcommand: %s\n\n", subcommand)
		printStatsUsage()
		os.Exit(1)
	}
}

func handleConnectionsCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printConnectionsUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list":
		handleListConnections(ctx)
	case "kick":
		handleKickConnections(ctx)
	case "help", "--help", "-h":
		printConnectionsUsage()
	default:
		fmt.Printf("Unknown connections subcommand: %s\n\n", subcommand)
		printConnectionsUsage()
		os.Exit(1)
	}
}

func handleUploaderCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printUploaderUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleUploaderStatus(ctx)
	case "help", "--help", "-h":
		printUploaderUsage()
	default:
		fmt.Printf("Unknown uploader subcommand: %s\n\n", subcommand)
		printUploaderUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("sora-admin version %s (commit: %s, built at: %s)\n", version, commit, date)
}

func printUsage() {
	fmt.Printf(`SORA Admin Tool

Usage:
  sora-admin <command> <subcommand> [options]

Commands:
  accounts      Manage user accounts
  credentials   Manage account credentials
  cache         Cache management operations
  stats         System statistics and analytics
  connections   Connection management
  health        System health status
  config        Configuration management
  migrate       Database schema migration management
  uploader      Upload queue management
  messages      List and restore deleted messages
  import        Import maildir data
  export        Export maildir data
  version       Show version information
  help          Show this help message

Examples:
  sora-admin accounts create --email user@example.com --password mypassword
  sora-admin accounts list
  sora-admin credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin credentials list --email user@example.com
  sora-admin cache stats
  sora-admin stats auth --window 1h
  sora-admin connections kick --user user@example.com

Use 'sora-admin <command> --help' for more information about a command group.
Use 'sora-admin <command> <subcommand> --help' for detailed help on specific commands.
`)
}

func printAccountsUsage() {
	fmt.Printf(`Account Management

Usage:
  sora-admin accounts <subcommand> [options]

Subcommands:
  create   Create a new account
  list     List all accounts in the system
  show     Show detailed information for a specific account
  update   Update an existing account's password
  delete   Delete an account (soft delete with grace period)
  restore  Restore a soft-deleted account

Examples:
  sora-admin accounts create --email user@example.com --password mypassword
  sora-admin accounts list
  sora-admin accounts show --email user@example.com
  sora-admin accounts update --email user@example.com --password newpassword
  sora-admin accounts delete --email user@example.com --confirm
  sora-admin accounts restore --email user@example.com

Use 'sora-admin accounts <subcommand> --help' for detailed help.
`)
}

func printCredentialsUsage() {
	fmt.Printf(`Credential Management

Usage:
  sora-admin credentials <subcommand> [options]

Subcommands:
  add      Add a credential to an existing account
  list     List all credentials for an account
  show     Show detailed information for a specific credential
  delete   Delete a specific credential from an account

Examples:
  sora-admin credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin credentials list --email user@example.com
  sora-admin credentials show --email user@example.com
  sora-admin credentials delete --email alias@example.com

Use 'sora-admin credentials <subcommand> --help' for detailed help.
`)
}

func printCacheUsage() {
	fmt.Printf(`Cache Management

Usage:
  sora-admin cache <subcommand> [options]

Subcommands:
  stats    Show local cache size and object count
  metrics  Show cache hit/miss ratios and performance metrics
  purge    Clear all cached objects

Examples:
  sora-admin cache stats
  sora-admin cache metrics --since 1h
  sora-admin cache purge

Use 'sora-admin cache <subcommand> --help' for detailed help.
`)
}

func printStatsUsage() {
	fmt.Printf(`System Statistics

Usage:
  sora-admin stats <subcommand> [options]

Subcommands:
  auth        Show authentication statistics and blocked IPs
  connection  Show active proxy connections and statistics

Examples:
  sora-admin stats auth --window 1h --blocked
  sora-admin stats connection --user user@example.com

Use 'sora-admin stats <subcommand> --help' for detailed help.
`)
}

func printConnectionsUsage() {
	fmt.Printf(`Connection Management

Usage:
  sora-admin connections <subcommand> [options]

Subcommands:
  list   List active proxy connections
  kick   Force disconnect proxy connections

Examples:
  sora-admin connections list
  sora-admin connections list --user user@example.com
  sora-admin connections kick --user user@example.com
  sora-admin connections kick --all

Use 'sora-admin connections <subcommand> --help' for detailed help.
`)
}

func printUploaderUsage() {
	fmt.Printf(`Upload Queue Management

Usage:
  sora-admin uploader <subcommand> [options]

Subcommands:
  status   Show uploader queue status and failed uploads

Examples:
  sora-admin uploader status
  sora-admin uploader status --show-failed=false
  sora-admin uploader status --failed-limit 20

Use 'sora-admin uploader <subcommand> --help' for detailed help.
`)
}

func handleCreateAccount(ctx context.Context) {
	// Parse accounts create specific flags
	fs := flag.NewFlagSet("accounts create", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the new account (required unless --credentials is provided)")
	password := fs.String("password", "", "Password for the new account (required unless --password-hash or --credentials is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")
	credentials := fs.String("credentials", "", "JSON string containing multiple credentials (alternative to single email/password)")

	fs.Usage = func() {
		fmt.Printf(`Create a new account

Usage:
  sora-admin accounts create [options]

Options:
  --email string         Email address for the new account (required unless --credentials is provided)
  --password string      Password for the new account (required unless --password-hash or --credentials is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --credentials string   JSON string containing multiple credentials (alternative to single email/password)
  --config string        Path to TOML configuration file (default: config.toml)

Examples:
  # Create account with single credential
  sora-admin accounts create --email user@example.com --password mypassword
  sora-admin accounts create --email user@example.com --password mypassword --hash ssha512
  sora-admin accounts create --email user@example.com --password-hash '$2a$12$xyz...'
  
  # Create account with multiple credentials
  sora-admin accounts create --credentials '[{"email":"user@example.com","password":"pass1","is_primary":true},{"email":"alias@example.com","password":"pass2","is_primary":false}]'
  
  # Create account with mixed credentials (password and password_hash)
  sora-admin accounts create --credentials '[{"email":"user@example.com","password":"pass1","is_primary":true},{"email":"alias@example.com","password_hash":"$2a$12$xyz...","is_primary":false}]'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *credentials == "" && *email == "" {
		fmt.Printf("Error: either --email or --credentials is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *credentials != "" && (*email != "" || *password != "" || *passwordHash != "") {
		fmt.Printf("Error: cannot specify --credentials with --email, --password, or --password-hash\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *credentials == "" {
		if *password == "" && *passwordHash == "" {
			fmt.Printf("Error: either --password or --password-hash is required\n\n")
			fs.Usage()
			os.Exit(1)
		}

		if *password != "" && *passwordHash != "" {
			fmt.Printf("Error: cannot specify both --password and --password-hash\n\n")
			fs.Usage()
			os.Exit(1)
		}
	}

	// Validate hash type
	validHashTypes := []string{"bcrypt", "ssha512", "sha512"}
	hashTypeValid := false
	for _, validType := range validHashTypes {
		if *hashType == validType {
			hashTypeValid = true
			break
		}
	}
	if !hashTypeValid {
		fmt.Printf("Error: --hash must be one of: %s\n\n", strings.Join(validHashTypes, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Create the account
	if *credentials != "" {
		// Create account with multiple credentials
		if err := createAccountWithCredentials(ctx, cfg, *credentials); err != nil {
			logger.Fatalf("Failed to create account with credentials: %v", err)
		}
		fmt.Printf("Successfully created account with multiple credentials\n")
	} else {
		// Create account with single credential (always as primary identity)
		if err := createAccount(ctx, cfg, *email, *password, *passwordHash, true, *hashType); err != nil {
			logger.Fatalf("Failed to create account: %v", err)
		}
		fmt.Printf("Successfully created account: %s\n", *email)
	}
}

func handleAddCredential(ctx context.Context) {
	// Parse add-credential specific flags
	fs := flag.NewFlagSet("credentials add", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	primaryIdentity := fs.String("primary", "", "Primary identity of the account to add credential to (required)")
	email := fs.String("email", "", "New email address to add as credential (required)")
	password := fs.String("password", "", "Password for the new credential (required unless --password-hash is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	makePrimary := fs.Bool("make-primary", false, "Make this the new primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Add a credential to an existing account

Usage:
  sora-admin credentials add [options]

Options:
  --primary string       Primary identity of the account to add credential to (required)
  --email string         New email address to add as credential (required)
  --password string      Password for the new credential (required unless --password-hash is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --make-primary         Make this the new primary identity for the account
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string        Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin credentials add --primary admin@example.com --email newalias@example.com --password mypassword --make-primary
  sora-admin credentials add --primary admin@example.com --email alias@example.com --password-hash '$2a$12$xyz...'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *primaryIdentity == "" {
		fmt.Printf("Error: --primary is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password == "" && *passwordHash == "" {
		fmt.Printf("Error: either --password or --password-hash is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password != "" && *passwordHash != "" {
		fmt.Printf("Error: cannot specify both --password and --password-hash\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate hash type
	validHashTypes := []string{"bcrypt", "ssha512", "sha512"}
	hashTypeValid := false
	for _, validType := range validHashTypes {
		if *hashType == validType {
			hashTypeValid = true
			break
		}
	}
	if !hashTypeValid {
		fmt.Printf("Error: --hash must be one of: %s\n\n", strings.Join(validHashTypes, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Add the credential
	if err := addCredential(ctx, cfg, *primaryIdentity, *email, *password, *passwordHash, *makePrimary, *hashType); err != nil {
		logger.Fatalf("Failed to add credential: %v", err)
	}

	fmt.Printf("Successfully added credential: %s to account with primary identity: %s\n", *email, *primaryIdentity)
}

func createAccount(ctx context.Context, cfg AdminConfig, email, password, passwordHash string, isPrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Create account using the new db operation
	req := db.CreateAccountRequest{
		Email:        email,
		Password:     password,
		PasswordHash: passwordHash,
		IsPrimary:    isPrimary,
		HashType:     hashType,
	}

	if err := rdb.CreateAccountWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

// CredentialInput represents a credential input from JSON
type CredentialInput struct {
	Email        string `json:"email"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	IsPrimary    bool   `json:"is_primary"`
	HashType     string `json:"hash_type,omitempty"`
}

func createAccountWithCredentials(ctx context.Context, cfg AdminConfig, credentialsJSON string) error {

	// Parse credentials JSON
	var credentialInputs []CredentialInput
	if err := json.Unmarshal([]byte(credentialsJSON), &credentialInputs); err != nil {
		return fmt.Errorf("invalid credentials JSON: %w", err)
	}

	if len(credentialInputs) == 0 {
		return fmt.Errorf("at least one credential must be provided")
	}

	// Convert to db.CredentialSpec
	credentials := make([]db.CredentialSpec, len(credentialInputs))
	for i, input := range credentialInputs {
		// Set default hash type if not specified
		hashType := input.HashType
		if hashType == "" {
			hashType = "bcrypt"
		}

		credentials[i] = db.CredentialSpec{
			Email:        input.Email,
			Password:     input.Password,
			PasswordHash: input.PasswordHash,
			IsPrimary:    input.IsPrimary,
			HashType:     hashType,
		}
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Create account with multiple credentials
	req := db.CreateAccountWithCredentialsRequest{
		Credentials: credentials,
	}

	accountID, err := rdb.CreateAccountWithCredentialsWithRetry(ctx, req)
	if err != nil {
		return err
	}

	logger.Infof("Created account with ID %d and %d credentials", accountID, len(credentials))
	return nil
}

func handleListConnections(ctx context.Context) {
	// Parse connections list specific flags
	fs := flag.NewFlagSet("connections list", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	userEmail := fs.String("user", "", "Filter connections by user email")
	protocol := fs.String("protocol", "", "Filter connections by protocol (IMAP, POP3, LMTP)")
	instanceID := fs.String("instance", "", "Filter connections by instance ID")

	fs.Usage = func() {
		fmt.Printf(`List active proxy connections

Usage:
  sora-admin connections list [options]

Options:
  --user string         Filter connections by user email
  --protocol string     Filter connections by protocol (IMAP, POP3, LMTP)  
  --instance string     Filter connections by instance ID
  --config string       Path to TOML configuration file (default: config.toml)

This command shows:
  - Active connections with client and server addresses
  - Protocol type and connection duration
  - User email and instance information
  - Connection activity status

Examples:
  sora-admin connections list
  sora-admin connections list --user user@example.com
  sora-admin connections list --protocol IMAP
  sora-admin connections list --instance server1
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// List connections
	if err := listConnections(ctx, cfg, *userEmail, *protocol, *instanceID); err != nil {
		logger.Fatalf("Failed to list connections: %v", err)
	}
}

func listConnections(ctx context.Context, cfg AdminConfig, userEmail, protocol, instanceID string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get all active connections
	connections, err := rdb.GetActiveConnectionsWithRetry(ctx)
	if err != nil {
		return fmt.Errorf("failed to get active connections: %w", err)
	}

	// Apply filters
	var filteredConnections []db.ConnectionInfo
	for _, conn := range connections {
		// Filter by user email
		if userEmail != "" && !strings.Contains(strings.ToLower(conn.Email), strings.ToLower(userEmail)) {
			continue
		}
		// Filter by protocol
		if protocol != "" && !strings.EqualFold(conn.Protocol, protocol) {
			continue
		}
		// Filter by instance ID
		if instanceID != "" && !strings.Contains(conn.InstanceID, instanceID) {
			continue
		}
		filteredConnections = append(filteredConnections, conn)
	}

	if len(filteredConnections) == 0 {
		if userEmail != "" || protocol != "" || instanceID != "" {
			fmt.Println("No active connections found matching the specified filters.")
		} else {
			fmt.Println("No active connections found.")
		}
		return nil
	}

	fmt.Printf("Found %d active connection(s):\n\n", len(filteredConnections))

	// Print header
	fmt.Printf("%-25s %-8s %-20s %-20s %-15s %-20s %-10s\n",
		"User", "Protocol", "Client", "Server", "Instance", "Connected", "Duration")
	fmt.Printf("%-25s %-8s %-20s %-20s %-15s %-20s %-10s\n",
		"----", "--------", "------", "------", "--------", "---------", "--------")

	// Print connection details
	now := time.Now()
	for _, conn := range filteredConnections {
		email := conn.Email
		if email == "" {
			email = fmt.Sprintf("account-%d", conn.AccountID)
		}

		duration := now.Sub(conn.ConnectedAt)
		durationStr := formatDuration(duration)

		// Truncate long fields for better display
		if len(email) > 24 {
			email = email[:21] + "..."
		}
		if len(conn.ClientAddr) > 19 {
			conn.ClientAddr = conn.ClientAddr[:16] + "..."
		}
		if len(conn.ServerAddr) > 19 {
			conn.ServerAddr = conn.ServerAddr[:16] + "..."
		}
		if len(conn.InstanceID) > 14 {
			conn.InstanceID = conn.InstanceID[:11] + "..."
		}

		fmt.Printf("%-25s %-8s %-20s %-20s %-15s %-20s %-10s\n",
			email,
			conn.Protocol,
			conn.ClientAddr,
			conn.ServerAddr,
			conn.InstanceID,
			conn.ConnectedAt.Format("2006-01-02 15:04:05"),
			durationStr)
	}

	fmt.Printf("\nTotal active connections: %d\n", len(filteredConnections))
	return nil
}

func handleKickConnections(ctx context.Context) {
	// Parse kick-connections specific flags
	fs := flag.NewFlagSet("connections kick", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	userEmail := fs.String("user", "", "Kick all connections for specific user email")
	protocol := fs.String("protocol", "", "Kick connections using specific protocol (IMAP, POP3, ManageSieve)")
	server := fs.String("server", "", "Kick connections to specific server")
	clientAddr := fs.String("client", "", "Kick connection from specific client address")
	all := fs.Bool("all", false, "Kick all active connections")
	confirm := fs.Bool("confirm", false, "Confirm kick without interactive prompt")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Force disconnect proxy connections

Usage:
  sora-admin kick-connections [options]

Options:
  --user string         Kick all connections for specific user email
  --protocol string     Kick connections using specific protocol (IMAP, POP3, ManageSieve)
  --server string       Kick connections to specific server
  --client string       Kick connection from specific client address
  --all                 Kick all active connections
  --confirm             Confirm kick without interactive prompt
  --config string       Path to TOML configuration file (default: config.toml)

This command marks connections for termination. The proxy servers check for
termination marks every 30 seconds and will close marked connections.

At least one filtering option (--user, --protocol, --server, --client, or --all) must be specified.

Examples:
  sora-admin kick-connections --user user@example.com
  sora-admin kick-connections --user user@example.com --protocol IMAP
  sora-admin kick-connections --server 127.0.0.1:143
  sora-admin kick-connections --all --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate that at least one filter is specified
	if *userEmail == "" && *protocol == "" && *server == "" && *clientAddr == "" && !*all {
		fmt.Printf("Error: At least one filtering option must be specified\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate protocol if specified
	if *protocol != "" {
		validProtocols := []string{"IMAP", "POP3", "ManageSieve"}
		valid := false
		for _, p := range validProtocols {
			if strings.EqualFold(*protocol, p) {
				valid = true
				*protocol = p // Normalize case
				break
			}
		}
		if !valid {
			fmt.Printf("Error: Invalid protocol. Must be one of: %s\n\n", strings.Join(validProtocols, ", "))
			fs.Usage()
			os.Exit(1)
		}
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Kick connections
	if err := kickConnections(ctx, cfg, *userEmail, *protocol, *server, *clientAddr, *all, *confirm); err != nil {
		logger.Fatalf("Failed to kick connections: %v", err)
	}
}

func kickConnections(ctx context.Context, cfg AdminConfig, userEmail, protocol, serverAddr, clientAddr string, all, autoConfirm bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Build criteria
	criteria := db.TerminationCriteria{
		Email:      userEmail,
		Protocol:   protocol,
		ServerAddr: serverAddr,
		ClientAddr: clientAddr,
	}

	// Get preview of what will be kicked
	stats, err := rdb.GetConnectionStatsWithRetry(ctx)
	if err != nil {
		return fmt.Errorf("failed to get connection stats: %w", err)
	}

	// Count matching connections
	matchCount := 0
	for _, conn := range stats.Users {
		if matches(conn, criteria, all) {
			matchCount++
		}
	}

	if matchCount == 0 {
		fmt.Println("No matching connections found.")
		return nil
	}

	// Show what will be kicked
	fmt.Printf("Connections to be kicked:\n")
	fmt.Printf("%-30s %-12s %-21s %-21s\n", "Email", "Protocol", "Client Address", "Server Address")
	fmt.Printf("%s\n", strings.Repeat("-", 84))

	for _, conn := range stats.Users {
		if matches(conn, criteria, all) {
			fmt.Printf("%-30s %-12s %-21s %-21s\n",
				conn.Email,
				conn.Protocol,
				conn.ClientAddr,
				conn.ServerAddr)
		}
	}

	fmt.Printf("\nTotal connections to kick: %d\n", matchCount)

	// Confirm if not auto-confirmed
	if !autoConfirm {
		fmt.Printf("\nAre you sure you want to kick these connections? (y/N): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Operation cancelled.")
			return nil
		}
	}

	// Mark connections for termination
	affected, err := rdb.MarkConnectionsForTerminationWithRetry(ctx, criteria)
	if err != nil {
		return fmt.Errorf("failed to mark connections for termination: %w", err)
	}

	fmt.Printf("\n%d connections marked for termination.\n", affected)
	fmt.Println("Connections will be closed within a few seconds.")
	return nil
}

// matches checks if a connection matches the given criteria
func matches(conn db.ConnectionInfo, criteria db.TerminationCriteria, all bool) bool {
	if all {
		return true
	}

	// Check each criteria
	if criteria.Email != "" && !strings.EqualFold(conn.Email, criteria.Email) {
		return false
	}

	if criteria.Protocol != "" && conn.Protocol != criteria.Protocol {
		return false
	}

	if criteria.ServerAddr != "" && conn.ServerAddr != criteria.ServerAddr {
		return false
	}

	if criteria.ClientAddr != "" && conn.ClientAddr != criteria.ClientAddr {
		return false
	}

	// If we get here, all specified criteria matched
	return criteria.Email != "" || criteria.Protocol != "" || criteria.ServerAddr != "" || criteria.ClientAddr != ""
}

func addCredential(ctx context.Context, cfg AdminConfig, primaryIdentity, email, password, passwordHash string, makePrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get the account ID for the primary identity
	// This read operation also needs resilience.
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, primaryIdentity)
	if err != nil {
		return fmt.Errorf("failed to find account with primary identity '%s': %w", primaryIdentity, err)
	}

	// Add credential using the new db operation
	req := db.AddCredentialRequest{
		AccountID:       accountID,
		NewEmail:        email,
		NewPassword:     password,
		NewPasswordHash: passwordHash,
		IsPrimary:       makePrimary,
		NewHashType:     hashType,
	}

	if err = rdb.AddCredentialWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

func handleUpdateAccount(ctx context.Context) {
	// Parse update-account specific flags
	fs := flag.NewFlagSet("accounts update", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to update (required)")
	password := fs.String("password", "", "New password for the account (optional if --password-hash or --make-primary is provided)")
	passwordHash := fs.String("password-hash", "", "Pre-computed password hash (alternative to --password)")
	makePrimary := fs.Bool("make-primary", false, "Make this credential the primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Update an existing account's password and/or primary status

Usage:
  sora-admin accounts update [options]

Options:
  --email string         Email address for the account to update (required)
  --password string      New password for the account (optional if --password-hash or --make-primary is provided)
  --password-hash string Pre-computed password hash (alternative to --password)
  --make-primary         Make this credential the primary identity for the account
  --hash string          Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string        Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin accounts update --email user@example.com --password newpassword
  sora-admin accounts update --email user@example.com --password newpassword --make-primary
  sora-admin accounts update --email user@example.com --make-primary
  sora-admin accounts update --email user@example.com --password newpassword --hash ssha512
  sora-admin accounts update --email user@example.com --password-hash '$2a$12$xyz...'
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password == "" && *passwordHash == "" && !*makePrimary {
		fmt.Printf("Error: either --password, --password-hash, or --make-primary must be specified\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password != "" && *passwordHash != "" {
		fmt.Printf("Error: cannot specify both --password and --password-hash\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Validate hash type
	validHashTypes := []string{"bcrypt", "ssha512", "sha512"}
	hashTypeValid := false
	for _, validType := range validHashTypes {
		if *hashType == validType {
			hashTypeValid = true
			break
		}
	}
	if !hashTypeValid {
		fmt.Printf("Error: --hash must be one of: %s\n\n", strings.Join(validHashTypes, ", "))
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Update the account
	if err := updateAccount(ctx, cfg, *email, *password, *passwordHash, *makePrimary, *hashType); err != nil {
		logger.Fatalf("Failed to update account: %v", err)
	}

	// Print appropriate success message based on what was updated
	if (*password != "" || *passwordHash != "") && *makePrimary {
		fmt.Printf("Successfully updated password and set as primary for account: %s\n", *email)
	} else if *password != "" || *passwordHash != "" {
		fmt.Printf("Successfully updated password for account: %s\n", *email)
	} else if *makePrimary {
		fmt.Printf("Successfully set as primary identity for account: %s\n", *email)
	}
}

func handleDeleteAccount(ctx context.Context) {
	// Parse delete-account specific flags
	fs := flag.NewFlagSet("accounts delete", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to delete (required)")
	confirm := fs.Bool("confirm", false, "Confirm account deletion (required)")

	fs.Usage = func() {
		fmt.Printf(`Soft-delete an account

This command soft-deletes an account by marking it for deletion. The account and
its data will be permanently removed by a background worker after a configurable
grace period.

During the grace period, the account can be restored using the 'accounts restore' command.

Usage:
  sora-admin accounts delete [options]

Options:
  --email string      Email address for the account to delete (required)
  --confirm           Confirm account soft-deletion (required for safety)
  --config string     Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin accounts delete --email user@example.com --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if !*confirm {
		fmt.Printf("Error: --confirm is required for account deletion\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Delete the account
	if err := deleteAccount(ctx, cfg, *email); err != nil {
		logger.Fatalf("Failed to delete account: %v", err)
	}

	fmt.Printf("Successfully soft-deleted account: %s. It will be permanently removed after the grace period.\n", *email)
}

func deleteAccount(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Delete the account using the existing database function
	if err := rdb.DeleteAccountWithRetry(ctx, email); err != nil {
		return fmt.Errorf("failed to delete account: %w", err)
	}

	return nil
}

func updateAccount(ctx context.Context, cfg AdminConfig, email, password, passwordHash string, makePrimary bool, hashType string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Update account using the new db operation
	req := db.UpdateAccountRequest{
		Email:        email,
		Password:     password,
		PasswordHash: passwordHash,
		HashType:     hashType,
		MakePrimary:  makePrimary,
	}

	if err := rdb.UpdateAccountWithRetry(ctx, req); err != nil {
		return err
	}

	return nil
}

func handleListCredentials(ctx context.Context) {
	// Parse list-credentials specific flags
	fs := flag.NewFlagSet("credentials list", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address associated with the account (required)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`List all credentials for an account

Usage:
  sora-admin list-credentials [options]

Options:
  --email string       Email address associated with the account (required)
  --config string      Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin list-credentials --email user@example.com
  sora-admin list-credentials --email alias@example.com --config custom.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// List the credentials
	if err := listCredentials(ctx, cfg, *email); err != nil {
		logger.Fatalf("Failed to list credentials: %v", err)
	}
}

func listCredentials(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// List credentials using the new db operation
	credentials, err := rdb.ListCredentialsWithRetry(ctx, email)
	if err != nil {
		return err
	}

	fmt.Printf("Credentials for account associated with %s:\n\n", email)

	for _, cred := range credentials {
		primaryMarker := ""
		if cred.PrimaryIdentity {
			primaryMarker = " * primary"
		}
		fmt.Printf("  %s%s\n", cred.Address, primaryMarker)
		fmt.Printf("    Created: %s\n", cred.CreatedAt)
		fmt.Printf("    Updated: %s\n", cred.UpdatedAt)
		fmt.Printf("\n")
	}

	fmt.Printf("Total credentials: %d\n", len(credentials))

	return nil
}

func handleDeleteCredential(ctx context.Context) {
	// Parse delete-credential specific flags
	fs := flag.NewFlagSet("credentials delete", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address of the credential to delete (required)")

	fs.Usage = func() {
		fmt.Printf(`Delete a specific credential from an account

This command removes a specific credential (email/password combination) from an account.

Restrictions:
- You cannot delete the primary credential. Use update-account to make another 
  credential primary first, then delete the old one.
- You cannot delete the last credential of an account. Use delete-account to 
  remove the entire account and all its data.

Usage:
  sora-admin delete-credential [options]

Options:
  --email string      Email address of the credential to delete (required)
  --config string     Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin delete-credential --email alias@example.com
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Delete the credential
	if err := deleteCredential(ctx, cfg, *email); err != nil {
		logger.Fatalf("Failed to delete credential: %v", err)
	}

	fmt.Printf("Successfully deleted credential: %s\n", *email)
}

func deleteCredential(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Delete the credential using the database function
	if err := rdb.DeleteCredentialWithRetry(ctx, email); err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	return nil
}

func handleListAccounts(ctx context.Context) {
	// Parse list-accounts specific flags
	fs := flag.NewFlagSet("accounts list", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")

	fs.Usage = func() {
		fmt.Printf(`List all accounts in the system

This command displays a summary of all accounts including:
- Account ID and primary email address
- Number of credentials (aliases) per account
- Number of mailboxes per account
- Total message count per account (excluding expunged messages)
- Account creation date

Usage:
  sora-admin list-accounts [options]

Options:
  --config string     Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin list-accounts
  sora-admin list-accounts --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// List accounts
	if err := listAccounts(ctx, cfg); err != nil {
		logger.Fatalf("Failed to list accounts: %v", err)
	}
}

func listAccounts(ctx context.Context, cfg AdminConfig) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// List accounts using the database function
	accounts, err := rdb.ListAccountsWithRetry(ctx)
	if err != nil {
		return err
	}

	if len(accounts) == 0 {
		fmt.Println("No accounts found in the system.")
		return nil
	}

	fmt.Printf("Found %d account(s):\n\n", len(accounts))

	// Print header
	fmt.Printf("%-8s %-30s %-10s %-10s %-12s %-20s\n",
		"ID", "Primary Email", "Credentials", "Mailboxes", "Messages", "Created")
	fmt.Printf("%-8s %-30s %-10s %-10s %-12s %-20s\n",
		"--", "-------------", "-----------", "---------", "--------", "-------")

	// Print account details
	for _, account := range accounts {
		primaryEmail := account.PrimaryEmail
		if primaryEmail == "" {
			primaryEmail = "<no primary>"
		}

		fmt.Printf("%-8d %-30s %-10d %-10d %-12d %-20s\n",
			account.AccountID,
			primaryEmail,
			account.CredentialCount,
			account.MailboxCount,
			account.MessageCount,
			account.CreatedAt)
	}

	fmt.Printf("\nTotal accounts: %d\n", len(accounts))
	return nil
}

func handleRestoreAccount(ctx context.Context) {
	// Parse accounts restore specific flags
	fs := flag.NewFlagSet("accounts restore", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to restore (required)")

	fs.Usage = func() {
		fmt.Printf(`Restore a soft-deleted account

This command restores an account that was previously deleted and is still within
the grace period. The account and all its data (mailboxes, messages, credentials)
will be restored to active status.

Usage:
  sora-admin accounts restore [options]

Options:
  --email string      Email address for the account to restore (required)
  --config string     Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin accounts restore --email user@example.com
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Restore the account
	if err := restoreAccount(ctx, cfg, *email); err != nil {
		logger.Fatalf("Failed to restore account: %v", err)
	}

	fmt.Printf("Successfully restored account: %s\n", *email)
}

func handleShowAccount(ctx context.Context) {
	// Parse show-account specific flags
	fs := flag.NewFlagSet("accounts show", flag.ExitOnError)
	email := fs.String("email", "", "Email address of the account to show")
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show detailed information for a specific account
This command displays comprehensive information about an account including:
- Account ID and status (active/deleted)
- Primary email address and all credential aliases
- Account creation date and deletion date (if soft-deleted)
- Number of mailboxes and total message count
- All associated email addresses with their status

Usage:
  sora-admin accounts show --email <email> [options]

Options:
  --email string      Email address of the account to show (required)
  --config string     Path to TOML configuration file (default: config.toml)
  --json             Output in JSON format instead of human-readable format

Examples:
  sora-admin accounts show --email user@example.com
  sora-admin accounts show --email user@example.com --json
  sora-admin accounts show --email user@example.com --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	var cfg AdminConfig
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		// Check if this is a file not found error and if so, be more flexible.
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show the account details
	if err := showAccount(ctx, cfg, *email, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show account: %v", err)
	}
}

func restoreAccount(ctx context.Context, cfg AdminConfig, email string) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Restore the account using the database function
	if err := rdb.RestoreAccountWithRetry(ctx, email); err != nil {
		return fmt.Errorf("failed to restore account: %w", err)
	}

	return nil
}

func showAccount(ctx context.Context, cfg AdminConfig, email string, jsonOutput bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get detailed account information
	accountDetails, err := rdb.GetAccountDetailsWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			return fmt.Errorf("account with email %s does not exist", email)
		}
		return fmt.Errorf("failed to get account details: %w", err)
	}

	// Output the results
	if jsonOutput {
		jsonData, err := json.MarshalIndent(accountDetails, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable output
		fmt.Printf("Account Details:\n")
		fmt.Printf("  Account ID:    %d\n", accountDetails.ID)
		fmt.Printf("  Primary Email: %s\n", accountDetails.PrimaryEmail)
		fmt.Printf("  Status:        %s\n", accountDetails.Status)
		fmt.Printf("  Created:       %s\n", accountDetails.CreatedAt.Format("2006-01-02 15:04:05 UTC"))

		if accountDetails.DeletedAt != nil {
			fmt.Printf("  Deleted:       %s\n", accountDetails.DeletedAt.Format("2006-01-02 15:04:05 UTC"))
		}

		fmt.Printf("  Mailboxes:     %d\n", accountDetails.MailboxCount)
		fmt.Printf("  Messages:      %d\n", accountDetails.MessageCount)

		fmt.Printf("\nCredentials (%d):\n", len(accountDetails.Credentials))
		for _, cred := range accountDetails.Credentials {
			status := "alias"
			if cred.PrimaryIdentity {
				status = "primary"
			}
			fmt.Printf("  %-30s %-8s created: %s\n",
				cred.Address,
				status,
				cred.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}

	return nil
}

func handleShowCredential(ctx context.Context) {
	// Parse show-credential specific flags
	fs := flag.NewFlagSet("credentials show", flag.ExitOnError)
	email := fs.String("email", "", "Email address (credential) to show details for")
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show detailed information for a specific credential

This command displays comprehensive information about a specific credential including:
- The email address and its account association
- Whether it's a primary identity or alias
- Creation and last update timestamps
- Account status (active/deleted)
- Associated account summary information

Usage:
  sora-admin credentials show --email <email> [options]

Options:
  --email string      Email address (credential) to show details for (required)
  --config string     Path to TOML configuration file (default: config.toml)
  --json             Output in JSON format instead of human-readable format

Examples:
  sora-admin credentials show --email user@example.com
  sora-admin credentials show --email alias@example.com --json
  sora-admin credentials show --email user@example.com --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	if *email == "" {
		fmt.Println("Error: --email is required")
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	var cfg AdminConfig
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		// Check if this is a file not found error and if so, be more flexible.
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show the credential details
	if err := showCredential(ctx, cfg, *email, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show credential: %v", err)
	}
}

func showCredential(ctx context.Context, cfg AdminConfig, email string, jsonOutput bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Get credential details and associated account information
	credentialDetails, err := rdb.GetCredentialDetailsWithRetry(ctx, email)
	if err != nil {
		return err // The error from the DB function is already descriptive
	}

	// Output the results
	if jsonOutput {
		jsonData, err := json.MarshalIndent(credentialDetails, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable output
		fmt.Printf("Credential Details:\n")
		fmt.Printf("  Email Address: %s\n", credentialDetails.Address)

		roleType := "Alias"
		if credentialDetails.PrimaryIdentity {
			roleType = "Primary Identity"
		}
		fmt.Printf("  Role: %s\n", roleType)

		fmt.Printf("  Created: %s\n", credentialDetails.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
		fmt.Printf("  Updated: %s\n", credentialDetails.UpdatedAt.Format("2006-01-02 15:04:05 UTC"))

		fmt.Printf("\nAssociated Account:\n")
		fmt.Printf("  Account ID: %d\n", credentialDetails.Account.ID)
		fmt.Printf("  Status: %s\n", credentialDetails.Account.Status)
		fmt.Printf("  Created: %s\n", credentialDetails.Account.CreatedAt.Format("2006-01-02 15:04:05 UTC"))

		if credentialDetails.Account.DeletedAt != nil {
			fmt.Printf("  Deleted: %s\n", credentialDetails.Account.DeletedAt.Format("2006-01-02 15:04:05 UTC"))
		}

		fmt.Printf("  Total Credentials: %d\n", credentialDetails.Account.TotalCredentials)
		fmt.Printf("  Mailboxes: %d\n", credentialDetails.Account.MailboxCount)
		fmt.Printf("  Messages: %d\n", credentialDetails.Account.MessageCount)
	}

	return nil
}

// Helper function to check if a flag was explicitly set
func isFlagSet(fs *flag.FlagSet, name string) bool {
	isSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			isSet = true
		}
	})
	return isSet
}

func handleMessagesCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printMessagesUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "list-deleted":
		handleListDeletedMessages(ctx)
	case "restore":
		handleRestoreMessages(ctx)
	case "help", "--help", "-h":
		printMessagesUsage()
	default:
		fmt.Printf("Unknown messages subcommand: %s\n\n", subcommand)
		printMessagesUsage()
		os.Exit(1)
	}
}

func printMessagesUsage() {
	fmt.Printf(`Message Management

Usage:
  sora-admin messages <subcommand> [options]

Subcommands:
  list-deleted   List deleted (expunged) messages for an account
  restore        Restore deleted messages to their original mailboxes

Examples:
  sora-admin messages list-deleted --email user@example.com
  sora-admin messages list-deleted --email user@example.com --mailbox INBOX --since 2024-01-01
  sora-admin messages restore --email user@example.com --mailbox INBOX
  sora-admin messages restore --email user@example.com --ids 123,456,789

Use 'sora-admin messages <subcommand> --help' for detailed help.
`)
}

func handleListDeletedMessages(ctx context.Context) {
	// Parse list-deleted-messages specific flags
	fs := flag.NewFlagSet("messages list-deleted", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Filter by mailbox path (optional)")
	since := fs.String("since", "", "Show messages deleted since this date (YYYY-MM-DD or RFC3339)")
	until := fs.String("until", "", "Show messages deleted until this date (YYYY-MM-DD or RFC3339)")
	limit := fs.Int("limit", 100, "Maximum number of messages to show")

	fs.Usage = func() {
		fmt.Printf(`List deleted (expunged) messages for an account

This command shows messages that have been deleted (expunged) but not yet
permanently removed by the cleanup worker. Messages in the grace period
can be restored using the 'restore' subcommand.

Usage:
  sora-admin messages list-deleted --email <email> [options]

Required Options:
  --email string        Email address of the account

Optional Filters:
  --mailbox string      Only show messages from this mailbox
  --since string        Only show messages deleted since this date (YYYY-MM-DD or RFC3339)
  --until string        Only show messages deleted until this date (YYYY-MM-DD or RFC3339)
  --limit int           Maximum number of messages to show (default: 100)

Other Options:
  --config string       Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin messages list-deleted --email user@example.com
  sora-admin messages list-deleted --email user@example.com --mailbox INBOX
  sora-admin messages list-deleted --email user@example.com --since 2024-01-01
  sora-admin messages list-deleted --email user@example.com --limit 50
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required flags
	if *email == "" {
		fmt.Println("ERROR: --email is required")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Parse time filters
	var sinceTime, untilTime *time.Time
	if *since != "" {
		t, err := parseTimeFlag(*since)
		if err != nil {
			logger.Fatalf("Invalid --since value: %v", err)
		}
		sinceTime = &t
	}
	if *until != "" {
		t, err := parseTimeFlag(*until)
		if err != nil {
			logger.Fatalf("Invalid --until value: %v", err)
		}
		untilTime = &t
	}

	// List deleted messages
	if err := listDeletedMessages(ctx, cfg, *email, mailbox, sinceTime, untilTime, *limit); err != nil {
		logger.Fatalf("Failed to list deleted messages: %v", err)
	}
}

func handleRestoreMessages(ctx context.Context) {
	// Parse restore-messages specific flags
	fs := flag.NewFlagSet("messages restore", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address of the account (required)")
	mailbox := fs.String("mailbox", "", "Restore all deleted messages from this mailbox")
	ids := fs.String("ids", "", "Comma-separated list of message IDs to restore")
	since := fs.String("since", "", "Restore messages deleted since this date (YYYY-MM-DD or RFC3339)")
	until := fs.String("until", "", "Restore messages deleted until this date (YYYY-MM-DD or RFC3339)")
	confirm := fs.Bool("confirm", false, "Confirm restoration without prompting")

	fs.Usage = func() {
		fmt.Printf(`Restore deleted messages to their original mailboxes

This command restores deleted (expunged) messages back to their original mailboxes.
If the original mailbox no longer exists, it will be recreated. Messages are
assigned new UIDs in their target mailboxes.

You can restore messages by:
  - Specific message IDs (--ids)
  - All messages from a mailbox (--mailbox)
  - Messages deleted within a time range (--since/--until)

Usage:
  sora-admin messages restore --email <email> [options]

Required Options:
  --email string        Email address of the account

Filter Options (choose one or combine):
  --ids string          Comma-separated list of message IDs to restore
  --mailbox string      Restore all deleted messages from this mailbox
  --since string        Restore messages deleted since this date (YYYY-MM-DD or RFC3339)
  --until string        Restore messages deleted until this date (YYYY-MM-DD or RFC3339)

Other Options:
  --confirm             Skip confirmation prompt
  --config string       Path to TOML configuration file (default: config.toml)

Examples:
  # Restore specific messages by ID
  sora-admin messages restore --email user@example.com --ids 123,456,789 --confirm

  # Restore all deleted messages from INBOX
  sora-admin messages restore --email user@example.com --mailbox INBOX --confirm

  # Restore messages deleted in the last 24 hours
  sora-admin messages restore --email user@example.com --since $(date -u -d '1 day ago' '+%%Y-%%m-%%d') --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required flags
	if *email == "" {
		fmt.Println("ERROR: --email is required")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Validate that at least one filter is provided
	if *ids == "" && *mailbox == "" && *since == "" && *until == "" {
		fmt.Println("ERROR: At least one filter option is required (--ids, --mailbox, --since, or --until)")
		fmt.Println()
		fs.Usage()
		os.Exit(1)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Parse message IDs if provided
	var messageIDs []int64
	if *ids != "" {
		parts := strings.Split(*ids, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			var id int64
			if _, err := fmt.Sscanf(part, "%d", &id); err != nil {
				logger.Fatalf("Invalid message ID '%s': %v", part, err)
			}
			messageIDs = append(messageIDs, id)
		}
	}

	// Parse time filters
	var sinceTime, untilTime *time.Time
	if *since != "" {
		t, err := parseTimeFlag(*since)
		if err != nil {
			logger.Fatalf("Invalid --since value: %v", err)
		}
		sinceTime = &t
	}
	if *until != "" {
		t, err := parseTimeFlag(*until)
		if err != nil {
			logger.Fatalf("Invalid --until value: %v", err)
		}
		untilTime = &t
	}

	// Restore messages
	if err := restoreMessages(ctx, cfg, *email, mailbox, messageIDs, sinceTime, untilTime, *confirm); err != nil {
		logger.Fatalf("Failed to restore messages: %v", err)
	}
}

func parseTimeFlag(value string) (time.Time, error) {
	// Try parsing as YYYY-MM-DD first
	if t, err := time.Parse("2006-01-02", value); err == nil {
		return t, nil
	}
	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid date format (use YYYY-MM-DD or RFC3339)")
}

func listDeletedMessages(ctx context.Context, cfg AdminConfig, email string, mailbox *string, since *time.Time, until *time.Time, limit int) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Build parameters
	params := db.ListDeletedMessagesParams{
		Email: email,
		Limit: limit,
	}
	if mailbox != nil && *mailbox != "" {
		params.MailboxPath = mailbox
	}
	if since != nil {
		params.Since = since
	}
	if until != nil {
		params.Until = until
	}

	// List deleted messages
	messages, err := rdb.ListDeletedMessagesWithRetry(ctx, params)
	if err != nil {
		return err
	}

	if len(messages) == 0 {
		fmt.Println("No deleted messages found matching the criteria.")
		return nil
	}

	fmt.Printf("Found %d deleted message(s):\n\n", len(messages))

	// Print header
	fmt.Printf("%-10s %-20s %-40s %-50s %-20s\n",
		"ID", "Mailbox", "Message-ID", "Subject", "Deleted At")
	fmt.Printf("%-10s %-20s %-40s %-50s %-20s\n",
		"--", "-------", "----------", "-------", "----------")

	// Print message details
	for _, msg := range messages {
		subject := msg.Subject
		if len(subject) > 47 {
			subject = subject[:47] + "..."
		}

		messageID := msg.MessageID
		if len(messageID) > 37 {
			messageID = messageID[:37] + "..."
		}

		mailboxPath := msg.MailboxPath
		if len(mailboxPath) > 17 {
			mailboxPath = mailboxPath[:17] + "..."
		}

		fmt.Printf("%-10d %-20s %-40s %-50s %-20s\n",
			msg.ID,
			mailboxPath,
			messageID,
			subject,
			msg.ExpungedAt.Format("2006-01-02 15:04:05"))
	}

	fmt.Printf("\nTotal deleted messages: %d\n", len(messages))

	if len(messages) == limit {
		fmt.Printf("Note: Result limited to %d messages. Use --limit to see more.\n", limit)
	}

	return nil
}

func restoreMessages(ctx context.Context, cfg AdminConfig, email string, mailbox *string, messageIDs []int64, since *time.Time, until *time.Time, confirm bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Build parameters
	params := db.RestoreMessagesParams{
		Email:      email,
		MessageIDs: messageIDs,
	}
	if mailbox != nil && *mailbox != "" {
		params.MailboxPath = mailbox
	}
	if since != nil {
		params.Since = since
	}
	if until != nil {
		params.Until = until
	}

	// If not confirmed, show what will be restored and ask for confirmation
	if !confirm {
		// First, list what will be restored
		listParams := db.ListDeletedMessagesParams{
			Email: email,
			Limit: 0, // no limit for preview
		}
		if mailbox != nil && *mailbox != "" {
			listParams.MailboxPath = mailbox
		}
		if since != nil {
			listParams.Since = since
		}
		if until != nil {
			listParams.Until = until
		}

		messages, err := rdb.ListDeletedMessagesWithRetry(ctx, listParams)
		if err != nil {
			return fmt.Errorf("failed to preview messages: %w", err)
		}

		// Filter by message IDs if provided
		if len(messageIDs) > 0 {
			idMap := make(map[int64]bool)
			for _, id := range messageIDs {
				idMap[id] = true
			}

			var filtered []db.DeletedMessage
			for _, msg := range messages {
				if idMap[msg.ID] {
					filtered = append(filtered, msg)
				}
			}
			messages = filtered
		}

		if len(messages) == 0 {
			fmt.Println("No messages found matching the criteria.")
			return nil
		}

		fmt.Printf("The following %d message(s) will be restored:\n\n", len(messages))
		for i, msg := range messages {
			if i >= 10 {
				fmt.Printf("... and %d more messages\n", len(messages)-10)
				break
			}
			fmt.Printf("  ID: %d, Mailbox: %s, Subject: %s\n", msg.ID, msg.MailboxPath, msg.Subject)
		}

		fmt.Printf("\nContinue with restoration? (yes/no): ")
		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "yes" && strings.ToLower(response) != "y" {
			fmt.Println("Restoration cancelled.")
			return nil
		}
	}

	// Perform restoration
	count, err := rdb.RestoreMessagesWithRetry(ctx, params)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully restored %d message(s).\n", count)
	return nil
}

func handleImportCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printImportUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "maildir":
		handleImportMaildir(ctx)
	case "s3":
		handleImportS3(ctx)
	case "--help", "-h":
		printImportUsage()
	default:
		fmt.Printf("Unknown import subcommand: %s\n\n", subcommand)
		printImportUsage()
		os.Exit(1)
	}
}

func printImportUsage() {
	fmt.Printf(`Import Management

Usage:
  sora-admin import <subcommand> [options]

Subcommands:
  maildir        Import maildir data
  s3             Import messages from S3 storage (recovery scenario)
  fix-subscriptions  Fix subscription status for default mailboxes

Examples:
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir
  sora-admin import maildir --email user@example.com --maildir-path /home/user/Maildir --dry-run
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --dovecot
  sora-admin import s3 --email user@example.com --dry-run
  sora-admin import s3 --email user@example.com --workers 5 --batch-size 500

Use 'sora-admin import <subcommand> --help' for detailed help.
`)
}

func handleImportMaildir(ctx context.Context) {
	// Parse import specific flags
	fs := flag.NewFlagSet("import", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to import mail to (required)")
	maildirPath := fs.String("maildir-path", "", "Path to the maildir to import (required)")
	jobs := fs.Int("jobs", 4, "Number of parallel import jobs")
	dryRun := fs.Bool("dry-run", false, "Preview what would be imported without making changes")
	preserveFlags := fs.Bool("preserve-flags", true, "Preserve maildir flags (Seen, Answered, etc)")
	showProgress := fs.Bool("progress", true, "Show import progress")
	delay := fs.Duration("delay", 0, "Delay between operations to control rate (e.g. 500ms)")
	forceReimport := fs.Bool("force-reimport", false, "Force reimport of messages even if they already exist")
	cleanupDB := fs.Bool("cleanup-db", false, "Remove the SQLite import database after successful import")
	dovecot := fs.Bool("dovecot", false, "Process Dovecot-specific files (subscriptions, keywords, uidlist)")
	sievePath := fs.String("sieve", "", "Path to Sieve script file to import for the user")
	preserveUIDs := fs.Bool("preserve-uids", false, "Preserve original UIDs from dovecot-uidlist files")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to import (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Import only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Import only messages before this date (YYYY-MM-DD)")

	fs.Usage = func() {
		fmt.Printf(`Import maildir from a given path

Usage:
  sora-admin import maildir [options]

Options:
  --email string          Email address for the account to import mail to (required)
  --maildir-path string   Path to the maildir root directory (must contain cur/, new/, tmp/) (required)
  --jobs int              Number of parallel import jobs (default: 4)
  --dry-run               Preview what would be imported without making changes
  --preserve-flags        Preserve maildir flags (default: true)  
  --progress              Show import progress (default: true)
  --delay duration        Delay between operations to control rate (e.g. 500ms)
  --force-reimport        Force reimport of messages even if they already exist
  --cleanup-db            Remove the SQLite import database after successful import
  --dovecot               Process Dovecot-specific files (subscriptions, dovecot-keywords, dovecot-uidlist)
  --sieve string          Path to Sieve script file to import for the user
  --preserve-uids         Preserve original UIDs from dovecot-uidlist files (implied by --dovecot)
  --mailbox-filter string Comma-separated list of mailboxes to import (e.g. INBOX,Sent,Archive*)
  --start-date string     Import only messages after this date (YYYY-MM-DD)
  --end-date string       Import only messages before this date (YYYY-MM-DD)
  --config string         Path to TOML configuration file (default: config.toml)

IMPORTANT: --maildir-path must point to a maildir root directory (containing cur/, new/, tmp/ subdirectories),
not to a parent directory containing multiple maildirs.

Use --dovecot flag to process Dovecot-specific files including 'subscriptions', 'dovecot-keywords', and
'dovecot-uidlist'. This will create missing mailboxes, subscribe the user to specified folders, preserve
custom IMAP keywords/flags, and maintain original UIDs from dovecot-uidlist files.

Examples:
  # Import all mail (correct path points to maildir root)
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/example.com/user/Maildir

  # Dry run to preview (note: correct maildir path)
  sora-admin import maildir --email user@example.com --maildir-path /home/user/Maildir --dry-run

  # Import only INBOX and Sent folders
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --mailbox-filter INBOX,Sent

  # Import messages from 2023
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --start-date 2023-01-01 --end-date 2023-12-31

  # Import with cleanup (removes SQLite database after completion)
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --cleanup-db

  # Import from Dovecot with subscriptions and custom keywords
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --dovecot

  # Import with Sieve script
  sora-admin import maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --sieve /path/to/user.sieve
`)
	}

	// Parse the remaining arguments (skip the command name and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *maildirPath == "" {
		fmt.Printf("Error: --maildir-path is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Parse date filters
	var startDateParsed, endDateParsed *time.Time
	if *startDate != "" {
		t, err := time.Parse("2006-01-02", *startDate)
		if err != nil {
			fmt.Printf("Error: Invalid start date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		startDateParsed = &t
	}
	if *endDate != "" {
		t, err := time.Parse("2006-01-02", *endDate)
		if err != nil {
			fmt.Printf("Error: Invalid end date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		// Add 23:59:59 to include the entire end date
		t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		endDateParsed = &t
	}

	// Parse mailbox filter
	var mailboxList []string
	if *mailboxFilter != "" {
		mailboxList = strings.Split(*mailboxFilter, ",")
		for i := range mailboxList {
			mailboxList[i] = strings.TrimSpace(mailboxList[i])
		}
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	s3, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.GetDebug())
	if err != nil {
		logger.Fatalf("Failed to connect to S3: %v", err)
	}
	if cfg.S3.Encrypt {
		if err := s3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	// Get FTS retention from config
	ftsRetention, err := cfg.Cleanup.GetFTSRetention()
	if err != nil {
		logger.Fatalf("Failed to parse FTS retention: %v", err)
	}

	// Create importer options
	options := ImporterOptions{
		DryRun:        *dryRun,
		StartDate:     startDateParsed,
		EndDate:       endDateParsed,
		MailboxFilter: mailboxList,
		PreserveFlags: *preserveFlags,
		ShowProgress:  *showProgress,
		ForceReimport: *forceReimport,
		CleanupDB:     *cleanupDB,
		Dovecot:       *dovecot,
		ImportDelay:   *delay,
		SievePath:     *sievePath,
		PreserveUIDs:  *preserveUIDs || *dovecot,
		FTSRetention:  ftsRetention,
	}

	importer, err := NewImporter(ctx, *maildirPath, *email, *jobs, rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		logger.Fatalf("Failed to import maildir: %v", err)
	}
}

func handleExportCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printExportUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "maildir":
		handleExportMaildir(ctx)
	case "--help", "-h":
		printExportUsage()
	default:
		fmt.Printf("Unknown export subcommand: %s\n\n", subcommand)
		printExportUsage()
		os.Exit(1)
	}
}

func printExportUsage() {
	fmt.Printf(`Export Management

Usage:
  sora-admin export <subcommand> [options]

Subcommands:
  maildir  Export messages to maildir format

Examples:
  sora-admin export maildir --email user@example.com --maildir-path /var/backup/user/Maildir
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --mailbox-filter INBOX,Sent
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --dovecot

Use 'sora-admin export <subcommand> --help' for detailed help.
`)
}

func handleExportMaildir(ctx context.Context) {
	// Parse export specific flags
	fs := flag.NewFlagSet("export", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to export mail from (required)")
	maildirPath := fs.String("maildir-path", "", "Path where the maildir will be created/updated (required)")
	jobs := fs.Int("jobs", 4, "Number of parallel export jobs")
	dryRun := fs.Bool("dry-run", false, "Preview what would be exported without making changes")
	showProgress := fs.Bool("progress", true, "Show export progress")
	delay := fs.Duration("delay", 0, "Delay between operations to control rate (e.g. 500ms)")
	dovecot := fs.Bool("dovecot", false, "Export Dovecot-specific files (subscriptions and dovecot-uidlist)")
	exportUIDList := fs.Bool("export-dovecot-uidlist", false, "Export dovecot-uidlist files with UID mappings")
	overwriteFlags := fs.Bool("overwrite-flags", false, "Update flags on existing messages")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to export (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Export only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Export only messages before this date (YYYY-MM-DD)")

	fs.Usage = func() {
		fmt.Printf(`Export messages to maildir format

Usage:
  sora-admin export maildir [options]

Options:
  --email string          Email address for the account to export mail from (required)
  --maildir-path string   Path where the maildir will be created/updated (required)
  --jobs int              Number of parallel export jobs (default: 4)
  --dry-run               Preview what would be exported without making changes
  --progress              Show export progress (default: true)
  --delay duration        Delay between operations to control rate (e.g. 500ms)
  --dovecot               Export Dovecot-specific files (subscriptions, dovecot-uidlist)
  --export-dovecot-uidlist Export dovecot-uidlist files with UID mappings (implied by --dovecot)
  --overwrite-flags       Update flags on existing messages (default: false)
  --mailbox-filter string Comma-separated list of mailboxes to export (e.g. INBOX,Sent,Archive*)
  --start-date string     Export only messages after this date (YYYY-MM-DD)
  --end-date string       Export only messages before this date (YYYY-MM-DD)
  --config string         Path to TOML configuration file (default: config.toml)

The exporter creates a SQLite database (sora-export.db) in the maildir path to track
exported messages and avoid duplicates. If exporting to an existing maildir, messages
with the same content hash will be skipped unless --overwrite-flags is specified.

Examples:
  # Export all mail to a new maildir
  sora-admin export maildir --email user@example.com --maildir-path /var/backup/user/Maildir

  # Export only INBOX and Sent folders
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --mailbox-filter INBOX,Sent

  # Export with Dovecot metadata (includes dovecot-uidlist files)
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --dovecot
  
  # Export with only dovecot-uidlist files (no subscriptions)
  sora-admin export maildir --email user@example.com --maildir-path /backup/maildir --export-dovecot-uidlist

  # Update flags on existing messages
  sora-admin export maildir --email user@example.com --maildir-path /existing/maildir --overwrite-flags
`)
	}

	// Parse the remaining arguments (skip the command name and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *maildirPath == "" {
		fmt.Printf("Error: --maildir-path is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	// Parse date filters
	var startDateParsed, endDateParsed *time.Time
	if *startDate != "" {
		t, err := time.Parse("2006-01-02", *startDate)
		if err != nil {
			fmt.Printf("Error: Invalid start date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		startDateParsed = &t
	}
	if *endDate != "" {
		t, err := time.Parse("2006-01-02", *endDate)
		if err != nil {
			fmt.Printf("Error: Invalid end date format. Use YYYY-MM-DD\n")
			os.Exit(1)
		}
		// Add 23:59:59 to include the entire end date
		t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		endDateParsed = &t
	}

	// Parse mailbox filter
	var mailboxList []string
	if *mailboxFilter != "" {
		mailboxList = strings.Split(*mailboxFilter, ",")
		for i := range mailboxList {
			mailboxList[i] = strings.TrimSpace(mailboxList[i])
		}
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	s3, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.GetDebug())
	if err != nil {
		logger.Fatalf("Failed to connect to S3: %v", err)
	}
	if cfg.S3.Encrypt {
		if err := s3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	// If dovecot flag is enabled, also enable UID list export
	exportUIDListEnabled := *exportUIDList || *dovecot

	// Create exporter options
	options := ExporterOptions{
		DryRun:         *dryRun,
		StartDate:      startDateParsed,
		EndDate:        endDateParsed,
		MailboxFilter:  mailboxList,
		ShowProgress:   *showProgress,
		Dovecot:        *dovecot,
		OverwriteFlags: *overwriteFlags,
		ExportDelay:    *delay,
		ExportUIDList:  exportUIDListEnabled,
	}

	exporter, err := NewExporter(ctx, *maildirPath, *email, *jobs, rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create exporter: %v", err)
	}

	if err := exporter.Run(); err != nil {
		logger.Fatalf("Failed to export maildir: %v", err)
	}
}

func handleCacheStats(ctx context.Context) {
	// Parse cache-stats specific flags
	fs := flag.NewFlagSet("cache stats", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")

	fs.Usage = func() {
		fmt.Printf(`Show local cache size and object count

Usage:
  sora-admin cache-stats [options]

Options:
  --config string      Path to TOML configuration file (default: config.toml)

This command shows:
  - Cache directory path
  - Number of cached objects
  - Total cache size in bytes and human-readable format
  - Cache capacity and maximum object size

Examples:
  sora-admin cache-stats
  sora-admin cache-stats --config /path/to/config.toml
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show cache stats
	if err := showCacheStats(ctx, cfg); err != nil {
		logger.Fatalf("Failed to show cache stats: %v", err)
	}
}

func handleCachePurge(ctx context.Context) {
	// Parse cache-purge specific flags
	fs := flag.NewFlagSet("cache purge", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	confirm := fs.Bool("confirm", false, "Confirm cache purge without interactive prompt")

	fs.Usage = func() {
		fmt.Printf(`Clear all cached objects

Usage:
  sora-admin cache-purge [options]

Options:
  --config string      Path to TOML configuration file (default: config.toml)
  --confirm            Confirm cache purge without interactive prompt

This command removes all cached objects from the local cache directory
and clears the cache index database. This action cannot be undone.

Examples:
  sora-admin cache-purge
  sora-admin cache-purge --confirm
  sora-admin cache-purge --config /path/to/config.toml --confirm
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Purge cache
	if err := purgeCacheWithConfirmation(ctx, cfg, *confirm); err != nil {
		logger.Fatalf("Failed to purge cache: %v", err)
	}
}

func showCacheStats(ctx context.Context, cfg AdminConfig) error {
	// Parse cache configuration using defaulting methods
	capacityBytes := cfg.LocalCache.GetCapacityWithDefault()
	maxObjectSizeBytes := cfg.LocalCache.GetMaxObjectSizeWithDefault()
	purgeInterval := cfg.LocalCache.GetPurgeIntervalWithDefault()
	orphanCleanupAge := cfg.LocalCache.GetOrphanCleanupAgeWithDefault()

	// Connect to minimal database instance for cache initialization
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, rdb)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cacheInstance.Close()

	// Get cache statistics
	stats, err := cacheInstance.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get cache statistics: %w", err)
	}

	// Display stats
	fmt.Printf("Cache Statistics\n")
	fmt.Printf("================\n\n")
	fmt.Printf("Cache path:         %s\n", cfg.LocalCache.Path)
	fmt.Printf("Object count:       %d\n", stats.ObjectCount)
	fmt.Printf("Total size:         %d bytes (%s)\n", stats.TotalSize, formatBytes(stats.TotalSize))
	fmt.Printf("Capacity:           %d bytes (%s)\n", capacityBytes, cfg.LocalCache.Capacity)
	fmt.Printf("Max object size:    %d bytes (%s)\n", maxObjectSizeBytes, cfg.LocalCache.MaxObjectSize)
	fmt.Printf("Utilization:        %.1f%%\n", float64(stats.TotalSize)/float64(capacityBytes)*100)

	return nil
}

func purgeCacheWithConfirmation(ctx context.Context, cfg AdminConfig, autoConfirm bool) error {
	if !autoConfirm {
		fmt.Printf("This will remove ALL cached objects from %s\n", cfg.LocalCache.Path)
		fmt.Printf("This action cannot be undone. Are you sure? (y/N): ")

		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}

		if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
			fmt.Println("Cache purge cancelled.")
			return nil
		}
	}

	// Parse cache configuration using defaulting methods
	capacityBytes := cfg.LocalCache.GetCapacityWithDefault()
	maxObjectSizeBytes := cfg.LocalCache.GetMaxObjectSizeWithDefault()
	purgeInterval := cfg.LocalCache.GetPurgeIntervalWithDefault()
	orphanCleanupAge := cfg.LocalCache.GetOrphanCleanupAgeWithDefault()

	// Connect to minimal database instance for cache initialization
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, purgeInterval, orphanCleanupAge, rdb)
	if err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}
	defer cacheInstance.Close()

	// Get current stats before purging
	stats, err := cacheInstance.GetStats()
	if err != nil {
		return fmt.Errorf("failed to get cache statistics before purge: %w", err)
	}

	fmt.Printf("Purging %d objects (%s) from cache...\n", stats.ObjectCount, formatBytes(stats.TotalSize))

	// Purge all cached objects
	if err := cacheInstance.PurgeAll(ctx); err != nil {
		return fmt.Errorf("failed to purge cache: %w", err)
	}

	fmt.Printf("Cache purged successfully.\n")
	return nil
}

func handleUploaderStatus(ctx context.Context) {
	// Parse uploader status specific flags
	fs := flag.NewFlagSet("uploader status", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	showFailed := fs.Bool("show-failed", true, "Show failed uploads details")
	failedLimit := fs.Int("failed-limit", 10, "Maximum number of failed uploads to show")

	fs.Usage = func() {
		fmt.Printf(`Show uploader queue status and failed uploads

Usage:
  sora-admin uploader status [options]

Options:
  --config string       Path to TOML configuration file (default: config.toml)
  --show-failed         Show failed uploads details (default: true)
  --failed-limit int    Maximum number of failed uploads to show (default: 10)

This command shows:
  - Number of pending uploads and total size
  - Number of failed uploads (reached max attempts)
  - Age of oldest pending upload
  - Details of failed uploads including content hashes and attempt counts

Examples:
  sora-admin uploader status
  sora-admin uploader status --config /path/to/config.toml
  sora-admin uploader status --failed-limit 20
  sora-admin uploader status --show-failed=false
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show uploader status
	if err := showUploaderStatus(ctx, cfg, *showFailed, *failedLimit); err != nil {
		logger.Fatalf("Failed to show uploader status: %v", err)
	}
}

func showUploaderStatus(ctx context.Context, cfg AdminConfig, showFailed bool, failedLimit int) error {
	// Connect to database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Validate retry interval parsing (for config validation)
	cfg.Uploader.GetRetryIntervalWithDefault()

	// Get uploader statistics
	stats, err := rdb.GetUploaderStatsWithRetry(ctx, cfg.Uploader.MaxAttempts)
	if err != nil {
		return fmt.Errorf("failed to get uploader stats: %w", err)
	}

	// Display uploader status
	fmt.Printf("Uploader Status\n")
	fmt.Printf("===============\n\n")
	fmt.Printf("Configuration:\n")
	fmt.Printf("  Upload path:        %s\n", cfg.Uploader.Path)
	fmt.Printf("  Batch size:         %d\n", cfg.Uploader.BatchSize)
	fmt.Printf("  Concurrency:        %d\n", cfg.Uploader.Concurrency)
	fmt.Printf("  Max attempts:       %d\n", cfg.Uploader.MaxAttempts)
	fmt.Printf("  Retry interval:     %s\n", cfg.Uploader.RetryInterval)
	fmt.Printf("\n")

	fmt.Printf("Queue Status:\n")
	fmt.Printf("  Pending uploads:    %d\n", stats.TotalPending)
	fmt.Printf("  Pending size:       %d bytes (%s)\n", stats.TotalPendingSize, formatBytes(stats.TotalPendingSize))
	fmt.Printf("  Failed uploads:     %d\n", stats.FailedUploads)

	if stats.OldestPending.Valid {
		age := time.Since(stats.OldestPending.Time)
		fmt.Printf("  Oldest pending:     %s (age: %s)\n", stats.OldestPending.Time.Format(time.RFC3339), formatDuration(age))
	} else {
		fmt.Printf("  Oldest pending:     N/A\n")
	}

	// Show failed uploads if requested
	if showFailed && stats.FailedUploads > 0 {
		fmt.Printf("\nFailed Uploads (showing up to %d):\n", failedLimit)
		fmt.Printf("%-10s %-10s %-64s %-8s %-12s %-19s %s\n", "ID", "Account ID", "Content Hash", "Size", "Attempts", "Created", "Instance ID")
		fmt.Printf("%s\n", strings.Repeat("-", 141))

		failedUploads, err := rdb.GetFailedUploadsWithRetry(ctx, cfg.Uploader.MaxAttempts, failedLimit)
		if err != nil {
			return fmt.Errorf("failed to get failed uploads: %w", err)
		}

		for _, upload := range failedUploads {
			fmt.Printf("%-10d %-10d %-64s %-8s %-12d %-19s %s\n",
				upload.ID,
				upload.AccountID,
				upload.ContentHash,
				formatBytes(upload.Size),
				upload.Attempts,
				upload.CreatedAt.Format("2006-01-02 15:04:05"),
				upload.InstanceID)
		}

		if int64(len(failedUploads)) < stats.FailedUploads {
			fmt.Printf("\n... and %d more failed uploads\n", stats.FailedUploads-int64(len(failedUploads)))
		}
	}

	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else {
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}

func handleConnectionStats(ctx context.Context) {
	// Parse connection-stats specific flags
	fs := flag.NewFlagSet("stats connection", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	userEmail := fs.String("user", "", "Show connections for specific user email")
	server := fs.String("server", "", "Show connections for specific server")
	cleanupStale := fs.Bool("cleanup-stale", false, "Remove stale connections (no activity for 30 minutes)")
	staleMinutes := fs.Int("stale-minutes", 30, "Minutes of inactivity to consider connection stale")
	showDetail := fs.Bool("detail", true, "Show detailed connection list")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Show active proxy connections and statistics

Usage:
  sora-admin connection-stats [options]

Options:
  --user string         Show connections for specific user email
  --server string       Show connections for specific server
  --cleanup-stale       Remove stale connections (no activity for specified minutes)
  --stale-minutes int   Minutes of inactivity to consider connection stale (default: 30)
  --detail              Show detailed connection list (default: true)
  --config string       Path to TOML configuration file (default: config.toml)

This command shows:
  - Total number of active connections
  - Connections grouped by protocol (IMAP, POP3, ManageSieve)
  - Connections grouped by server
  - Detailed list of all connections with user, protocol, client address, etc.
  - Option to filter by specific user or server
  - Option to cleanup stale connections

Examples:
  sora-admin connection-stats
  sora-admin connection-stats --user user@example.com
  sora-admin connection-stats --server 127.0.0.1:143
  sora-admin connection-stats --cleanup-stale
  sora-admin connection-stats --cleanup-stale --stale-minutes 60
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show connection statistics
	if err := showConnectionStats(ctx, cfg, *userEmail, *server, *cleanupStale, *staleMinutes, *showDetail); err != nil {
		logger.Fatalf("Failed to show connection stats: %v", err)
	}
}

func showConnectionStats(ctx context.Context, cfg AdminConfig, userEmail, serverFilter string, cleanupStale bool, staleMinutes int, showDetail bool) error {

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	// Cleanup stale connections if requested
	if cleanupStale {
		staleDuration := time.Duration(staleMinutes) * time.Minute
		removed, err := rdb.CleanupStaleConnectionsWithRetry(ctx, staleDuration)
		if err != nil {
			return fmt.Errorf("failed to cleanup stale connections: %w", err)
		}
		fmt.Printf("Cleaned up %d stale connections (no activity for %d minutes)\n\n", removed, staleMinutes)
	}

	// Get connection statistics
	var stats *db.ConnectionStats
	if userEmail != "" {
		// Get connections for specific user
		connections, err := rdb.GetUserConnectionsWithRetry(ctx, userEmail)
		if err != nil {
			return fmt.Errorf("failed to get user connections: %w", err)
		}

		// Build stats from user connections
		stats = &db.ConnectionStats{
			TotalConnections:      int64(len(connections)),
			ConnectionsByProtocol: make(map[string]int64),
			ConnectionsByServer:   make(map[string]int64),
			Users:                 connections,
		}

		// Count by protocol and server
		for _, conn := range connections {
			stats.ConnectionsByProtocol[conn.Protocol]++
			stats.ConnectionsByServer[conn.ServerAddr]++
		}
	} else {
		// Get all connection statistics
		stats, err = rdb.GetConnectionStatsWithRetry(ctx)
		if err != nil {
			return fmt.Errorf("failed to get connection stats: %w", err)
		}
	}

	// Apply server filter if specified
	if serverFilter != "" && userEmail == "" {
		filteredUsers := []db.ConnectionInfo{}
		for _, conn := range stats.Users {
			if conn.ServerAddr == serverFilter {
				filteredUsers = append(filteredUsers, conn)
			}
		}
		stats.Users = filteredUsers
	}

	if stats.TotalConnections == 0 && userEmail == "" && serverFilter == "" {
		fmt.Println("No active proxy connections found.")
		fmt.Println("\nNote: This command only shows connections made to Sora proxy servers (e.g., imap_proxy).")
		fmt.Println("Ensure your clients are connecting to the proxy ports defined in your configuration.")
		return nil
	}

	// Display statistics
	fmt.Printf("Active Proxy Connections\n")
	fmt.Printf("========================\n\n")

	if userEmail != "" {
		fmt.Printf("User: %s\n\n", userEmail)
	}
	if serverFilter != "" {
		fmt.Printf("Server: %s\n\n", serverFilter)
	}

	fmt.Printf("Summary:\n")
	fmt.Printf("  Total connections: %d\n", stats.TotalConnections)
	fmt.Printf("\n")

	// Show connections by protocol
	if len(stats.ConnectionsByProtocol) > 0 {
		fmt.Printf("By Protocol:\n")
		for protocol, count := range stats.ConnectionsByProtocol {
			fmt.Printf("  %-12s %d\n", protocol+":", count)
		}
		fmt.Printf("\n")
	}

	// Show connections by server
	if len(stats.ConnectionsByServer) > 0 && userEmail == "" && serverFilter == "" {
		fmt.Printf("By Server:\n")
		for server, count := range stats.ConnectionsByServer {
			fmt.Printf("  %-20s %d\n", server+":", count)
		}
		fmt.Printf("\n")
	}

	// Show detailed connection list
	if showDetail && len(stats.Users) > 0 {
		fmt.Printf("Active Connections:\n")
		fmt.Printf("%-30s %-12s %-21s %-21s %-19s %-19s\n", "Email", "Protocol", "Client Address", "Server Address", "Connected At", "Last Activity")
		fmt.Printf("%s\n", strings.Repeat("-", 135))

		for _, conn := range stats.Users {
			connectedTime := conn.ConnectedAt.Format("2006-01-02 15:04:05")
			lastActivityTime := conn.LastActivity.Format("2006-01-02 15:04:05")

			fmt.Printf("%-30s %-12s %-21s %-21s %-19s %-19s\n",
				conn.Email,
				conn.Protocol,
				conn.ClientAddr,
				conn.ServerAddr,
				connectedTime,
				lastActivityTime)
		}
		fmt.Printf("\n")

		// Show connection duration info
		now := time.Now()
		fmt.Printf("Connection Durations:\n")
		for _, conn := range stats.Users {
			duration := now.Sub(conn.ConnectedAt)
			idle := now.Sub(conn.LastActivity)
			fmt.Printf("  %s (%s): Connected for %s, idle for %s\n",
				conn.Email,
				conn.Protocol,
				formatDuration(duration),
				formatDuration(idle))
		}
	}

	return nil
}

func handleAuthStats(ctx context.Context) {
	// Parse auth-stats specific flags
	fs := flag.NewFlagSet("stats auth", flag.ExitOnError)
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	windowDuration := fs.String("window", "15m", "Time window for statistics (e.g., '15m', '1h', '24h')")
	showBlocked := fs.Bool("blocked", true, "Show currently blocked IPs and usernames")
	showStats := fs.Bool("stats", true, "Show overall authentication statistics")
	maxAttemptsIP := fs.Int("max-attempts-ip", 10, "Max attempts per IP for blocking threshold")
	maxAttemptsUsername := fs.Int("max-attempts-username", 5, "Max attempts per username for blocking threshold")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Show authentication statistics and blocked IPs
Usage:
  sora-admin auth-stats [options]

Options:
  --window string               Time window for statistics (default: "15m")
  --blocked                     Show currently blocked IPs and usernames (default: true)
  --stats                       Show overall authentication statistics (default: true)
  --max-attempts-ip int         Max attempts per IP for blocking threshold (default: 10)
  --max-attempts-username int   Max attempts per username for blocking threshold (default: 5)
  --config string              Path to TOML configuration file (default: "config.toml")


Examples:
  sora-admin auth-stats                                    # Show stats for last 15 minutes
  sora-admin auth-stats --window 1h --blocked             # Show blocked IPs in last hour
  sora-admin auth-stats --window 24h --stats              # Show 24-hour auth statistics
`)
	}

	err := fs.Parse(os.Args[2:])
	if err != nil {
		logger.Fatalf("Failed to parse flags: %v", err)
	}

	// Parse window duration
	window, err := time.ParseDuration(*windowDuration)
	if err != nil {
		logger.Fatalf("Invalid window duration '%s': %v", *windowDuration, err)
	}

	// Load configuration
	var adminConfig AdminConfig
	if _, err := toml.DecodeFile(*configPath, &adminConfig); err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	// Create context for database operations

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &adminConfig.Database, false, false)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	fmt.Printf("Authentication Statistics and Blocked IPs\n")
	fmt.Printf("Window: %s\n", window)
	fmt.Printf("Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Show general auth statistics
	if *showStats {
		stats, err := rdb.GetAuthAttemptsStatsWithRetry(ctx, window)
		if err != nil {
			logger.Infof("Failed to get auth statistics: %v", err)
		} else {
			fmt.Printf("Overall Statistics (last %s):\n", window)
			fmt.Printf("  Total Attempts:     %v\n", stats["total_attempts"])
			fmt.Printf("  Failed Attempts:    %v\n", stats["failed_attempts"])
			fmt.Printf("  Success Rate:       %.2f%%\n", stats["success_rate"])
			fmt.Printf("  Unique IPs:         %v\n", stats["unique_ips"])
			fmt.Printf("  Unique Usernames:   %v\n", stats["unique_usernames"])
			fmt.Printf("  Unique Protocols:   %v\n", stats["unique_protocols"])
			fmt.Printf("\n")
		}
	}

	// Show currently blocked IPs and usernames
	if *showBlocked {
		blocked, err := rdb.GetBlockedIPsWithRetry(ctx, window, window, *maxAttemptsIP, *maxAttemptsUsername)
		if err != nil {
			logger.Infof("Failed to get blocked IPs: %v", err)
		} else {
			if len(blocked) > 0 {
				fmt.Printf("Currently Blocked (exceeding thresholds):\n")
				fmt.Printf("%-12s %-25s %-8s %-20s %-20s %-25s\n", "Type", "Identifier", "Failures", "First Failure", "Last Failure", "Username")
				fmt.Printf("%s\n", strings.Repeat("-", 115))

				for _, block := range blocked {
					blockType := block["block_type"].(string)
					identifier := block["identifier"].(string)
					failureCount := block["failure_count"].(int)
					firstFailure := block["first_failure"].(time.Time)
					lastFailure := block["last_failure"].(time.Time)

					username := ""
					if block["username"] != nil {
						username = block["username"].(string)
					}

					fmt.Printf("%-12s %-25s %-8d %-20s %-20s %-25s\n",
						blockType,
						identifier,
						failureCount,
						firstFailure.Format("2006-01-02 15:04:05"),
						lastFailure.Format("2006-01-02 15:04:05"),
						username)
				}
				fmt.Printf("\nTotal blocked: %d\n", len(blocked))
			} else {
				fmt.Printf("No currently blocked IPs or usernames (exceeding %d failures per IP, %d per username).\n", *maxAttemptsIP, *maxAttemptsUsername)
			}
		}
	}
}

func handleHealthCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printHealthUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "status":
		handleHealthStatus(ctx)
	case "--help", "-h":
		printHealthUsage()
	default:
		fmt.Printf("Unknown health subcommand: %s\n\n", subcommand)
		printHealthUsage()
		os.Exit(1)
	}
}

func printHealthUsage() {
	fmt.Printf(`System Health Management

Usage:
  sora-admin health <subcommand> [options]

Subcommands:
  status   Show system health status and component monitoring

Examples:
  sora-admin health status
  sora-admin health status --hostname server1.example.com
  sora-admin health status --component database --detailed

Use 'sora-admin health <subcommand> --help' for detailed help.
`)
}

func handleHealthStatus(ctx context.Context) {
	fs := flag.NewFlagSet("health", flag.ExitOnError)

	// Command-specific flags
	hostname := fs.String("hostname", "", "Show health status for specific hostname")
	component := fs.String("component", "", "Show health status for specific component")
	detailed := fs.Bool("detailed", false, "Show detailed health information including metadata")
	history := fs.Bool("history", false, "Show health status history")
	since := fs.String("since", "1h", "Time window for history (e.g., 1h, 24h, 7d)")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	// Configuration
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")

	fs.Usage = func() {
		fmt.Printf(`Show system health status and component monitoring

Usage:
  sora-admin health status [options]

Options:
  --hostname string     Show health status for specific hostname
  --component string    Show health status for specific component
  --detailed            Show detailed health information including metadata
  --history             Show health status history
  --since string        Time window for history, e.g. 1h, 24h, 7d (default: 1h)
  --json                Output in JSON format
  --config string       Path to TOML configuration file (default: config.toml)

This command shows:
  - Overall system health status
  - Component health status (database, S3, circuit breakers)
  - Server-specific health information
  - Health status history and trends
  - Component failure rates and error details

Examples:
  sora-admin health status
  sora-admin health status --hostname server1.example.com
  sora-admin health status --component database --detailed
  sora-admin health status --history --since 24h
  sora-admin health status --json
`)
	}

	// Parse command arguments (skip program name, command name, and subcommand name)
	args := os.Args[3:]
	if err := fs.Parse(args); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Validate time window format for history
	var sinceTime time.Time
	if *history {
		duration, err := time.ParseDuration(*since)
		if err != nil {
			// time.ParseDuration doesn't support 'd' for days, so we handle it by converting to hours.
			if strings.HasSuffix(*since, "d") {
				sinceInHours := strings.Replace(*since, "d", "h", 1)
				if d, err := time.ParseDuration(sinceInHours); err == nil {
					duration = d * 24
				} else {
					// The inner parse failed, so the format is invalid.
					logger.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
				}
			} else {
				// The original parse failed and it's not a 'd' unit we can handle.
				logger.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
			}
		}
		sinceTime = time.Now().Add(-duration)
	}

	// Load configuration
	cfg := AdminConfig{}
	if _, err := os.Stat(*configPath); err == nil {
		if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	} else {
		if isFlagSet(fs, "config") {
			logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
		} else {
			logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
		}
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	if *jsonOutput {
		if err := showHealthStatusJSON(ctx, rdb, *hostname, *component, *detailed, *history, sinceTime); err != nil {
			logger.Fatalf("Failed to show health status: %v", err)
		}
	} else {
		if err := showHealthStatus(ctx, rdb, *hostname, *component, *detailed, *history, sinceTime); err != nil {
			logger.Fatalf("Failed to show health status: %v", err)
		}
	}
}

func showHealthStatus(ctx context.Context, rdb *resilient.ResilientDatabase, hostname, component string, detailed, history bool, sinceTime time.Time) error {
	if history && component != "" {
		return showComponentHistory(ctx, rdb, hostname, component, sinceTime)
	}

	// Show overview first
	overview, err := rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get system health overview: %w", err)
	}

	// Display system overview
	fmt.Printf("System Health Overview\n")
	fmt.Printf("======================\n\n")

	statusColor := getStatusColor(overview.OverallStatus)
	fmt.Printf("Overall Status: %s%s%s\n", statusColor, strings.ToUpper(string(overview.OverallStatus)), "\033[0m")
	fmt.Printf("Last Updated: %s\n", overview.LastUpdated.Format("2006-01-02 15:04:05 UTC"))
	if hostname != "" {
		fmt.Printf("Hostname: %s\n", hostname)
	}
	fmt.Printf("\n")

	// Component summary
	fmt.Printf("Component Summary:\n")
	fmt.Printf("  Total Components: %d\n", overview.ComponentCount)
	if overview.ComponentCount > 0 {
		fmt.Printf("  Healthy: %s%d%s\n", "\033[32m", overview.HealthyCount, "\033[0m")
		if overview.DegradedCount > 0 {
			fmt.Printf("  Degraded: %s%d%s\n", "\033[33m", overview.DegradedCount, "\033[0m")
		}
		if overview.UnhealthyCount > 0 {
			fmt.Printf("  Unhealthy: %s%d%s\n", "\033[31m", overview.UnhealthyCount, "\033[0m")
		}
		if overview.UnreachableCount > 0 {
			fmt.Printf("  Unreachable: %s%d%s\n", "\033[35m", overview.UnreachableCount, "\033[0m")
		}
	}
	fmt.Printf("\n")

	// Get detailed component status
	statuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get health statuses: %w", err)
	}

	if len(statuses) == 0 {
		fmt.Printf("No health data available.\n")
		if hostname != "" {
			fmt.Printf("Note: No health data found for hostname '%s'.\n", hostname)
		} else {
			fmt.Printf("Note: Health monitoring may not be active or data may have been cleaned up.\n")
		}
		return nil
	}

	// Filter by component if specified
	if component != "" {
		filteredStatuses := []*db.HealthStatus{}
		for _, status := range statuses {
			if status.ComponentName == component {
				filteredStatuses = append(filteredStatuses, status)
			}
		}
		statuses = filteredStatuses

		if len(statuses) == 0 {
			fmt.Printf("No health data found for component '%s'", component)
			if hostname != "" {
				fmt.Printf(" on hostname '%s'", hostname)
			}
			fmt.Printf(".\n")
			return nil
		}
	}

	// Display component details
	fmt.Printf("Component Health Details\n")
	fmt.Printf("========================\n\n")

	// Group by server hostname for better organization
	serverGroups := make(map[string][]*db.HealthStatus)
	for _, status := range statuses {
		serverGroups[status.ServerHostname] = append(serverGroups[status.ServerHostname], status)
	}

	for serverName, serverStatuses := range serverGroups {
		if len(serverGroups) > 1 {
			fmt.Printf("Server: %s\n", serverName)
			fmt.Printf("%s\n", strings.Repeat("-", len(serverName)+8))
		}

		for _, status := range serverStatuses {
			statusColor := getStatusColor(status.Status)
			fmt.Printf("%-20s %s%-12s%s", status.ComponentName, statusColor, strings.ToUpper(string(status.Status)), "\033[0m")

			// Calculate failure rate
			failureRate := 0.0
			if status.CheckCount > 0 {
				failureRate = float64(status.FailCount) / float64(status.CheckCount) * 100
			}

			fmt.Printf(" (%.1f%% failure rate)\n", failureRate)

			if detailed {
				fmt.Printf("  Last Check: %s\n", status.LastCheck.Format("2006-01-02 15:04:05 UTC"))
				fmt.Printf("  Checks: %d total, %d failed\n", status.CheckCount, status.FailCount)

				if status.LastError != nil {
					fmt.Printf("  Last Error: %s\n", *status.LastError)
				}

				if len(status.Metadata) > 0 {
					fmt.Printf("  Metadata:\n")
					for key, value := range status.Metadata {
						fmt.Printf("    %s: %v\n", key, value)
					}
				}
				fmt.Printf("\n")
			}
		}

		if len(serverGroups) > 1 {
			fmt.Printf("\n")
		}
	}

	return nil
}

func showComponentHistory(ctx context.Context, rdb *resilient.ResilientDatabase, hostname, component string, sinceTime time.Time) error {
	if hostname == "" {
		// Get all hostnames for this component
		allStatuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to get health statuses: %w", err)
		}

		hostnames := make(map[string]bool)
		for _, status := range allStatuses {
			if status.ComponentName == component {
				hostnames[status.ServerHostname] = true
			}
		}

		if len(hostnames) == 0 {
			fmt.Printf("No health data found for component '%s'.\n", component)
			return nil
		}

		// Show history for each hostname
		for hn := range hostnames {
			fmt.Printf("Component Health History: %s on %s\n", component, hn)
			fmt.Printf("%s\n", strings.Repeat("=", 40+len(component)+len(hn)))

			history, err := rdb.GetHealthHistoryWithRetry(ctx, hn, component, sinceTime, 50)
			if err != nil {
				fmt.Printf("Error getting history for %s: %v\n\n", hn, err)
				continue
			}

			showHistoryTable(history)
			fmt.Printf("\n")
		}
	} else {
		fmt.Printf("Component Health History: %s on %s\n", component, hostname)
		fmt.Printf("%s\n", strings.Repeat("=", 40+len(component)+len(hostname)))

		history, err := rdb.GetHealthHistoryWithRetry(ctx, hostname, component, sinceTime, 50)
		if err != nil {
			return fmt.Errorf("failed to get health history: %w", err)
		}

		showHistoryTable(history)
	}

	return nil
}

func showHistoryTable(history []*db.HealthStatus) {
	if len(history) == 0 {
		fmt.Printf("No health history available.\n")
		return
	}

	fmt.Printf("%-19s %-12s %-8s %-8s %s\n", "Timestamp", "Status", "Checks", "Failures", "Error")
	fmt.Printf("%s\n", strings.Repeat("-", 80))

	for _, h := range history {
		statusColor := getStatusColor(h.Status)
		errorMsg := ""
		if h.LastError != nil {
			errorMsg = *h.LastError
			if len(errorMsg) > 40 {
				errorMsg = errorMsg[:37] + "..."
			}
		}

		fmt.Printf("%-19s %s%-12s%s %-8d %-8d %s\n",
			h.UpdatedAt.Format("2006-01-02 15:04:05"),
			statusColor,
			strings.ToUpper(string(h.Status)),
			"\033[0m",
			h.CheckCount,
			h.FailCount,
			errorMsg)
	}
}

func showHealthStatusJSON(ctx context.Context, rdb *resilient.ResilientDatabase, hostname, component string, detailed, history bool, sinceTime time.Time) error {
	type JSONHealthOutput struct {
		Overview   *db.SystemHealthOverview `json:"overview"`
		Components []*db.HealthStatus       `json:"components,omitempty"`
		History    []*db.HealthStatus       `json:"history,omitempty"`
		Timestamp  time.Time                `json:"timestamp"`
		Filter     map[string]string        `json:"filter,omitempty"`
	}

	output := JSONHealthOutput{
		Timestamp: time.Now(),
		Filter:    make(map[string]string),
	}

	if hostname != "" {
		output.Filter["hostname"] = hostname
	}
	if component != "" {
		output.Filter["component"] = component
	}

	// Get overview
	overview, err := rdb.GetSystemHealthOverviewWithRetry(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get system health overview: %w", err)
	}
	output.Overview = overview

	if history && component != "" {
		// Get history for specific component
		if hostname == "" {
			// Get all hostnames for this component first
			allStatuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to get health statuses: %w", err)
			}

			for _, status := range allStatuses {
				if status.ComponentName == component {
					hist, err := rdb.GetHealthHistoryWithRetry(ctx, status.ServerHostname, component, sinceTime, 50)
					if err != nil {
						continue
					}
					output.History = append(output.History, hist...)
				}
			}
		} else {
			hist, err := rdb.GetHealthHistoryWithRetry(ctx, hostname, component, sinceTime, 50)
			if err != nil {
				return fmt.Errorf("failed to get health history: %w", err)
			}
			output.History = hist
		}
	} else {
		// Get current component status
		statuses, err := rdb.GetAllHealthStatusesWithRetry(ctx, hostname)
		if err != nil {
			return fmt.Errorf("failed to get health statuses: %w", err)
		}

		// Filter by component if specified
		if component != "" {
			filteredStatuses := []*db.HealthStatus{}
			for _, status := range statuses {
				if status.ComponentName == component {
					filteredStatuses = append(filteredStatuses, status)
				}
			}
			statuses = filteredStatuses
		}

		output.Components = statuses
	}

	// Remove metadata if not detailed mode
	if !detailed {
		for _, status := range output.Components {
			status.Metadata = nil
		}
		for _, status := range output.History {
			status.Metadata = nil
		}
	}

	// Output JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func getStatusColor(status db.ComponentStatus) string {
	switch status {
	case db.StatusHealthy:
		return "\033[32m" // Green
	case db.StatusDegraded:
		return "\033[33m" // Yellow
	case db.StatusUnhealthy:
		return "\033[31m" // Red
	case db.StatusUnreachable:
		return "\033[35m" // Magenta
	default:
		return "\033[0m" // Reset
	}
}

func handleCacheMetrics(ctx context.Context) {
	// Parse cache-metrics specific flags
	fs := flag.NewFlagSet("cache metrics", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	instanceID := fs.String("instance", "", "Show metrics for specific instance ID")
	since := fs.String("since", "24h", "Time window for historical metrics (e.g., 1h, 24h, 7d)")
	showHistory := fs.Bool("history", false, "Show historical metrics instead of just latest")
	limit := fs.Int("limit", 50, "Maximum number of historical records to show")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")

	fs.Usage = func() {
		fmt.Printf(`Show cache hit/miss ratios and performance metrics

Usage:
  sora-admin cache metrics [options]

Options:
  --instance string    Show metrics for specific instance ID
  --since string       Time window for historical metrics (default: 24h)
  --history            Show historical metrics instead of just latest
  --limit int          Maximum number of historical records to show (default: 50)
  --json               Output in JSON format
  --config string      Path to TOML configuration file (default: config.toml)

This command shows:
  - Cache hit/miss ratios for each instance
  - Total cache operations and performance trends
  - Instance uptime and performance over time
  - Historical trends when using --history flag

Examples:
  sora-admin cache metrics
  sora-admin cache metrics --instance server1-cache
  sora-admin cache metrics --history --since 7d
  sora-admin cache metrics --json
`)
	}

	// Parse the remaining arguments (skip the command and subcommand name)
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Error parsing flags: %v", err)
	}

	// Parse since duration
	sinceDuration, err := helpers.ParseDuration(*since)
	if err != nil {
		logger.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				logger.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				logger.Infof("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			logger.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show cache metrics
	if err := showCacheMetrics(ctx, cfg, *instanceID, sinceDuration, *showHistory, *limit, *jsonOutput); err != nil {
		logger.Fatalf("Failed to show cache metrics: %v", err)
	}
}

func showCacheMetrics(ctx context.Context, cfg AdminConfig, instanceID string, sinceDuration time.Duration, showHistory bool, limit int, jsonOutput bool) error {
	// Connect to database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		return fmt.Errorf("failed to initialize resilient database: %w", err)
	}
	defer rdb.Close()

	if showHistory {
		return showHistoricalCacheMetrics(ctx, rdb, instanceID, sinceDuration, limit, jsonOutput)
	}

	return showLatestCacheMetrics(ctx, rdb, instanceID, jsonOutput)
}

func showLatestCacheMetrics(ctx context.Context, rdb *resilient.ResilientDatabase, instanceID string, jsonOutput bool) error {
	var metrics []*db.CacheMetricsRecord
	var err error

	if instanceID != "" {
		// Get metrics for specific instance
		// Get the single most recent metric for the instance, regardless of age.
		metrics, err = rdb.GetCacheMetricsWithRetry(ctx, instanceID, time.Time{}, 1)
	} else {
		// Get latest metrics for all instances
		metrics, err = rdb.GetLatestCacheMetricsWithRetry(ctx)
	}

	if err != nil {
		return fmt.Errorf("failed to get cache metrics: %w", err)
	}

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"metrics":   metrics,
			"timestamp": time.Now(),
		})
	}

	if len(metrics) == 0 {
		fmt.Println("No cache metrics available.")
		fmt.Println("\nNote: Cache metrics are collected when the cache is actively used.")
		fmt.Println("Start the Sora server and perform some operations to generate metrics.")
		return nil
	}

	// Display metrics in table format
	fmt.Printf("Cache Performance Metrics (Latest)\n")
	fmt.Printf("==================================\n\n")

	fmt.Printf("%-20s %-15s %-8s %-8s %-8s %-12s %-10s %-19s\n",
		"Instance ID", "Server", "Hits", "Misses", "Hit Rate", "Total Ops", "Uptime", "Recorded At")
	fmt.Printf("%s\n", strings.Repeat("-", 110))

	for _, m := range metrics {
		uptimeDuration := time.Duration(m.UptimeSeconds) * time.Second
		fmt.Printf("%-20s %-15s %-8d %-8d %-7.1f%% %-12d %-10s %-19s\n",
			truncateString(m.InstanceID, 20),
			truncateString(m.ServerHostname, 15),
			m.Hits,
			m.Misses,
			m.HitRate,
			m.TotalOperations,
			formatDuration(uptimeDuration),
			m.RecordedAt.Format("2006-01-02 15:04:05"))
	}

	// Show summary statistics
	if len(metrics) > 1 {
		var totalHits, totalMisses, totalOps int64
		for _, m := range metrics {
			totalHits += m.Hits
			totalMisses += m.Misses
			totalOps += m.TotalOperations
		}

		overallHitRate := 0.0
		if totalOps > 0 {
			overallHitRate = float64(totalHits) / float64(totalOps) * 100
		}

		fmt.Printf("\nSummary Across All Instances:\n")
		fmt.Printf("  Total Instances: %d\n", len(metrics))
		fmt.Printf("  Combined Hits:   %d\n", totalHits)
		fmt.Printf("  Combined Misses: %d\n", totalMisses)
		fmt.Printf("  Overall Hit Rate: %.1f%%\n", overallHitRate)
	}

	return nil
}

func showHistoricalCacheMetrics(ctx context.Context, rdb *resilient.ResilientDatabase, instanceID string, sinceDuration time.Duration, limit int, jsonOutput bool) error {
	since := time.Now().Add(-sinceDuration)
	metrics, err := rdb.GetCacheMetricsWithRetry(ctx, instanceID, since, limit)
	if err != nil {
		return fmt.Errorf("failed to get cache metrics: %w", err)
	}

	if jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]interface{}{
			"metrics":   metrics,
			"since":     since,
			"timestamp": time.Now(),
		})
	}

	if len(metrics) == 0 {
		fmt.Printf("No cache metrics available for the last %s.\n", sinceDuration)
		return nil
	}

	fmt.Printf("Cache Performance Metrics (Historical - Last %s)\n", sinceDuration)
	fmt.Printf("=================================================\n\n")

	// Group by instance for better display
	instanceGroups := make(map[string][]*db.CacheMetricsRecord)
	for _, m := range metrics {
		instanceGroups[m.InstanceID] = append(instanceGroups[m.InstanceID], m)
	}

	for instance, instanceMetrics := range instanceGroups {
		fmt.Printf("Instance: %s\n", instance)
		fmt.Printf("%s\n", strings.Repeat("-", len(instance)+10))

		fmt.Printf("%-8s %-8s %-8s %-12s %-10s %-19s\n",
			"Hits", "Misses", "Hit Rate", "Total Ops", "Uptime", "Recorded At")
		fmt.Printf("%s\n", strings.Repeat("-", 75))

		for _, m := range instanceMetrics {
			uptimeDuration := time.Duration(m.UptimeSeconds) * time.Second
			fmt.Printf("%-8d %-8d %-7.1f%% %-12d %-10s %-19s\n",
				m.Hits,
				m.Misses,
				m.HitRate,
				m.TotalOperations,
				formatDuration(uptimeDuration),
				m.RecordedAt.Format("2006-01-02 15:04:05"))
		}
		fmt.Printf("\n")
	}

	return nil
}

func handleConfigCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printConfigUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "dump":
		handleConfigDump(ctx)
	case "--help", "-h":
		printConfigUsage()
	default:
		fmt.Printf("Unknown config subcommand: %s\n\n", subcommand)
		printConfigUsage()
		os.Exit(1)
	}
}

func printConfigUsage() {
	fmt.Printf(`Configuration Management

Usage:
  sora-admin config <subcommand> [options]

Subcommands:
  dump     Dump the parsed configuration for debugging

Examples:
  sora-admin config dump --config sora.config.toml
  sora-admin config dump --format json --mask-secrets=false
  sora-admin config dump --format pretty

Use 'sora-admin config <subcommand> --help' for detailed help.
`)
}

func handleConfigDump(ctx context.Context) {
	// Parse config-dump specific flags
	var configFile, format string
	var maskSecrets bool

	flagSet := flag.NewFlagSet("config-dump", flag.ExitOnError)
	flagSet.StringVar(&configFile, "config", "config.toml", "Path to configuration file")
	flagSet.StringVar(&format, "format", "toml", "Output format: toml, json, or pretty")
	flagSet.BoolVar(&maskSecrets, "mask-secrets", true, "Mask sensitive values (passwords, keys)")
	flagSet.Usage = func() {
		fmt.Printf(`Dump the parsed configuration for debugging

Usage:
  sora-admin config dump [options]

Options:
  --config PATH        Path to configuration file (default: config.toml)
  --format FORMAT      Output format: toml, json, or pretty (default: toml)
  --mask-secrets       Mask sensitive values like passwords (default: true)

Examples:
  sora-admin config dump --config sora.config.toml
  sora-admin config dump --format json --mask-secrets=false
  sora-admin config dump --format pretty
`)
	}

	flagSet.Parse(os.Args[3:])

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(configFile, &cfg); err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}

	// Mask secrets if requested
	if maskSecrets {
		if cfg.Database.Write != nil {
			cfg.Database.Write.Password = "***MASKED***"
		}
		if cfg.Database.Read != nil {
			cfg.Database.Read.Password = "***MASKED***"
		}
		cfg.S3.AccessKey = "***MASKED***"
		cfg.S3.SecretKey = "***MASKED***"
		cfg.S3.EncryptionKey = "***MASKED***"
	}

	// Output in requested format
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(cfg); err != nil {
			logger.Fatalf("Failed to encode config as JSON: %v", err)
		}
	case "pretty":
		printPrettyConfig(cfg)
	case "toml":
		encoder := toml.NewEncoder(os.Stdout)
		if err := encoder.Encode(cfg); err != nil {
			logger.Fatalf("Failed to encode config as TOML: %v", err)
		}
	default:
		logger.Fatalf("Unknown format: %s (supported: toml, json, pretty)", format)
	}
}

func printPrettyConfig(cfg AdminConfig) {
	fmt.Println("=== SORA ADMIN CONFIGURATION ===")
	fmt.Println()

	fmt.Println("DATABASE CONFIGURATION:")
	fmt.Printf("  Debug: %t\n", cfg.Database.GetDebug())

	if cfg.Database.Write != nil {
		fmt.Println("  Write Database:")
		fmt.Printf("    Hosts: %v\n", cfg.Database.Write.Hosts)
		fmt.Printf("    Port: %s\n", cfg.Database.Write.Port)
		fmt.Printf("    User: %s\n", cfg.Database.Write.User)
		fmt.Printf("    Password: %s\n", cfg.Database.Write.Password)
		fmt.Printf("    Database: %s\n", cfg.Database.Write.Name)
		fmt.Printf("    TLS Mode: %t\n", cfg.Database.Write.TLSMode)
		fmt.Printf("    Max Connections: %d\n", cfg.Database.Write.MaxConns)
		fmt.Printf("    Min Connections: %d\n", cfg.Database.Write.MinConns)
		fmt.Printf("    Max Connection Lifetime: %s\n", cfg.Database.Write.MaxConnLifetime)
		fmt.Printf("    Max Connection Idle Time: %s\n", cfg.Database.Write.MaxConnIdleTime)
	}

	if cfg.Database.Read != nil {
		fmt.Println("  Read Database:")
		fmt.Printf("    Hosts: %v\n", cfg.Database.Read.Hosts)
		fmt.Printf("    Port: %s\n", cfg.Database.Read.Port)
		fmt.Printf("    User: %s\n", cfg.Database.Read.User)
		fmt.Printf("    Password: %s\n", cfg.Database.Read.Password)
		fmt.Printf("    Database: %s\n", cfg.Database.Read.Name)
		fmt.Printf("    TLS Mode: %t\n", cfg.Database.Read.TLSMode)
		fmt.Printf("    Max Connections: %d\n", cfg.Database.Read.MaxConns)
		fmt.Printf("    Min Connections: %d\n", cfg.Database.Read.MinConns)
		fmt.Printf("    Max Connection Lifetime: %s\n", cfg.Database.Read.MaxConnLifetime)
		fmt.Printf("    Max Connection Idle Time: %s\n", cfg.Database.Read.MaxConnIdleTime)
	}

	fmt.Println()
	fmt.Println("S3 CONFIGURATION:")
	fmt.Printf("  Endpoint: %s\n", cfg.S3.Endpoint)
	fmt.Printf("  Disable TLS: %t\n", cfg.S3.DisableTLS)
	fmt.Printf("  Access Key: %s\n", cfg.S3.AccessKey)
	fmt.Printf("  Secret Key: %s\n", cfg.S3.SecretKey)
	fmt.Printf("  Bucket: %s\n", cfg.S3.Bucket)
	fmt.Printf("  Trace: %t\n", cfg.S3.GetDebug())
	fmt.Printf("  Encrypt: %t\n", cfg.S3.Encrypt)
	fmt.Printf("  Encryption Key: %s\n", cfg.S3.EncryptionKey)

	fmt.Println()
	fmt.Println("UPLOADER CONFIGURATION:")
	fmt.Printf("  Path: %s\n", cfg.Uploader.Path)
	fmt.Printf("  Batch Size: %d\n", cfg.Uploader.BatchSize)
	fmt.Printf("  Concurrency: %d\n", cfg.Uploader.Concurrency)
	fmt.Printf("  Max Attempts: %d\n", cfg.Uploader.MaxAttempts)
	fmt.Printf("  Retry Interval: %s\n", cfg.Uploader.RetryInterval)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func handleImportS3(ctx context.Context) {
	// Define flag set for S3 import
	fs := flag.NewFlagSet("import s3", flag.ExitOnError)

	// Define flags
	email := fs.String("email", "", "Email address to import messages for")
	batchSize := fs.Int("batch-size", 1000, "Number of S3 objects to process in each batch")
	maxObjects := fs.Int("max-objects", 0, "Maximum number of objects to process (0 = unlimited)")
	workers := fs.Int("workers", 5, "Number of concurrent workers")
	dryRun := fs.Bool("dry-run", false, "Show what would be imported without making changes")
	showProgress := fs.Bool("show-progress", true, "Show import progress")
	forceReimport := fs.Bool("force-reimport", false, "Force reimport even if message already exists")
	cleanupDB := fs.Bool("cleanup-db", true, "Cleanup temporary database when done")
	importDelay := fs.Duration("import-delay", 0, "Delay between imports to control rate")
	continuationToken := fs.String("continuation-token", "", "S3 continuation token to resume from")
	configPath := fs.String("config", "config.toml", "Path to configuration file")

	// Parse the flags
	if err := fs.Parse(os.Args[3:]); err != nil {
		logger.Fatalf("Failed to parse flags: %v", err)
	}

	// Validate required flags
	if *email == "" {
		logger.Fatal("--email is required (e.g., 'user@example.com')")
	}

	// Load configuration
	var cfg AdminConfig
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}

	// Connect to resilient database
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, false)
	if err != nil {
		logger.Fatalf("Failed to initialize resilient database: %v", err)
	}
	defer rdb.Close()

	// Connect to S3
	s3, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.GetDebug())
	if err != nil {
		logger.Fatalf("Failed to connect to S3: %v", err)
	}
	if cfg.S3.Encrypt {
		if err := s3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			logger.Fatalf("Failed to enable S3 encryption: %v", err)
		}
	}

	// Configure S3 importer options
	options := S3ImporterOptions{
		Email:             *email,
		DryRun:            *dryRun,
		BatchSize:         *batchSize,
		MaxObjects:        *maxObjects,
		ShowProgress:      *showProgress,
		ForceReimport:     *forceReimport,
		CleanupDB:         *cleanupDB,
		ImportDelay:       *importDelay,
		ContinuationToken: *continuationToken,
		Workers:           *workers,
	}

	importer, err := NewS3Importer(rdb, s3, options)
	if err != nil {
		logger.Fatalf("Failed to create S3 importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		logger.Fatalf("Failed to import from S3: %v", err)
	}
}
