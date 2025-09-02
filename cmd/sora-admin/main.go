package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/storage"
)

// AdminConfig holds minimal configuration needed for admin operations
type AdminConfig struct {
	Database   config.DatabaseConfig `toml:"database"`
	S3         S3Config              `toml:"s3"`
	LocalCache LocalCacheConfig      `toml:"local_cache"`
	Uploader   UploaderConfig        `toml:"uploader"`
}

// S3Config holds S3 configuration - copied from main config
type S3Config struct {
	Endpoint      string `toml:"endpoint"`
	DisableTLS    bool   `toml:"disable_tls"`
	AccessKey     string `toml:"access_key"`
	SecretKey     string `toml:"secret_key"`
	Bucket        string `toml:"bucket"`
	Trace         bool   `toml:"trace"`
	Encrypt       bool   `toml:"encrypt"`
	EncryptionKey string `toml:"encryption_key"`
}

// LocalCacheConfig holds cache configuration - copied from main config
type LocalCacheConfig struct {
	Path          string `toml:"path"`
	Capacity      string `toml:"capacity"`
	MaxObjectSize string `toml:"max_object_size"`
}

// UploaderConfig holds uploader configuration - copied from main config
type UploaderConfig struct {
	Path          string `toml:"path"`
	BatchSize     int    `toml:"batch_size"`
	Concurrency   int    `toml:"concurrency"`
	MaxAttempts   int    `toml:"max_attempts"`
	RetryInterval string `toml:"retry_interval"`
}

func newDefaultAdminConfig() AdminConfig {
	return AdminConfig{
		Database: config.DatabaseConfig{
			LogQueries: false,
			Write: &config.DatabaseEndpointConfig{
				Hosts:    []string{"localhost:5432"},
				User:     "postgres",
				Password: "",
				Name:     "sora_mail_db",
				TLSMode:  false,
			},
			Read: &config.DatabaseEndpointConfig{
				Hosts:    []string{"localhost:5432"},
				User:     "postgres",
				Password: "",
				Name:     "sora_mail_db",
				TLSMode:  false,
			},
		},
		S3: S3Config{
			Endpoint:      "",
			AccessKey:     "",
			SecretKey:     "",
			Bucket:        "",
			Encrypt:       false,
			EncryptionKey: "",
		},
		LocalCache: LocalCacheConfig{
			Path:          "/tmp/sora/cache",
			Capacity:      "1gb",
			MaxObjectSize: "5mb",
		},
		Uploader: UploaderConfig{
			Path:          "/tmp/sora/uploads",
			BatchSize:     20,
			Concurrency:   10,
			MaxAttempts:   5,
			RetryInterval: "30s",
		},
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "create-account":
		handleCreateAccount()
	case "add-credential":
		handleAddCredential()
	case "update-account":
		handleUpdateAccount()
	case "list-credentials":
		handleListCredentials()
	case "import-maildir":
		handleImportMaildir()
	case "export-maildir":
		handleExportMaildir()
	case "cache-stats":
		handleCacheStats()
	case "cache-purge":
		handleCachePurge()
	case "uploader-status":
		handleUploaderStatus()
	case "connection-stats":
		handleConnectionStats()
	case "kick-connections":
		handleKickConnections()
	case "auth-stats":
		handleAuthStats()
	case "health-status":
		handleHealthStatus()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`SORA Admin Tool

Usage:
  sora-admin <command> [options]

Commands:
  create-account    Create a new account
  add-credential    Add a credential to an existing account
  update-account    Update an existing account's password
  list-credentials  List all credentials for an account
  import-maildir    Import maildir from a given path
  export-maildir    Export messages to maildir format
  cache-stats       Show local cache size and object count
  cache-purge       Clear all cached objects
  uploader-status   Show uploader queue status and failed uploads
  connection-stats  Show active proxy connections and statistics
  kick-connections  Force disconnect proxy connections
  auth-stats        Show authentication statistics and blocked IPs
  health-status     Show system health status and component monitoring
  help              Show this help message

Examples:
  sora-admin create-account --email user@example.com --password mypassword
  sora-admin add-credential --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin update-account --email user@example.com --password newpassword
  sora-admin list-credentials --email user@example.com
  sora-admin cache-stats --config /path/to/config.toml
  sora-admin auth-stats --window 1h --blocked
  sora-admin cache-purge --config /path/to/config.toml
  sora-admin uploader-status --config /path/to/config.toml
  sora-admin connection-stats --config /path/to/config.toml
  sora-admin kick-connections --user user@example.com

Use 'sora-admin <command> --help' for more information about a command.
`)
}

func handleCreateAccount() {
	// Parse create-account specific flags
	fs := flag.NewFlagSet("create-account", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the new account (required)")
	password := fs.String("password", "", "Password for the new account (required)")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	fs.Usage = func() {
		fmt.Printf(`Create a new account

Usage:
  sora-admin create-account [options]

Options:
  --email string       Email address for the new account (required)
  --password string    Password for the new account (required)
  --hash string        Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string      Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin create-account --email user@example.com --password mypassword
  sora-admin create-account --email user@example.com --password mypassword --hash ssha512
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password == "" {
		fmt.Printf("Error: --password is required\n\n")
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Create the account (always as primary identity)
	if err := createAccount(cfg, *email, *password, true, *hashType); err != nil {
		log.Fatalf("Failed to create account: %v", err)
	}

	fmt.Printf("Successfully created account: %s\n", *email)
}

func handleAddCredential() {
	// Parse add-credential specific flags
	fs := flag.NewFlagSet("add-credential", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	primaryIdentity := fs.String("primary", "", "Primary identity of the account to add credential to (required)")
	email := fs.String("email", "", "New email address to add as credential (required)")
	password := fs.String("password", "", "Password for the new credential (required)")
	makePrimary := fs.Bool("make-primary", false, "Make this the new primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Add a credential to an existing account

Usage:
  sora-admin add-credential [options]

Options:
  --primary string      Primary identity of the account to add credential to (required)
  --email string        New email address to add as credential (required)
  --password string     Password for the new credential (required)
  --make-primary        Make this the new primary identity for the account
  --hash string         Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string       Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin add-credential --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin add-credential --primary admin@example.com --email newalias@example.com --password mypassword --make-primary
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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

	if *password == "" && !*makePrimary {
		fmt.Printf("Error: either --password or --make-primary must be specified\n\n")
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Add the credential
	if err := addCredential(cfg, *primaryIdentity, *email, *password, *makePrimary, *hashType); err != nil {
		log.Fatalf("Failed to add credential: %v", err)
	}

	fmt.Printf("Successfully added credential: %s to account with primary identity: %s\n", *email, *primaryIdentity)
}

func createAccount(cfg AdminConfig, email, password string, isPrimary bool, hashType string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Create account using the new db operation
	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		IsPrimary: isPrimary,
		HashType:  hashType,
	}

	if err := database.CreateAccount(ctx, req); err != nil {
		return err
	}

	return nil
}

func handleKickConnections() {
	// Parse kick-connections specific flags
	fs := flag.NewFlagSet("kick-connections", flag.ExitOnError)

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

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Kick connections
	if err := kickConnections(cfg, *userEmail, *protocol, *server, *clientAddr, *all, *confirm); err != nil {
		log.Fatalf("Failed to kick connections: %v", err)
	}
}

func kickConnections(cfg AdminConfig, userEmail, protocol, serverAddr, clientAddr string, all, autoConfirm bool) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Build criteria
	criteria := db.TerminationCriteria{
		Email:      userEmail,
		Protocol:   protocol,
		ServerAddr: serverAddr,
		ClientAddr: clientAddr,
	}

	// Get preview of what will be kicked
	stats, err := database.GetConnectionStats(ctx)
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
	affected, err := database.MarkConnectionsForTermination(ctx, criteria)
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

func addCredential(cfg AdminConfig, primaryIdentity, email, password string, makePrimary bool, hashType string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Add credential using the new db operation
	req := db.AddCredentialRequest{
		PrimaryIdentity: primaryIdentity,
		NewEmail:        email,
		Password:        password,
		IsPrimary:       makePrimary,
		HashType:        hashType,
	}

	if err := database.AddCredential(ctx, req); err != nil {
		return err
	}

	return nil
}

func handleUpdateAccount() {
	// Parse update-account specific flags
	fs := flag.NewFlagSet("update-account", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to update (required)")
	password := fs.String("password", "", "New password for the account (required)")
	makePrimary := fs.Bool("make-primary", false, "Make this credential the primary identity for the account")
	hashType := fs.String("hash", "bcrypt", "Password hash type (bcrypt, ssha512, sha512)")

	// Database connection flags (overrides from config file)

	fs.Usage = func() {
		fmt.Printf(`Update an existing account's password and/or primary status

Usage:
  sora-admin update-account [options]

Options:
  --email string        Email address for the account to update (required)
  --password string     New password for the account (optional with --make-primary)
  --make-primary        Make this credential the primary identity for the account
  --hash string        Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string      Path to TOML configuration file (default: config.toml)

Examples:
  sora-admin update-account --email user@example.com --password newpassword
  sora-admin update-account --email user@example.com --password newpassword --make-primary
  sora-admin update-account --email user@example.com --make-primary
  sora-admin update-account --email user@example.com --password newpassword --hash ssha512
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Validate required arguments
	if *email == "" {
		fmt.Printf("Error: --email is required\n\n")
		fs.Usage()
		os.Exit(1)
	}

	if *password == "" && !*makePrimary {
		fmt.Printf("Error: either --password or --make-primary must be specified\n\n")
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Update the account
	if err := updateAccount(cfg, *email, *password, *makePrimary, *hashType); err != nil {
		log.Fatalf("Failed to update account: %v", err)
	}

	// Print appropriate success message based on what was updated
	if *password != "" && *makePrimary {
		fmt.Printf("Successfully updated password and set as primary for account: %s\n", *email)
	} else if *password != "" {
		fmt.Printf("Successfully updated password for account: %s\n", *email)
	} else if *makePrimary {
		fmt.Printf("Successfully set as primary identity for account: %s\n", *email)
	}
}

func updateAccount(cfg AdminConfig, email, password string, makePrimary bool, hashType string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Update account using the new db operation
	req := db.UpdateAccountRequest{
		Email:       email,
		Password:    password,
		HashType:    hashType,
		MakePrimary: makePrimary,
	}

	if err := database.UpdateAccount(ctx, req); err != nil {
		return err
	}

	return nil
}

func handleListCredentials() {
	// Parse list-credentials specific flags
	fs := flag.NewFlagSet("list-credentials", flag.ExitOnError)

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

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// List the credentials
	if err := listCredentials(cfg, *email); err != nil {
		log.Fatalf("Failed to list credentials: %v", err)
	}
}

func listCredentials(cfg AdminConfig, email string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// List credentials using the new db operation
	credentials, err := database.ListCredentials(ctx, email)
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

func handleImportMaildir() {
	// Parse import-maildir specific flags
	fs := flag.NewFlagSet("import-maildir", flag.ExitOnError)

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
	dovecot := fs.Bool("dovecot", false, "Process Dovecot-specific files (subscriptions, dovecot-keywords)")
	sievePath := fs.String("sieve", "", "Path to Sieve script file to import for the user")
	preserveUIDs := fs.Bool("preserve-uids", false, "Preserve original UIDs from dovecot-uidlist files")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to import (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Import only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Import only messages before this date (YYYY-MM-DD)")

	fs.Usage = func() {
		fmt.Printf(`Import maildir from a given path

Usage:
  sora-admin import-maildir [options]

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
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/example.com/user/Maildir

  # Dry run to preview (note: correct maildir path)
  sora-admin import-maildir --email user@example.com --maildir-path /home/user/Maildir --dry-run

  # Import only INBOX and Sent folders
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --mailbox-filter INBOX,Sent

  # Import messages from 2023
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --start-date 2023-01-01 --end-date 2023-12-31

  # Import with cleanup (removes SQLite database after completion)
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --cleanup-db

  # Import from Dovecot with subscriptions and custom keywords
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --dovecot

  # Import with Sieve script
  sora-admin import-maildir --email user@example.com --maildir-path /var/vmail/user/Maildir --sieve /path/to/user.sieve
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Connect to database
	database, err := db.NewDatabaseFromConfig(context.Background(), &cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Connect to S3
	s3, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.Trace)
	if err != nil {
		log.Fatalf("Failed to connect to S3: %v", err)
	}
	if cfg.S3.Encrypt {
		if err := s3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			log.Fatalf("Failed to enable S3 encryption: %v", err)
		}
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
	}

	importer, err := NewImporter(*maildirPath, *email, *jobs, database, s3, options)
	if err != nil {
		log.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		log.Fatalf("Failed to import maildir: %v", err)
	}
}

func handleExportMaildir() {
	// Parse export-maildir specific flags
	fs := flag.NewFlagSet("export-maildir", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	email := fs.String("email", "", "Email address for the account to export mail from (required)")
	maildirPath := fs.String("maildir-path", "", "Path where the maildir will be created/updated (required)")
	jobs := fs.Int("jobs", 4, "Number of parallel export jobs")
	dryRun := fs.Bool("dry-run", false, "Preview what would be exported without making changes")
	showProgress := fs.Bool("progress", true, "Show export progress")
	delay := fs.Duration("delay", 0, "Delay between operations to control rate (e.g. 500ms)")
	dovecot := fs.Bool("dovecot", false, "Export Dovecot-specific files (subscriptions)")
	exportUIDList := fs.Bool("export-dovecot-uidlist", false, "Export dovecot-uidlist files with UID mappings")
	overwriteFlags := fs.Bool("overwrite-flags", false, "Update flags on existing messages")
	mailboxFilter := fs.String("mailbox-filter", "", "Comma-separated list of mailboxes to export (e.g. INBOX,Sent)")
	startDate := fs.String("start-date", "", "Export only messages after this date (YYYY-MM-DD)")
	endDate := fs.String("end-date", "", "Export only messages before this date (YYYY-MM-DD)")

	fs.Usage = func() {
		fmt.Printf(`Export messages to maildir format

Usage:
  sora-admin export-maildir [options]

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
  sora-admin export-maildir --email user@example.com --maildir-path /var/backup/user/Maildir

  # Export only INBOX and Sent folders
  sora-admin export-maildir --email user@example.com --maildir-path /backup/maildir --mailbox-filter INBOX,Sent

  # Export with Dovecot metadata (includes dovecot-uidlist files)
  sora-admin export-maildir --email user@example.com --maildir-path /backup/maildir --dovecot
  
  # Export with only dovecot-uidlist files (no subscriptions)
  sora-admin export-maildir --email user@example.com --maildir-path /backup/maildir --export-dovecot-uidlist

  # Update flags on existing messages
  sora-admin export-maildir --email user@example.com --maildir-path /existing/maildir --overwrite-flags
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Connect to database
	database, err := db.NewDatabaseFromConfig(context.Background(), &cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	// Connect to S3
	s3, err := storage.New(cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, !cfg.S3.DisableTLS, cfg.S3.Trace)
	if err != nil {
		log.Fatalf("Failed to connect to S3: %v", err)
	}
	if cfg.S3.Encrypt {
		if err := s3.EnableEncryption(cfg.S3.EncryptionKey); err != nil {
			log.Fatalf("Failed to enable S3 encryption: %v", err)
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

	exporter, err := NewExporter(*maildirPath, *email, *jobs, database, s3, options)
	if err != nil {
		log.Fatalf("Failed to create exporter: %v", err)
	}

	if err := exporter.Run(); err != nil {
		log.Fatalf("Failed to export maildir: %v", err)
	}
}

func handleCacheStats() {
	// Parse cache-stats specific flags
	fs := flag.NewFlagSet("cache-stats", flag.ExitOnError)

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

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show cache stats
	if err := showCacheStats(cfg); err != nil {
		log.Fatalf("Failed to show cache stats: %v", err)
	}
}

func handleCachePurge() {
	// Parse cache-purge specific flags
	fs := flag.NewFlagSet("cache-purge", flag.ExitOnError)

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

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Purge cache
	if err := purgeCacheWithConfirmation(cfg, *confirm); err != nil {
		log.Fatalf("Failed to purge cache: %v", err)
	}
}

func showCacheStats(cfg AdminConfig) error {
	// Parse cache configuration
	capacityBytes, err := helpers.ParseSize(cfg.LocalCache.Capacity)
	if err != nil {
		return fmt.Errorf("failed to parse cache capacity '%s': %w", cfg.LocalCache.Capacity, err)
	}

	maxObjectSizeBytes, err := helpers.ParseSize(cfg.LocalCache.MaxObjectSize)
	if err != nil {
		return fmt.Errorf("failed to parse max object size '%s': %w", cfg.LocalCache.MaxObjectSize, err)
	}

	// Connect to minimal database instance for cache initialization
	ctx := context.Background()
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, database)
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

func purgeCacheWithConfirmation(cfg AdminConfig, autoConfirm bool) error {
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

	// Parse cache configuration
	capacityBytes, err := helpers.ParseSize(cfg.LocalCache.Capacity)
	if err != nil {
		return fmt.Errorf("failed to parse cache capacity '%s': %w", cfg.LocalCache.Capacity, err)
	}

	maxObjectSizeBytes, err := helpers.ParseSize(cfg.LocalCache.MaxObjectSize)
	if err != nil {
		return fmt.Errorf("failed to parse max object size '%s': %w", cfg.LocalCache.MaxObjectSize, err)
	}

	// Connect to minimal database instance for cache initialization
	ctx := context.Background()
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Initialize cache
	cacheInstance, err := cache.New(cfg.LocalCache.Path, capacityBytes, maxObjectSizeBytes, database)
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

func handleUploaderStatus() {
	// Parse uploader-status specific flags
	fs := flag.NewFlagSet("uploader-status", flag.ExitOnError)

	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	showFailed := fs.Bool("show-failed", true, "Show failed uploads details")
	failedLimit := fs.Int("failed-limit", 10, "Maximum number of failed uploads to show")

	fs.Usage = func() {
		fmt.Printf(`Show uploader queue status and failed uploads

Usage:
  sora-admin uploader-status [options]

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
  sora-admin uploader-status
  sora-admin uploader-status --config /path/to/config.toml
  sora-admin uploader-status --failed-limit 20
  sora-admin uploader-status --show-failed=false
`)
	}

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show uploader status
	if err := showUploaderStatus(cfg, *showFailed, *failedLimit); err != nil {
		log.Fatalf("Failed to show uploader status: %v", err)
	}
}

func showUploaderStatus(cfg AdminConfig, showFailed bool, failedLimit int) error {
	// Connect to database
	ctx := context.Background()
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Validate retry interval parsing (for config validation)
	_, err = helpers.ParseDuration(cfg.Uploader.RetryInterval)
	if err != nil {
		return fmt.Errorf("failed to parse retry interval '%s': %w", cfg.Uploader.RetryInterval, err)
	}

	// Get uploader statistics
	stats, err := database.GetUploaderStats(ctx, cfg.Uploader.MaxAttempts)
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

		failedUploads, err := database.GetFailedUploads(ctx, cfg.Uploader.MaxAttempts, failedLimit)
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

func handleConnectionStats() {
	// Parse connection-stats specific flags
	fs := flag.NewFlagSet("connection-stats", flag.ExitOnError)

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

	// Parse the remaining arguments (skip the command name)
	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
	}

	// Load configuration
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			if isFlagSet(fs, "config") {
				log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
			} else {
				log.Printf("WARNING: default configuration file '%s' not found. Using defaults and command-line flags.", *configPath)
			}
		} else {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	}

	// Show connection statistics
	if err := showConnectionStats(cfg, *userEmail, *server, *cleanupStale, *staleMinutes, *showDetail); err != nil {
		log.Fatalf("Failed to show connection stats: %v", err)
	}
}

func showConnectionStats(cfg AdminConfig, userEmail, serverFilter string, cleanupStale bool, staleMinutes int, showDetail bool) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	// Cleanup stale connections if requested
	if cleanupStale {
		staleDuration := time.Duration(staleMinutes) * time.Minute
		removed, err := database.CleanupStaleConnections(ctx, staleDuration)
		if err != nil {
			return fmt.Errorf("failed to cleanup stale connections: %w", err)
		}
		fmt.Printf("Cleaned up %d stale connections (no activity for %d minutes)\n\n", removed, staleMinutes)
	}

	// Get connection statistics
	var stats *db.ConnectionStats
	if userEmail != "" {
		// Get connections for specific user
		connections, err := database.GetUserConnections(ctx, userEmail)
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
		stats, err = database.GetConnectionStats(ctx)
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

func handleAuthStats() {
	// Parse auth-stats specific flags
	fs := flag.NewFlagSet("auth-stats", flag.ExitOnError)
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
		log.Fatalf("Failed to parse flags: %v", err)
	}

	// Parse window duration
	window, err := time.ParseDuration(*windowDuration)
	if err != nil {
		log.Fatalf("Invalid window duration '%s': %v", *windowDuration, err)
	}

	// Load configuration
	var adminConfig AdminConfig
	if _, err := toml.DecodeFile(*configPath, &adminConfig); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Create context for database operations
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabaseFromConfig(ctx, &adminConfig.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	fmt.Printf("Authentication Statistics and Blocked IPs\n")
	fmt.Printf("Window: %s\n", window)
	fmt.Printf("Generated at: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Show general auth statistics
	if *showStats {
		stats, err := database.GetAuthAttemptsStats(ctx, window)
		if err != nil {
			log.Printf("Failed to get auth statistics: %v", err)
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
		blocked, err := database.GetBlockedIPs(ctx, window, window, *maxAttemptsIP, *maxAttemptsUsername)
		if err != nil {
			log.Printf("Failed to get blocked IPs: %v", err)
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

func handleHealthStatus() {
	fs := flag.NewFlagSet("health-status", flag.ExitOnError)

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
  sora-admin health-status [options]

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
  sora-admin health-status
  sora-admin health-status --hostname server1.example.com
  sora-admin health-status --component database --detailed
  sora-admin health-status --history --since 24h
  sora-admin health-status --json
`)
	}

	// Parse command arguments (skip program name and command name)
	args := os.Args[2:]
	if err := fs.Parse(args); err != nil {
		log.Fatalf("Error parsing flags: %v", err)
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
					log.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
				}
			} else {
				// The original parse failed and it's not a 'd' unit we can handle.
				log.Fatalf("Invalid time format for --since '%s'. Use a duration string like '1h', '24h', or '7d'.", *since)
			}
		}
		sinceTime = time.Now().Add(-duration)
	}

	// Load configuration
	cfg := AdminConfig{}
	if _, err := os.Stat(*configPath); err == nil {
		if _, err := toml.DecodeFile(*configPath, &cfg); err != nil {
			log.Fatalf("FATAL: error parsing configuration file '%s': %v", *configPath, err)
		}
	} else {
		if isFlagSet(fs, "config") {
			log.Fatalf("ERROR: specified configuration file '%s' not found: %v", *configPath, err)
		} else {
			log.Printf("WARNING: default configuration file '%s' not found. Using defaults.", *configPath)
		}
	}

	// Connect to database
	ctx := context.Background()
	database, err := db.NewDatabaseFromConfig(ctx, &cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()

	if *jsonOutput {
		if err := showHealthStatusJSON(ctx, database, *hostname, *component, *detailed, *history, sinceTime); err != nil {
			log.Fatalf("Failed to show health status: %v", err)
		}
	} else {
		if err := showHealthStatus(ctx, database, *hostname, *component, *detailed, *history, sinceTime); err != nil {
			log.Fatalf("Failed to show health status: %v", err)
		}
	}
}

func showHealthStatus(ctx context.Context, database *db.Database, hostname, component string, detailed, history bool, sinceTime time.Time) error {
	if history && component != "" {
		return showComponentHistory(ctx, database, hostname, component, sinceTime)
	}

	// Show overview first
	overview, err := database.GetSystemHealthOverview(ctx, hostname)
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
	statuses, err := database.GetAllHealthStatuses(ctx, hostname)
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

func showComponentHistory(ctx context.Context, database *db.Database, hostname, component string, sinceTime time.Time) error {
	if hostname == "" {
		// Get all hostnames for this component
		allStatuses, err := database.GetAllHealthStatuses(ctx, "")
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

			history, err := database.GetHealthHistory(ctx, hn, component, sinceTime, 50)
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

		history, err := database.GetHealthHistory(ctx, hostname, component, sinceTime, 50)
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

func showHealthStatusJSON(ctx context.Context, database *db.Database, hostname, component string, detailed, history bool, sinceTime time.Time) error {
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
	overview, err := database.GetSystemHealthOverview(ctx, hostname)
	if err != nil {
		return fmt.Errorf("failed to get system health overview: %w", err)
	}
	output.Overview = overview

	if history && component != "" {
		// Get history for specific component
		if hostname == "" {
			// Get all hostnames for this component first
			allStatuses, err := database.GetAllHealthStatuses(ctx, "")
			if err != nil {
				return fmt.Errorf("failed to get health statuses: %w", err)
			}

			for _, status := range allStatuses {
				if status.ComponentName == component {
					hist, err := database.GetHealthHistory(ctx, status.ServerHostname, component, sinceTime, 50)
					if err != nil {
						continue
					}
					output.History = append(output.History, hist...)
				}
			}
		} else {
			hist, err := database.GetHealthHistory(ctx, hostname, component, sinceTime, 50)
			if err != nil {
				return fmt.Errorf("failed to get health history: %w", err)
			}
			output.History = hist
		}
	} else {
		// Get current component status
		statuses, err := database.GetAllHealthStatuses(ctx, hostname)
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
