package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/storage"
)

// AdminConfig holds minimal configuration needed for admin operations
type AdminConfig struct {
	Database DatabaseConfig `toml:"database"`
	S3       S3Config       `toml:"s3"`
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

// DatabaseConfig holds database configuration - copied from main config
type DatabaseConfig struct {
	Host       string `toml:"host"`
	Port       string `toml:"port"`
	User       string `toml:"user"`
	Password   string `toml:"password"`
	Name       string `toml:"name"`
	TLSMode    bool   `toml:"tls"`
	LogQueries bool   `toml:"log_queries"`
}

func newDefaultAdminConfig() AdminConfig {
	return AdminConfig{
		Database: DatabaseConfig{
			Host:       "localhost",
			Port:       "5432",
			User:       "postgres",
			Password:   "",
			Name:       "sora_mail_db",
			TLSMode:    false,
			LogQueries: false,
		},
		S3: S3Config{
			Endpoint:      "",
			AccessKey:     "",
			SecretKey:     "",
			Bucket:        "",
			Encrypt:       false,
			EncryptionKey: "",
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
  help              Show this help message

Examples:
  sora-admin create-account --email user@example.com --password mypassword
  sora-admin add-credential --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin update-account --email user@example.com --password newpassword
  sora-admin list-credentials --email user@example.com
  sora-admin create-account --config /path/to/config.toml --email user@example.com --password mypassword

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

	// Database connection flags (overrides from config file)
	dbHost := fs.String("dbhost", "", "Database host (overrides config)")
	dbPort := fs.String("dbport", "", "Database port (overrides config)")
	dbUser := fs.String("dbuser", "", "Database user (overrides config)")
	dbPassword := fs.String("dbpassword", "", "Database password (overrides config)")
	dbName := fs.String("dbname", "", "Database name (overrides config)")
	dbTLS := fs.Bool("dbtls", false, "Enable TLS for database connection (overrides config)")

	fs.Usage = func() {
		fmt.Printf(`Create a new account

Usage:
  sora-admin create-account [options]

Options:
  --email string       Email address for the new account (required)
  --password string    Password for the new account (required)
  --hash string        Password hash type: bcrypt, ssha512, sha512 (default: bcrypt)
  --config string      Path to TOML configuration file (default: config.toml)
  
Database Options:
  --dbhost string      Database host (overrides config)
  --dbport string      Database port (overrides config)
  --dbuser string      Database user (overrides config)
  --dbpassword string  Database password (overrides config)
  --dbname string      Database name (overrides config)
  --dbtls              Enable TLS for database connection (overrides config)

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

	// Apply command-line flag overrides
	if isFlagSet(fs, "dbhost") {
		cfg.Database.Host = *dbHost
	}
	if isFlagSet(fs, "dbport") {
		cfg.Database.Port = *dbPort
	}
	if isFlagSet(fs, "dbuser") {
		cfg.Database.User = *dbUser
	}
	if isFlagSet(fs, "dbpassword") {
		cfg.Database.Password = *dbPassword
	}
	if isFlagSet(fs, "dbname") {
		cfg.Database.Name = *dbName
	}
	if isFlagSet(fs, "dbtls") {
		cfg.Database.TLSMode = *dbTLS
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
	dbHost := fs.String("dbhost", "", "Database host (overrides config)")
	dbPort := fs.String("dbport", "", "Database port (overrides config)")
	dbUser := fs.String("dbuser", "", "Database user (overrides config)")
	dbPassword := fs.String("dbpassword", "", "Database password (overrides config)")
	dbName := fs.String("dbname", "", "Database name (overrides config)")
	dbTLS := fs.Bool("dbtls", false, "Enable TLS for database connection (overrides config)")

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
  
Database Options:
  --dbhost string       Database host (overrides config)
  --dbport string       Database port (overrides config)
  --dbuser string       Database user (overrides config)
  --dbpassword string   Database password (overrides config)
  --dbname string       Database name (overrides config)
  --dbtls               Enable TLS for database connection (overrides config)

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

	// Apply command-line flag overrides
	if isFlagSet(fs, "dbhost") {
		cfg.Database.Host = *dbHost
	}
	if isFlagSet(fs, "dbport") {
		cfg.Database.Port = *dbPort
	}
	if isFlagSet(fs, "dbuser") {
		cfg.Database.User = *dbUser
	}
	if isFlagSet(fs, "dbpassword") {
		cfg.Database.Password = *dbPassword
	}
	if isFlagSet(fs, "dbname") {
		cfg.Database.Name = *dbName
	}
	if isFlagSet(fs, "dbtls") {
		cfg.Database.TLSMode = *dbTLS
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
	database, err := db.NewDatabase(ctx,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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

func addCredential(cfg AdminConfig, primaryIdentity, email, password string, makePrimary bool, hashType string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabase(ctx,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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
	dbHost := fs.String("dbhost", "", "Database host (overrides config)")
	dbPort := fs.String("dbport", "", "Database port (overrides config)")
	dbUser := fs.String("dbuser", "", "Database user (overrides config)")
	dbPassword := fs.String("dbpassword", "", "Database password (overrides config)")
	dbName := fs.String("dbname", "", "Database name (overrides config)")
	dbTLS := fs.Bool("dbtls", false, "Enable TLS for database connection (overrides config)")

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
  
Database Options:
  --dbhost string      Database host (overrides config)
  --dbport string      Database port (overrides config)
  --dbuser string      Database user (overrides config)
  --dbpassword string  Database password (overrides config)
  --dbname string      Database name (overrides config)
  --dbtls              Enable TLS for database connection (overrides config)

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

	// Apply command-line flag overrides
	if isFlagSet(fs, "dbhost") {
		cfg.Database.Host = *dbHost
	}
	if isFlagSet(fs, "dbport") {
		cfg.Database.Port = *dbPort
	}
	if isFlagSet(fs, "dbuser") {
		cfg.Database.User = *dbUser
	}
	if isFlagSet(fs, "dbpassword") {
		cfg.Database.Password = *dbPassword
	}
	if isFlagSet(fs, "dbname") {
		cfg.Database.Name = *dbName
	}
	if isFlagSet(fs, "dbtls") {
		cfg.Database.TLSMode = *dbTLS
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
	database, err := db.NewDatabase(ctx,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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
	dbHost := fs.String("dbhost", "", "Database host (overrides config)")
	dbPort := fs.String("dbport", "", "Database port (overrides config)")
	dbUser := fs.String("dbuser", "", "Database user (overrides config)")
	dbPassword := fs.String("dbpassword", "", "Database password (overrides config)")
	dbName := fs.String("dbname", "", "Database name (overrides config)")
	dbTLS := fs.Bool("dbtls", false, "Enable TLS for database connection (overrides config)")

	fs.Usage = func() {
		fmt.Printf(`List all credentials for an account

Usage:
  sora-admin list-credentials [options]

Options:
  --email string       Email address associated with the account (required)
  --config string      Path to TOML configuration file (default: config.toml)
  
Database Options:
  --dbhost string      Database host (overrides config)
  --dbport string      Database port (overrides config)
  --dbuser string      Database user (overrides config)
  --dbpassword string  Database password (overrides config)
  --dbname string      Database name (overrides config)
  --dbtls              Enable TLS for database connection (overrides config)

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

	// Apply command-line flag overrides
	if isFlagSet(fs, "dbhost") {
		cfg.Database.Host = *dbHost
	}
	if isFlagSet(fs, "dbport") {
		cfg.Database.Port = *dbPort
	}
	if isFlagSet(fs, "dbuser") {
		cfg.Database.User = *dbUser
	}
	if isFlagSet(fs, "dbpassword") {
		cfg.Database.Password = *dbPassword
	}
	if isFlagSet(fs, "dbname") {
		cfg.Database.Name = *dbName
	}
	if isFlagSet(fs, "dbtls") {
		cfg.Database.TLSMode = *dbTLS
	}

	// List the credentials
	if err := listCredentials(cfg, *email); err != nil {
		log.Fatalf("Failed to list credentials: %v", err)
	}
}

func listCredentials(cfg AdminConfig, email string) error {
	ctx := context.Background()

	// Connect to database
	database, err := db.NewDatabase(ctx,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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
	importDelay := fs.Duration("import-delay", 0, "Delay between imports to control rate (e.g. 500ms)")
	forceReimport := fs.Bool("force-reimport", false, "Force reimport of messages even if they already exist")
	cleanupDB := fs.Bool("cleanup-db", false, "Remove the SQLite import database after successful import")
	dovecot := fs.Bool("dovecot", false, "Process Dovecot-specific files (subscriptions, dovecot-keywords)")
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
  --force-reimport        Force reimport of messages even if they already exist
  --cleanup-db            Remove the SQLite import database after successful import
  --dovecot               Process Dovecot-specific files (subscriptions, dovecot-keywords)
  --mailbox-filter string Comma-separated list of mailboxes to import (e.g. INBOX,Sent,Archive*)
  --start-date string     Import only messages after this date (YYYY-MM-DD)
  --end-date string       Import only messages before this date (YYYY-MM-DD)
  --config string         Path to TOML configuration file (default: config.toml)

IMPORTANT: --maildir-path must point to a maildir root directory (containing cur/, new/, tmp/ subdirectories),
not to a parent directory containing multiple maildirs.

Use --dovecot flag to process Dovecot-specific 'subscriptions' and 'dovecot-keywords' files,
which will create missing mailboxes, subscribe the user to specified folders, and preserve
custom IMAP keywords/flags on imported messages.

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
	database, err := db.NewDatabase(context.Background(),
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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
		ImportDelay:   *importDelay,
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
	exportDelay := fs.Duration("export-delay", 0, "Delay between exports to control rate (e.g. 500ms)")
	dovecot := fs.Bool("dovecot", false, "Export Dovecot-specific files (subscriptions)")
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
  --dovecot               Export Dovecot-specific files (subscriptions)
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

  # Export with Dovecot metadata
  sora-admin export-maildir --email user@example.com --maildir-path /backup/maildir --dovecot

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
	database, err := db.NewDatabase(context.Background(),
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Name,
		cfg.Database.TLSMode,
		cfg.Database.LogQueries)
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

	// Create exporter options
	options := ExporterOptions{
		DryRun:         *dryRun,
		StartDate:      startDateParsed,
		EndDate:        endDateParsed,
		MailboxFilter:  mailboxList,
		ShowProgress:   *showProgress,
		Dovecot:        *dovecot,
		OverwriteFlags: *overwriteFlags,
		ExportDelay:    *exportDelay,
	}

	exporter, err := NewExporter(*maildirPath, *email, *jobs, database, s3, options)
	if err != nil {
		log.Fatalf("Failed to create exporter: %v", err)
	}

	if err := exporter.Run(); err != nil {
		log.Fatalf("Failed to export maildir: %v", err)
	}
}
