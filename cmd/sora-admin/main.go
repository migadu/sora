package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/logger"
)

// Version information, injected at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Global config loaded once at startup
var globalConfig AdminConfig

// AdminConfig holds minimal configuration needed for admin operations
type AdminConfig struct {
	Database                  config.DatabaseConfig        `toml:"database"`
	S3                        config.S3Config              `toml:"s3"`
	LocalCache                config.LocalCacheConfig      `toml:"local_cache"`
	Uploader                  config.UploaderConfig        `toml:"uploader"`
	Cleanup                   config.CleanupConfig         `toml:"cleanup"`
	SharedMailboxes           config.SharedMailboxesConfig `toml:"shared_mailboxes"`
	DynamicServers            []config.ServerConfig        // Populated from full config
	Server                    []map[string]any             `toml:"server"`                        // Ignore server config array, not needed for admin commands
	HTTPAPIAddr               string                       `toml:"http_api_addr"`                 // HTTP API address for kick operations (e.g., "http://localhost:8080")
	HTTPAPIKey                string                       `toml:"http_api_key"`                  // HTTP API key for authentication
	HTTPAPIInsecureSkipVerify bool                         `toml:"http_api_insecure_skip_verify"` // Skip TLS certificate verification (default: true for localhost)
}

// createHTTPAPIClient creates an HTTP client for calling the HTTP API
func createHTTPAPIClient(cfg AdminConfig) (*http.Client, error) {
	if cfg.HTTPAPIAddr == "" {
		return nil, fmt.Errorf("http_api_addr not configured (required for kick operations)")
	}
	if cfg.HTTPAPIKey == "" {
		return nil, fmt.Errorf("http_api_key not configured (required for kick operations)")
	}

	// Create custom transport with optional TLS verification skip
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.HTTPAPIInsecureSkipVerify,
		},
	}

	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, nil
}

// loadAdminConfig loads admin configuration from a TOML file with the same safety features as LoadConfigFromFile
// This provides: duplicate key handling, unknown key warnings, enhanced error messages, and whitespace trimming
func loadAdminConfig(configPath string, cfg *AdminConfig) error {
	// Use the full config loader from the config package for consistency
	fullCfg := &config.Config{}
	if err := config.LoadConfigFromFile(configPath, fullCfg); err != nil {
		return err
	}

	// Extract the parts we need for admin operations
	cfg.Database = fullCfg.Database
	cfg.S3 = fullCfg.S3
	cfg.LocalCache = fullCfg.LocalCache
	cfg.Uploader = fullCfg.Uploader
	cfg.Cleanup = fullCfg.Cleanup
	cfg.SharedMailboxes = fullCfg.SharedMailboxes
	cfg.DynamicServers = fullCfg.DynamicServers
	cfg.HTTPAPIAddr = fullCfg.AdminCLI.Addr
	cfg.HTTPAPIKey = fullCfg.AdminCLI.APIKey

	// Default to true for insecure skip verify (safer for localhost usage)
	cfg.HTTPAPIInsecureSkipVerify = true
	if fullCfg.AdminCLI.InsecureSkipVerify != nil {
		cfg.HTTPAPIInsecureSkipVerify = *fullCfg.AdminCLI.InsecureSkipVerify
	}

	return nil
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

	// Allow 'sora-admin help' and 'sora-admin version' without config
	if os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printUsage()
		os.Exit(0)
	}
	if os.Args[1] == "version" {
		printVersion()
		os.Exit(0)
	}

	// Determine the command first
	command := ""
	for i := 1; i < len(os.Args); i++ {
		if !strings.HasPrefix(os.Args[i], "-") {
			command = os.Args[i]
			break
		}
		// Skip --config and its value when looking for command
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			i++ // Skip the value
		}
	}

	if command == "" {
		printUsage()
		os.Exit(1)
	}

	// Special handling for 'config' subcommands - they parse their own --config flag
	if command == "config" {
		handleConfigCommand(ctx)
		return
	}

	// For all other commands, parse and remove the global --config flag
	configPath := ""
	newArgs := []string{os.Args[0]} // Keep program name

	for i := 1; i < len(os.Args); i++ {
		if os.Args[i] == "--config" && i+1 < len(os.Args) {
			configPath = os.Args[i+1]
			i++ // Skip the config path value
		} else {
			newArgs = append(newArgs, os.Args[i])
		}
	}

	if configPath == "" {
		logger.Fatalf("ERROR: --config flag is required")
	}

	if err := loadAdminConfig(configPath, &globalConfig); err != nil {
		logger.Fatalf("Failed to load configuration file '%s': %v", configPath, err)
	}

	// Replace os.Args with filtered args (without --config)
	os.Args = newArgs

	switch command {
	case "accounts":
		handleAccountsCommand(ctx)
	case "acl":
		handleACLCommand(ctx)
	case "credentials":
		handleCredentialsCommand(ctx)
	case "mailbox":
		handleMailboxCommand(ctx)
	case "cache":
		handleCacheCommand(ctx)
	case "stats":
		handleStatsCommand(ctx)
	case "connections":
		handleConnectionsCommand(ctx)
	case "affinity":
		handleAffinityCommand(ctx)
	case "health":
		handleHealthCommand(ctx)
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
	case "relay":
		handleRelayCommand(ctx)
	case "verify":
		handleVerifyCommand(ctx)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("sora-admin version %s (commit: %s, built at: %s)\n", version, commit, date)
}

func printUsage() {
	fmt.Printf(`SORA Admin Tool

Usage:
  sora-admin --config PATH <command> <subcommand> [options]

Global Options:
  --config PATH    Path to configuration file (required for most commands)

Commands:
  accounts      Manage user accounts
  acl           Manage mailbox ACL (Access Control Lists)
  credentials   Manage account credentials
  mailbox       Manage mailboxes (create, delete, rename, subscribe)
  cache         Cache management operations
  stats         System statistics and analytics
  connections   Connection management
  affinity      User-to-backend affinity management
  health        System health status
  config        Configuration management
  migrate       Database schema migration management
  uploader      Upload queue management
  messages      List and restore deleted messages
  relay         Relay queue management (stats, list, show, delete, requeue)
  verify        Verify data integrity (S3 storage, etc.)
  import        Import maildir data
  export        Export maildir data
  version       Show version information
  help          Show this help message

Examples:
  sora-admin --config config.toml accounts create --email user@example.com --password mypassword
  sora-admin --config config.toml accounts list
  sora-admin --config config.toml credentials add --primary admin@example.com --email alias@example.com --password mypassword
  sora-admin --config config.toml credentials list --email user@example.com
  sora-admin --config config.toml cache stats
  sora-admin --config config.toml stats auth --window 1h
  sora-admin --config config.toml connections kick --user user@example.com
  sora-admin --config config.toml affinity set --user user@example.com --protocol imap --backend 192.168.1.10:993
  sora-admin --config config.toml config validate

Use 'sora-admin --config PATH <command> --help' for more information about a command group.
Use 'sora-admin --config PATH <command> <subcommand> --help' for detailed help on specific commands.
`)
}

// CredentialInput represents a credential input from JSON
type CredentialInput struct {
	Email        string `json:"email"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	IsPrimary    bool   `json:"is_primary"`
	HashType     string `json:"hash_type,omitempty"`
}

// Helper function to check if a flag was explicitly set

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Affinity Management Functions

// Affinity Management Functions (via HTTP Admin API)

// callAdminAPI makes an HTTP request to the admin API server
