package testutils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// TestConfig represents minimal test configuration
type TestConfig struct {
	Database struct {
		Write struct {
			Hosts    []string `toml:"hosts"`
			Port     int      `toml:"port"`
			User     string   `toml:"user"`
			Password string   `toml:"password"`
			Name     string   `toml:"name"`
			TLS      bool     `toml:"tls"`
		} `toml:"write"`
	} `toml:"database"`
}

// TestDatabase wraps database functionality for testing
type TestDatabase struct {
	*db.Database
	Config *TestConfig
}

// SetupTestDatabase creates a database connection using local PostgreSQL and config-test.toml
func SetupTestDatabase(t *testing.T) *TestDatabase {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()

	// Find the config-test.toml file by walking up from current directory
	configPath, err := findTestConfig()
	require.NoError(t, err, "config-test.toml not found. Please ensure it exists in the project root")

	// Load test configuration
	var cfg TestConfig
	_, err = toml.DecodeFile(configPath, &cfg)
	require.NoError(t, err, "Failed to load test config. Please check config-test.toml syntax")

	// Create database connection using test config
	host := "localhost"
	if len(cfg.Database.Write.Hosts) > 0 {
		host = cfg.Database.Write.Hosts[0]
	}
	port := "5432"
	if cfg.Database.Write.Port != 0 {
		port = fmt.Sprintf("%d", cfg.Database.Write.Port)
	}

	database, err := db.NewDatabase(ctx, host, port, cfg.Database.Write.User, cfg.Database.Write.Password, cfg.Database.Write.Name, cfg.Database.Write.TLS, false)
	require.NoError(t, err, "Failed to connect to test database. Please ensure PostgreSQL is running and %s database exists", cfg.Database.Write.Name)

	// Verify pg_trgm extension is available
	var extensionExists bool
	err = database.GetReadPool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')").Scan(&extensionExists)
	require.NoError(t, err)
	if !extensionExists {
		// Try to create the extension
		_, err = database.GetWritePool().Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm")
		if err != nil {
			t.Fatalf("pg_trgm extension is required but not available. Please run: psql %s -c 'CREATE EXTENSION pg_trgm;'", cfg.Database.Write.Name)
		}
	}

	return &TestDatabase{
		Database: database,
		Config:   &cfg,
	}
}

// findTestConfig walks up the directory tree to find config-test.toml
func findTestConfig() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		configPath := filepath.Join(dir, "config-test.toml")
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("config-test.toml not found in current directory or any parent directory")
}

// Cleanup closes database connections and cleans up test data
func (td *TestDatabase) Cleanup(t *testing.T) {
	// Close database connections
	if td.Database != nil {
		td.Database.Close()
	}
}

// CreateTestAccount creates a test account for testing purposes
func (td *TestDatabase) CreateTestAccount(t *testing.T, email, password string) int64 {
	ctx := context.Background()

	tx, err := td.Database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		IsPrimary: true,
		HashType:  "bcrypt",
	}

	err = td.Database.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get the created account ID
	accountID, err := td.Database.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)

	return accountID
}

// CreateTestMailbox creates a test mailbox for testing purposes
func (td *TestDatabase) CreateTestMailbox(t *testing.T, accountID int64, name string) {
	ctx := context.Background()

	tx, err := td.Database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = td.Database.CreateMailbox(ctx, tx, accountID, name, nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)
}

// TruncateAllTables cleans all data from test database tables
func (td *TestDatabase) TruncateAllTables(t *testing.T) {
	ctx := context.Background()

	// List of tables to truncate in dependency order
	tables := []string{
		"messages",
		"s3_upload_queue",
		"mailboxes",
		"credentials",
		"accounts",
		"active_connections",
		"sieve_scripts",
		"vacation_responses",
	}

	for _, table := range tables {
		_, err := td.Database.GetWritePool().Exec(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		require.NoError(t, err)
	}
}
