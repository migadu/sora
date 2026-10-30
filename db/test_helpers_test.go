package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/migadu/sora/config"
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

// setupTestDatabase creates a database connection using local PostgreSQL and config-test.toml
func setupTestDatabase(t testing.TB) *Database {
	return setupTestDatabaseWithSuffix(t, "")
}

// setupTestDatabaseWithSuffix connects like setupTestDatabase, but to the database
// named after the configured one plus suffix, creating it if it does not exist yet.
// It is for tests that empty whole tables: the configured database is shared with
// every other test package, and go test runs packages at the same time.
func setupTestDatabaseWithSuffix(t testing.TB, suffix string) *Database {
	ctx := context.Background()

	// Find the config-test.toml file by walking up from current directory
	configPath, err := findTestConfig()
	require.NoError(t, err, "config-test.toml not found. Please ensure it exists in the project root")

	// Load test configuration
	var cfg TestConfig
	_, err = toml.DecodeFile(configPath, &cfg)
	require.NoError(t, err, "Failed to load test config. Please check config-test.toml syntax")
	// SORA_TEST_DB_NAME overrides the database, as it does for the other test packages,
	// so a branch whose migrations differ from main can run against its own database
	// instead of migrating the shared one.
	if name := os.Getenv("SORA_TEST_DB_NAME"); name != "" {
		cfg.Database.Write.Name = name
	}
	cfg.Database.Write.Name += suffix

	// Create database connection using test config
	// Convert test config to DatabaseConfig format
	dbConfig := &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts:    cfg.Database.Write.Hosts,
			Port:     cfg.Database.Write.Port,
			User:     cfg.Database.Write.User,
			Password: cfg.Database.Write.Password,
			Name:     cfg.Database.Write.Name,
			TLSMode:  cfg.Database.Write.TLS,
		},
	}
	if suffix != "" {
		createTestDatabaseIfMissing(t, dbConfig.Write)
	}

	database, err := NewDatabaseFromConfig(ctx, dbConfig, true)
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

	return database
}

// createTestDatabaseIfMissing creates endpoint's database, connecting to the
// postgres maintenance database on the same server with the same credentials.
func createTestDatabaseIfMissing(t testing.TB, endpoint *config.DatabaseEndpointConfig) {
	ctx := context.Background()
	maintenance := *endpoint
	maintenance.Name = "postgres"
	admin, err := NewDatabaseFromConfig(ctx, &config.DatabaseConfig{Write: &maintenance}, false)
	require.NoError(t, err, "Failed to connect to the postgres database to create %s", endpoint.Name)
	defer admin.Close()

	var exists bool
	err = admin.GetWritePool().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", endpoint.Name).Scan(&exists)
	require.NoError(t, err)
	if exists {
		return
	}
	_, err = admin.GetWritePool().Exec(ctx, "CREATE DATABASE "+pgx.Identifier{endpoint.Name}.Sanitize())
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P04" { // duplicate_database: another test process created it first
		err = nil
	}
	require.NoError(t, err, "Failed to create test database %s", endpoint.Name)
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
