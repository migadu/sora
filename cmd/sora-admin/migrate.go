package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	pgxv5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/migadu/sora/db" // Import the db package to access MigrationsFS
	"github.com/migadu/sora/logger"
)

// Migrations are now embedded in the `db` package and accessed via `db.MigrationsFS`.

func handleMigrateCommand(ctx context.Context) {
	if len(os.Args) < 3 {
		printMigrateUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "up":
		handleMigrateUp(ctx)
	case "down":
		handleMigrateDown(ctx)
	case "version":
		handleMigrateVersion(ctx)
	case "force":
		handleMigrateForce(ctx)
	case "help", "--help", "-h":
		printMigrateUsage()
	default:
		fmt.Printf("Unknown migrate subcommand: %s\n\n", subcommand)
		printMigrateUsage()
		os.Exit(1)
	}
}

func printMigrateUsage() {
	fmt.Printf(`Database Schema Migration Management

This command can be run safely while sora instances are running. The golang-migrate
library uses its own internal advisory lock to ensure only one migration runs at a time.

Usage:
  sora-admin migrate <subcommand> [options]

Subcommands:
  up        Apply all pending upwards migrations
  down      Revert migrations
  version   Show the current migration version and dirty state
  force     Force the database to a specific version (for fixing dirty states)

Examples:
  sora-admin migrate up
  sora-admin migrate down --limit 2
  sora-admin migrate down --all
  sora-admin migrate version
  sora-admin migrate force 1

Use 'sora-admin migrate <subcommand> --help' for detailed help.
`)
}

func handleMigrateUp(ctx context.Context) {
	fs := flag.NewFlagSet("migrate up", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML configuration file (required)")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate up --config config.toml")
		fmt.Println("Applies all pending upwards migrations.")
	}
	fs.Parse(os.Args[3:])

	if *configPath == "" {
		fmt.Println("Error: --config is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	m, db, err := getMigrateInstance(ctx, *configPath)
	if err != nil {
		logger.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	logger.Info("Applying UP migrations...")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		logger.Fatalf("Failed to apply UP migrations: %v", err)
	}
	logger.Info("Migrations applied successfully.")
	showVersion(m)
}

func handleMigrateDown(ctx context.Context) {
	fs := flag.NewFlagSet("migrate down", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML configuration file (required)")
	limit := fs.Int("limit", 1, "Number of migrations to revert")
	all := fs.Bool("all", false, "Revert all migrations")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate down --config config.toml [--limit N | --all]")
		fmt.Println("Reverts migrations. Defaults to reverting one migration.")
	}
	fs.Parse(os.Args[3:])

	if *configPath == "" {
		fmt.Println("Error: --config is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	m, db, err := getMigrateInstance(ctx, *configPath)
	if err != nil {
		logger.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	if *all {
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				logger.Info("No migrations to revert.")
				showVersion(m)
				return
			}
			logger.Fatalf("Failed to get current migration version: %v", err)
		}
		if dirty {
			logger.Fatalf("Database is in a dirty state (version %d). Please fix manually with 'force' command.", version)
		}

		logger.Info("Reverting all migrations", "count", version)
		if err := m.Steps(-int(version)); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			logger.Fatalf("Failed to revert all migrations: %v", err)
		}
	} else {
		logger.Info("Reverting migrations", "count", *limit)
		if err := m.Steps(-(*limit)); err != nil {
			logger.Fatalf("Failed to revert migrations: %v", err)
		}
	}
	logger.Info("Migrations reverted successfully.")
	showVersion(m)
}

func handleMigrateVersion(ctx context.Context) {
	fs := flag.NewFlagSet("migrate version", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML configuration file (required)")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate version --config config.toml")
		fmt.Println("Shows the current migration version and dirty state.")
	}
	fs.Parse(os.Args[3:])

	if *configPath == "" {
		fmt.Println("Error: --config is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	m, db, err := getMigrateInstance(ctx, *configPath)
	if err != nil {
		logger.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	showVersion(m)
}

func handleMigrateForce(ctx context.Context) {
	fs := flag.NewFlagSet("migrate force", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to TOML configuration file (required)")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate force --config config.toml <version>")
		fmt.Println("Forcibly sets the database migration version. USE WITH CAUTION.")
	}
	fs.Parse(os.Args[3:])

	if *configPath == "" {
		fmt.Println("Error: --config is required")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	version, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		logger.Fatalf("Invalid version number: %v", err)
	}

	m, db, err := getMigrateInstance(ctx, *configPath)
	if err != nil {
		logger.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	logger.Info("Forcing database version", "version", version)
	if err := m.Force(version); err != nil {
		logger.Fatalf("Failed to force version: %v", err)
	}
	logger.Info("Version forced successfully.")
	showVersion(m)
}

func getMigrateInstance(ctx context.Context, configPath string) (*migrate.Migrate, *sql.DB, error) {
	cfg := newDefaultAdminConfig()
	if err := loadAdminConfig(configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			logger.Info("WARNING: Configuration file not found - using defaults", "config", configPath)
		} else {
			return nil, nil, fmt.Errorf("error parsing configuration file '%s': %w", configPath, err)
		}
	}

	dbCfg := cfg.Database.Write
	if dbCfg == nil || len(dbCfg.Hosts) == 0 {
		return nil, nil, errors.New("write database configuration is missing or has no hosts")
	}

	sslMode := "disable"
	if dbCfg.TLSMode {
		sslMode = "require"
	}
	connString := fmt.Sprintf("postgres://%s:%s@%s:%v/%s?sslmode=%s",
		dbCfg.User, dbCfg.Password, dbCfg.Hosts[0], dbCfg.Port, dbCfg.Name, sslMode)

	sqlDB, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open sql.DB for migrations: %w", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Use the exported MigrationsFS from the db package. The go:embed directive
	// includes the 'migrations' directory, so we create a sub-filesystem.
	migrations, err := fs.Sub(db.MigrationsFS, "migrations")
	if err != nil {
		sqlDB.Close()
		return nil, nil, fmt.Errorf("failed to get migrations subdirectory: %w", err)
	}

	sourceDriver, err := iofs.New(migrations, ".")
	if err != nil {
		sqlDB.Close()
		return nil, nil, fmt.Errorf("failed to create migration source driver: %w", err)
	}

	dbDriver, err := pgxv5.WithInstance(sqlDB, &pgxv5.Config{})
	if err != nil {
		sqlDB.Close()
		return nil, nil, fmt.Errorf("failed to create migration db driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", dbDriver)
	if err != nil {
		sqlDB.Close()
		return nil, nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	m.Log = &migrationLogger{}
	return m, sqlDB, nil
}

func showVersion(m *migrate.Migrate) {
	version, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			logger.Info("Current migration version: none")
			return
		}
		logger.Info("Failed to get migration version", "error", err)
		return
	}

	logger.Info("Current migration version", "version", version)
	if dirty {
		logger.Info("Dirty state: YES (Database may be in an inconsistent state. Use 'force' to fix.)")
	} else {
		logger.Info("Dirty state: no")
	}
}

// migrationLogger is a copy from db/db.go for admin tool use
type migrationLogger struct{}

func (l *migrationLogger) Printf(format string, v ...any) {
	logger.Info("MIGRATE", "msg", fmt.Sprintf(format, v...))
}

func (l *migrationLogger) Verbose() bool {
	return true
}
