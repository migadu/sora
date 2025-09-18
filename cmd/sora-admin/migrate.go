package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/golang-migrate/migrate/v4"
	pgxv5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db" // Import the db package to access MigrationsFS
)

// Migrations are now embedded in the `db` package and accessed via `db.MigrationsFS`.

func handleMigrateCommand() {
	if len(os.Args) < 3 {
		printMigrateUsage()
		os.Exit(1)
	}

	subcommand := os.Args[2]
	switch subcommand {
	case "up":
		handleMigrateUp()
	case "down":
		handleMigrateDown()
	case "version":
		handleMigrateVersion()
	case "force":
		handleMigrateForce()
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

This command should be run while the main 'sora' server is stopped to prevent
schema conflicts. It uses a database lock to ensure safety.

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

func handleMigrateUp() {
	fs := flag.NewFlagSet("migrate up", flag.ExitOnError)
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate up [--config config.toml]")
		fmt.Println("Applies all pending upwards migrations.")
	}
	fs.Parse(os.Args[3:])

	m, db, err := getMigrateInstance(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	if err := acquireExclusiveLock(db); err != nil {
		log.Fatalf("Failed to acquire exclusive lock: %v", err)
	}
	defer releaseExclusiveLock(db)

	log.Println("Applying UP migrations...")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("Failed to apply UP migrations: %v", err)
	}
	log.Println("Migrations applied successfully.")
	showVersion(m)
}

func handleMigrateDown() {
	fs := flag.NewFlagSet("migrate down", flag.ExitOnError)
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	limit := fs.Int("limit", 1, "Number of migrations to revert")
	all := fs.Bool("all", false, "Revert all migrations")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate down [--config config.toml] [--limit N | --all]")
		fmt.Println("Reverts migrations. Defaults to reverting one migration.")
	}
	fs.Parse(os.Args[3:])

	m, db, err := getMigrateInstance(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	if err := acquireExclusiveLock(db); err != nil {
		log.Fatalf("Failed to acquire exclusive lock: %v", err)
	}
	defer releaseExclusiveLock(db)

	if *all {
		version, dirty, err := m.Version()
		if err != nil {
			if errors.Is(err, migrate.ErrNilVersion) {
				log.Println("No migrations to revert.")
				showVersion(m)
				return
			}
			log.Fatalf("Failed to get current migration version: %v", err)
		}
		if dirty {
			log.Fatalf("Database is in a dirty state (version %d). Please fix manually with 'force' command.", version)
		}

		log.Printf("Reverting all %d migration(s)...\n", version)
		if err := m.Steps(-int(version)); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("Failed to revert all migrations: %v", err)
		}
	} else {
		log.Printf("Reverting %d migration(s)...\n", *limit)
		if err := m.Steps(-(*limit)); err != nil {
			log.Fatalf("Failed to revert migrations: %v", err)
		}
	}
	log.Println("Migrations reverted successfully.")
	showVersion(m)
}

func handleMigrateVersion() {
	fs := flag.NewFlagSet("migrate version", flag.ExitOnError)
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate version [--config config.toml]")
		fmt.Println("Shows the current migration version and dirty state.")
	}
	fs.Parse(os.Args[3:])

	m, db, err := getMigrateInstance(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	showVersion(m)
}

func handleMigrateForce() {
	fs := flag.NewFlagSet("migrate force", flag.ExitOnError)
	configPath := fs.String("config", "config.toml", "Path to TOML configuration file")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate force [--config config.toml] <version>")
		fmt.Println("Forcibly sets the database migration version. USE WITH CAUTION.")
	}
	fs.Parse(os.Args[3:])

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	version, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		log.Fatalf("Invalid version number: %v", err)
	}

	m, db, err := getMigrateInstance(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer db.Close()

	if err := acquireExclusiveLock(db); err != nil {
		log.Fatalf("Failed to acquire exclusive lock: %v", err)
	}
	defer releaseExclusiveLock(db)

	log.Printf("Forcing database version to %d...", version)
	if err := m.Force(version); err != nil {
		log.Fatalf("Failed to force version: %v", err)
	}
	log.Println("Version forced successfully.")
	showVersion(m)
}

func getMigrateInstance(configPath string) (*migrate.Migrate, *sql.DB, error) {
	cfg := newDefaultAdminConfig()
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		if os.IsNotExist(err) {
			log.Printf("WARNING: configuration file '%s' not found. Using defaults.", configPath)
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
	if err := sqlDB.Ping(); err != nil {
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

func acquireExclusiveLock(db *sql.DB) error {
	var lockAcquired bool
	// Use a context with a short timeout to avoid waiting forever.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", consts.SoraAdvisoryLockID).Scan(&lockAcquired)
	if err != nil {
		return fmt.Errorf("failed to query for advisory lock: %w", err)
	}

	if !lockAcquired {
		return fmt.Errorf("could not acquire exclusive database lock. Is a sora server instance already running?")
	}

	log.Println("Acquired exclusive database lock for migration.")
	return nil
}

func releaseExclusiveLock(db *sql.DB) {
	var unlocked bool
	// Use a background context as the main context might be done.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.QueryRowContext(ctx, "SELECT pg_advisory_unlock($1)", consts.SoraAdvisoryLockID).Scan(&unlocked)
	if err != nil {
		log.Printf("WARN: failed to release advisory lock after migration: %v", err)
	} else if unlocked {
		log.Println("Released exclusive database lock.")
	} else {
		log.Printf("WARN: pg_advisory_unlock reported lock was not held at time of release.")
	}
}

func showVersion(m *migrate.Migrate) {
	version, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			log.Println("Current migration version: none")
			return
		}
		log.Printf("Failed to get migration version: %v", err)
		return
	}

	log.Printf("Current migration version: %d", version)
	if dirty {
		log.Println("Dirty state: YES (Database may be in an inconsistent state. Use 'force' to fix.)")
	} else {
		log.Println("Dirty state: no")
	}
}

// migrationLogger is a copy from db/db.go for admin tool use
type migrationLogger struct{}

func (l *migrationLogger) Printf(format string, v ...interface{}) {
	log.Printf("[MIGRATE] "+format, v...)
}

func (l *migrationLogger) Verbose() bool {
	return true
}
