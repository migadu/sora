package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"
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

The 'version' subcommand can be run safely while sora instances are running (it queries
schema_migrations directly without acquiring locks). The 'up', 'down', and 'force'
subcommands require stopping sora instances first; they take the migration leader lock
and refuse to run while a starting instance holds it.

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
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate up --config config.toml")
		fmt.Println("Applies all pending upwards migrations.")
	}
	fs.Parse(os.Args[3:])

	m, db, err := getMigrateInstance(ctx)
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
	limit := fs.Int("limit", 1, "Number of migrations to revert")
	all := fs.Bool("all", false, "Revert every migration after the first (the initial schema)")
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate down --config config.toml [--limit N | --all]")
		fmt.Println("Reverts migrations. Defaults to reverting one migration.")
		fmt.Println("The first migration (the initial schema) is never reverted.")
	}
	fs.Parse(os.Args[3:])
	// A limit below 1 reverts nothing, and a negative one would migrate up.
	if *limit < 1 {
		logger.Fatal("--limit must be at least 1")
	}

	versions, err := db.MigrationVersions()
	if err != nil {
		logger.Fatalf("Failed to read the migrations: %v", err)
	}

	m, closer, err := getMigrateInstance(ctx)
	if err != nil {
		logger.Fatalf("Failed to initialize migration tool: %v", err)
	}
	defer closer.Close()

	version, dirty, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		// Migrate.Version returns ErrNilVersion before returning dirty, so a failed
		// down migration of version 1 (version = -1, dirty = true) looks the same
		// here as an empty schema. Down reads the driver directly and returns
		// ErrDirty{-1} when dirty or ErrNoChange when nothing is applied.
		if err := m.Down(); err != nil {
			var dirtyErr migrate.ErrDirty
			if errors.As(err, &dirtyErr) {
				logger.Fatalf("Database is in a dirty state (version %d). Please fix manually with 'force' command.", dirtyErr.Version)
			}
			if !errors.Is(err, migrate.ErrNoChange) {
				logger.Fatalf("Failed to revert migrations: %v", err)
			}
		}
		if !*all {
			logger.Fatalf("No migration is applied, so --limit %d has none to revert.", *limit)
		}
		logger.Info("No migrations to revert.")
		showVersion(m)
		return
	}
	if err != nil {
		logger.Fatalf("Failed to get current migration version: %v", err)
	}
	if dirty {
		logger.Fatalf("Database is in a dirty state (version %d). Please fix manually with 'force' command.", version)
	}

	target, err := downTarget(versions, version, *limit, *all)
	if err != nil {
		logger.Fatalf("Refusing to revert migrations: %v", err)
	}
	if target == version {
		logger.Info("No migrations to revert.")
		showVersion(m)
		return
	}

	// Migrate stops at the target. Down, and Steps with a limit that reaches the first
	// migration, would also run the first migration's down file (see downTarget).
	logger.Info("Reverting migrations", "from_version", version, "to_version", target)
	if err := m.Migrate(target); err != nil {
		logger.Fatalf("Failed to revert migrations: %v", err)
	}
	logger.Info("Migrations reverted successfully.")
	showVersion(m)
}

// downTarget returns the version that `migrate down` leaves applied when current is
// applied: limit migrations earlier, or with all the first migration. versions are
// the migrations in ascending order. It refuses to go past the first migration. That
// migration's down file is a deliberate no-op (000001_initial_schema.down.sql), so
// reverting it would record no version while the initial tables stay, and the next
// `migrate up`, or a sora start, would fail creating them again and leave the first
// version dirty. To tear the schema down, drop and recreate the database.
func downTarget(versions []uint, current uint, limit int, all bool) (uint, error) {
	i := slices.Index(versions, current)
	if i < 0 {
		return 0, fmt.Errorf("the applied migration version %d is not one of this binary's migrations", current)
	}
	if all {
		return versions[0], nil
	}
	if limit > i {
		return 0, fmt.Errorf("--limit %d would revert the first migration (%d), which is never reverted; %d applied migrations come after it",
			limit, versions[0], i)
	}
	return versions[i-limit], nil
}

func handleMigrateVersion(ctx context.Context) {
	fs := flag.NewFlagSet("migrate version", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate version --config config.toml")
		fmt.Println("Shows the current migration version and dirty state.")
	}
	fs.Parse(os.Args[3:])

	// Query schema_migrations directly instead of taking the migration leader lock.
	// Checking the version stays a plain read that is safe while sora instances run.
	sqlDB, err := openMigrationDB(ctx)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}
	defer sqlDB.Close()

	var version int
	var dirty bool
	err = sqlDB.QueryRowContext(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Info("Current migration version: none")
			return
		}
		logger.Fatalf("Failed to query migration version: %v", err)
	}

	logger.Info("Current migration version", "version", version)
	if dirty {
		logger.Info("Dirty state: YES (Database may be in an inconsistent state. Use 'force' to fix.)")
	} else {
		logger.Info("Dirty state: no")
	}
}

func handleMigrateForce(ctx context.Context) {
	fs := flag.NewFlagSet("migrate force", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: sora-admin migrate force --config config.toml <version>")
		fmt.Println("Forcibly sets the database migration version. USE WITH CAUTION.")
	}
	fs.Parse(os.Args[3:])

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	version, err := strconv.Atoi(fs.Arg(0))
	if err != nil {
		logger.Fatalf("Invalid version number: %v", err)
	}

	m, db, err := getMigrateInstance(ctx)
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

// openMigrationDB connects to the first write host using the server connection URL.
func openMigrationDB(ctx context.Context) (*sql.DB, error) {
	dbCfg := globalConfig.Database.Write
	if dbCfg == nil || len(dbCfg.Hosts) == 0 {
		return nil, errors.New("write database configuration is missing or has no hosts")
	}
	connURL, err := db.EndpointURL(dbCfg, dbCfg.Hosts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid write database configuration: %w", err)
	}

	sqlDB, err := sql.Open("pgx", connURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return sqlDB, nil
}

// getMigrateInstance connects to the first [database.write] host and returns a
// golang-migrate instance held under the migration leader lock (db.OpenMigrate): it
// never runs alongside a starting sora instance's migrations, and it takes no
// session-level lock that a transaction-mode pooler would strand. Close the returned
// io.Closer when done.
func getMigrateInstance(ctx context.Context) (*migrate.Migrate, io.Closer, error) {
	dbCfg := globalConfig.Database.Write
	if dbCfg == nil || len(dbCfg.Hosts) == 0 {
		return nil, nil, errors.New("write database configuration is missing or has no hosts")
	}

	connURL, err := db.EndpointURL(dbCfg, dbCfg.Hosts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid write database configuration: %w", err)
	}

	pool, err := pgxpool.New(ctx, connURL.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection pool for migrations: %w", err)
	}
	m, session, err := (&db.Database{WritePool: pool}).OpenMigrate(ctx)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("failed to start migration: %w", err)
	}

	m.Log = &migrationLogger{}
	return m, closerFunc(func() error {
		err := session.Close()
		pool.Close()
		return err
	}), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

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
	logger.Info("MIGRATE", "detail", fmt.Sprintf(format, v...))
}

func (l *migrationLogger) Verbose() bool {
	return true
}
