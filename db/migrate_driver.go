package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
)

// ErrMigrationInProgress is returned by OpenMigrate while another migrator, a starting
// Sora instance or another sora-admin, holds the migration leader lock.
var ErrMigrationInProgress = errors.New("another instance holds the migration leader lock and is running migrations")

// migrationDriver is the golang-migrate database driver Sora migrates with.
//
// golang-migrate's PostgreSQL drivers serialise migrators with a SESSION-level advisory
// lock: pg_advisory_lock and pg_advisory_unlock, in WithInstance and around every
// Up/Down/Force. Behind a transaction-mode pooler the two can run on different server
// connections; the unlock then releases nothing and the lock stays held on a pooled
// backend until the pooler retires it, stalling the next migration (see AdvisoryLockTx).
// This driver takes no lock of its own: every Sora migrator holds the migration leader
// lock (consts.SoraMigrationLeaderLockID) in an AdvisoryLockTx while it migrates.
//
// The rest follows golang-migrate's pgx/v5 driver: a migration file runs as one
// simple-protocol statement on one dedicated connection, and the version is kept in
// schema_migrations.
type migrationDriver struct {
	conn *pgx.Conn
}

var _ database.Driver = (*migrationDriver)(nil)

func (d *migrationDriver) Open(string) (database.Driver, error) {
	return nil, errors.New("migrationDriver is created by newMigrate, not opened by URL")
}

func (d *migrationDriver) Close() error { return d.conn.Close(context.Background()) }

// Lock and Unlock do nothing: the caller holds the migration leader lock.
func (d *migrationDriver) Lock() error   { return nil }
func (d *migrationDriver) Unlock() error { return nil }

func (d *migrationDriver) Run(migration io.Reader) error {
	body, err := io.ReadAll(migration)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(body)) == "" {
		return nil
	}
	if _, err := d.conn.Exec(context.Background(), string(body)); err != nil {
		return database.Error{OrigErr: err, Err: "migration failed", Query: body}
	}
	return nil
}

func (d *migrationDriver) SetVersion(version int, dirty bool) error {
	ctx := context.Background()
	return pgx.BeginFunc(ctx, d.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "TRUNCATE schema_migrations"); err != nil {
			return err
		}
		// As in golang-migrate's drivers, a dirty NilVersion is recorded too, so a failed
		// down migration of the first version does not look like an empty schema.
		if version >= 0 || (version == database.NilVersion && dirty) {
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, dirty) VALUES ($1, $2)", version, dirty)
			return err
		}
		return nil
	})
}

func (d *migrationDriver) Version() (int, bool, error) {
	var version int64
	var dirty bool
	err := d.conn.QueryRow(context.Background(), "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&version, &dirty)
	if errors.Is(err, pgx.ErrNoRows) {
		return database.NilVersion, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return int(version), dirty, nil
}

func (d *migrationDriver) Drop() error {
	return errors.New("migrationDriver does not drop schemas")
}

// newMigrate returns a golang-migrate instance for the embedded migrations, over a
// connection of its own opened with connConfig. Its driver takes no lock: the caller
// must hold the migration leader lock while it uses the instance. Closing the instance
// closes the connection.
func newMigrate(ctx context.Context, connConfig *pgx.ConnConfig) (*migrate.Migrate, error) {
	conn, err := pgx.ConnectConfig(ctx, connConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for migrations: %w", err)
	}
	// Create the version table only when it is missing: CREATE TABLE IF NOT EXISTS
	// needs CREATE on the schema even when the table exists.
	var exists bool
	err = conn.QueryRow(ctx, "SELECT to_regclass('schema_migrations') IS NOT NULL").Scan(&exists)
	if err == nil && !exists {
		_, err = conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)")
	}
	if err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("failed to prepare schema_migrations: %w", err)
	}

	migrations, err := fs.Sub(MigrationsFS, "migrations")
	if err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("failed to get migrations subdirectory: %w", err)
	}
	sourceDriver, err := iofs.New(migrations, ".")
	if err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("failed to create migration source driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", &migrationDriver{conn: conn})
	if err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}
	return m, nil
}

// migrateSession is a golang-migrate instance used under the migration leader lock.
type migrateSession struct {
	m      *migrate.Migrate
	leader *AdvisoryLockTx
}

// Close closes the migration connection and releases the leader lock.
func (s *migrateSession) Close() error {
	srcErr, dbErr := s.m.Close()
	s.leader.Release()
	return errors.Join(srcErr, dbErr)
}

// OpenMigrate takes the migration leader lock, the one starting Sora instances elect
// their migration leader with, and returns a golang-migrate instance for the embedded
// migrations, for sora-admin's migrate up, down and force. It does not wait for the
// lock: while another migrator holds it, it returns ErrMigrationInProgress. Close the
// returned io.Closer to close the instance and release the lock.
func (db *Database) OpenMigrate(ctx context.Context) (*migrate.Migrate, io.Closer, error) {
	leader, err := db.BeginAdvisoryLockTx(ctx)
	if err != nil {
		return nil, nil, err
	}
	ok, err := leader.TryLock(ctx, consts.SoraMigrationLeaderLockID)
	if err == nil && !ok {
		err = ErrMigrationInProgress
	}
	if err != nil {
		leader.Release()
		return nil, nil, err
	}
	m, err := newMigrate(ctx, db.WritePool.Config().ConnConfig.Copy())
	if err != nil {
		leader.Release()
		return nil, nil, err
	}
	return m, &migrateSession{m: m, leader: leader}, nil
}
