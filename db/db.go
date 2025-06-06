package db

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/yugabyte/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

type Database struct {
	Pool *pgxpool.Pool
}

// NewDatabase initializes a new SQL database connection
func NewDatabase(ctx context.Context, host, port, user, password, dbname string, tlsMode bool, logQueries bool) (*Database, error) {
	sslMode := "disable"
	if tlsMode {
		sslMode = "require"
	}

	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbname, sslMode)

	log.Printf("Connecting to database: postgres://%s@%s:%s/%s?sslmode=%s",
		user, host, port, dbname, sslMode)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatalf("unable to parse connection string: %v", err)
	}

	if logQueries {
		config.ConnConfig.Tracer = &CustomTracer{}
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	if err := dbPool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}

	db := &Database{
		Pool: dbPool,
	}

	if err := db.migrate(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *Database) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

func (db *Database) migrate(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx, schema)
	return err
}
