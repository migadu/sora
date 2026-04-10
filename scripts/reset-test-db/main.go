package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}

	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("DB_USER")
	if user == "" {
		user = "postgres"
	}

	connStr := fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable", user, host, port, dbName)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", dbName, err)
	}
	defer conn.Close(ctx)

	// Since this is natively hooked into make reset-test-db which is called before EVERY
	// test package, completely blowing away the schema ensures zero flaky behavior from
	// previous structural panics. Next step NewDatabaseFromConfig will recreate them.
	log.Printf("Resetting database %s to pristine state...", dbName)

	// Drop pg_trgm first to allow public schema to be dropped
	queries := []string{
		"DROP EXTENSION IF EXISTS pg_trgm CASCADE;",
		"DROP SCHEMA public CASCADE;",
		"CREATE SCHEMA public;",
		fmt.Sprintf("GRANT ALL ON SCHEMA public TO %s;", user),
	}

	for _, query := range queries {
		if _, err := conn.Exec(ctx, query); err != nil {
			// If it fails, fallback to truncating tables as before just in case
			log.Printf("Warning: failed to drop schema (%v). Falling back to TRUNCATE.", err)
			fallbackToTruncate(ctx, conn)
			return
		}
	}

	log.Println("Database successfully reset!")
}

func fallbackToTruncate(ctx context.Context, conn *pgx.Conn) {
	tables := []string{
		"vacation_responses", "sieve_scripts", "pending_uploads",
		"message_contents", "messages", "mailbox_stats", "mailbox_acls",
		"mailboxes", "credentials", "accounts", "metadata", "health_status",
		"cache_metrics",
	}

	// Disable triggers
	_, _ = conn.Exec(ctx, "SET session_replication_role = replica;")

	// Drop schema_migrations to ensure migrations run from scratch on errors
	_, _ = conn.Exec(ctx, "DROP TABLE IF EXISTS schema_migrations;")

	log.Println("Truncating tables...")
	_, err := conn.Exec(ctx, "TRUNCATE TABLE "+strings.Join(tables, ", ")+" CASCADE;")
	if err != nil {
		log.Fatalf("Fatal error truncating tables: %v", err)
	}

	// Re-enable triggers
	_, _ = conn.Exec(ctx, "SET session_replication_role = DEFAULT;")
	log.Println("Tables truncated successfully!")
}
