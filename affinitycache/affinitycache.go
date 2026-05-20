// Package affinitycache provides persistent storage for user-to-backend affinity
// mappings using SQLite.
//
// When a proxy server restarts, in-memory affinity mappings are lost. Without
// persistence, users get re-routed (potentially to different backends), losing
// cache locality and causing unnecessary backend churn.
//
// This package persists affinity assignments to local disk so they survive restarts.
// The AffinityManager loads persisted entries on startup and writes through on
// every set/update/delete.
//
// The cache is strictly optional — if it fails, the AffinityManager continues
// with in-memory-only operation and gossip-based cluster sync.
package affinitycache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	_ "modernc.org/sqlite"
)

// AffinityEntry represents a persisted affinity mapping.
type AffinityEntry struct {
	Username   string
	Protocol   string
	Backend    string
	AssignedAt time.Time
	ExpiresAt  time.Time
	NodeID     string
}

// Store provides persistent affinity storage backed by SQLite.
type Store struct {
	db *sql.DB
	mu sync.Mutex
}

// New creates a new affinity persistence store at dbPath.
// If the database is corrupted, it is automatically deleted and recreated.
func New(dbPath string) (*Store, error) {
	sqliteDB, err := openAndValidate(dbPath)
	if err != nil {
		logger.Warn("AffinityCache: Database appears corrupted, recreating", "path", dbPath, "error", err)
		if removeErr := removeDBFiles(dbPath); removeErr != nil {
			return nil, fmt.Errorf("failed to remove corrupted affinity cache db: %w", removeErr)
		}
		sqliteDB, err = openAndValidate(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to recreate affinity cache db: %w", err)
		}
		logger.Info("AffinityCache: Successfully recreated database", "path", dbPath)
	}

	return &Store{db: sqliteDB}, nil
}

// openAndValidate opens a SQLite database, sets pragmas, and creates the schema.
func openAndValidate(dbPath string) (*sql.DB, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		// Ensure the database file has 0600 permissions.
		// If the file does not exist, pre-create it with 0600 permissions.
		f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to create or set permissions on database file: %w", err)
		}
		f.Close()
		// If the file already exists, enforce 0600 permissions on it.
		if err := os.Chmod(dbPath, 0600); err != nil {
			return nil, fmt.Errorf("failed to enforce 0600 permissions on database file: %w", err)
		}
	}

	sqliteDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	if _, err := sqliteDB.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := sqliteDB.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set busy_timeout: %w", err)
	}
	if _, err := sqliteDB.Exec(`PRAGMA synchronous = NORMAL`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS affinity (
		key TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		protocol TEXT NOT NULL,
		backend TEXT NOT NULL,
		assigned_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		node_id TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_affinity_expires ON affinity(expires_at);
	`
	if _, err := sqliteDB.Exec(schema); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Integrity check
	var count int64
	if err := sqliteDB.QueryRow(`SELECT COUNT(*) FROM affinity`).Scan(&count); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	return sqliteDB, nil
}

// removeDBFiles removes the SQLite database and its journal files.
func removeDBFiles(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		p := dbPath + suffix
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", p, err)
		}
	}
	return nil
}

// LoadAll loads all non-expired affinity entries from the database.
// Called once on startup to pre-populate the in-memory map.
func (s *Store) LoadAll(ctx context.Context) ([]AffinityEntry, error) {
	now := time.Now().Unix()

	rows, err := s.db.QueryContext(ctx, `
		SELECT username, protocol, backend, assigned_at, expires_at, node_id
		FROM affinity
		WHERE expires_at > ?
	`, now)
	if err != nil {
		return nil, fmt.Errorf("failed to load affinity entries: %w", err)
	}
	defer rows.Close()

	var entries []AffinityEntry
	for rows.Next() {
		var e AffinityEntry
		var assignedAt, expiresAt int64
		if err := rows.Scan(&e.Username, &e.Protocol, &e.Backend, &assignedAt, &expiresAt, &e.NodeID); err != nil {
			return nil, fmt.Errorf("failed to scan affinity entry: %w", err)
		}
		e.AssignedAt = time.Unix(assignedAt, 0)
		e.ExpiresAt = time.Unix(expiresAt, 0)
		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// Set persists an affinity mapping (upsert).
func (s *Store) Set(ctx context.Context, entry AffinityEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := entry.Username + ":" + entry.Protocol
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO affinity (key, username, protocol, backend, assigned_at, expires_at, node_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			backend = excluded.backend,
			assigned_at = excluded.assigned_at,
			expires_at = excluded.expires_at,
			node_id = excluded.node_id
	`, key, entry.Username, entry.Protocol, entry.Backend,
		entry.AssignedAt.Unix(), entry.ExpiresAt.Unix(), entry.NodeID)

	if err != nil {
		return fmt.Errorf("failed to persist affinity: %w", err)
	}
	return nil
}

// Delete removes an affinity mapping.
func (s *Store) Delete(ctx context.Context, username, protocol string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := username + ":" + protocol
	_, err := s.db.ExecContext(ctx, `DELETE FROM affinity WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("failed to delete affinity: %w", err)
	}
	return nil
}

// Cleanup removes expired entries from the database.
func (s *Store) Cleanup(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	result, err := s.db.ExecContext(ctx, `DELETE FROM affinity WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired affinities: %w", err)
	}
	return result.RowsAffected()
}

// Count returns the total number of persisted entries.
func (s *Store) Count(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM affinity`).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Close closes the underlying SQLite database.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ErrNotConfigured is returned when persistence is not configured.
var ErrNotConfigured = errors.New("affinity persistence not configured")
