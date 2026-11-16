//go:build integration

package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
)

// These fixtures create separate PostgreSQL databases, not just separate
// accounts. Equal account IDs must not make one destination's cache completion
// authoritative for another destination.
type importerDestinationDB struct {
	name string
	rdb  *resilient.ResilientDatabase
}

func newImporterDestinationDB(t *testing.T, suffix, template string) *importerDestinationDB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer admin.Close(ctx)
	d := &importerDestinationDB{name: fmt.Sprintf("sora_impdest_%d_%s", time.Now().UnixNano(), suffix)}
	query := "CREATE DATABASE " + pgx.Identifier{d.name}.Sanitize()
	if template != "" {
		query += " TEMPLATE " + pgx.Identifier{template}.Sanitize()
	}
	if _, err := admin.Exec(ctx, query); err != nil {
		t.Fatalf("create isolated destination database: %v", err)
	}
	t.Cleanup(func() {
		if d.rdb != nil {
			d.rdb.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
		if err != nil {
			t.Errorf("connect to remove destination fixture: %v", err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{d.name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("remove destination fixture: %v", err)
		}
	})
	d.reopen(t)
	return d
}

func (d *importerDestinationDB) reopen(t *testing.T) {
	t.Helper()
	if d.rdb != nil {
		d.rdb.Close()
	}
	cfg := &config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: d.name,
	}}
	var err error
	d.rdb, err = resilient.NewResilientDatabaseWithOptions(context.Background(), cfg, false, true, true)
	if err != nil {
		t.Fatalf("open isolated destination database: %v", err)
	}
}

func assertDestinationSubjects(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, want ...string) {
	t.Helper()
	if got := liveSubjects(t, rdb, accountID); !slices.Equal(got, want) {
		t.Fatalf("live destination subjects = %q, want %q", got, want)
	}
}

// writeLegacyDestinationCache constructs the schema written before database
// identity existed. There is deliberately no new completion ledger to clear.
func writeLegacyDestinationCache(t *testing.T, maildir string, accountID any) {
	t.Helper()
	cache, err := sql.Open("sqlite", filepath.Join(maildir, maildirCacheName))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	_, err = cache.Exec(`CREATE TABLE messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL,
		filename TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL,
		mailbox TEXT NOT NULL, s3_uploaded INTEGER DEFAULT 0,
		s3_uploaded_at TIMESTAMP, account_id INTEGER,
		UNIQUE(hash, mailbox), UNIQUE(filename, mailbox))`)
	if err != nil {
		t.Fatal(err)
	}
	for _, folder := range []struct{ path, mailbox string }{{"cur", "INBOX"}, {".Archive/cur", "Archive"}} {
		entries, err := os.ReadDir(filepath.Join(maildir, folder.path))
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("legacy fixture has %d files in %s, want 1", len(entries), folder.path)
		}
		path := filepath.Join(maildir, folder.path, entries[0].Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cache.Exec(`INSERT INTO messages
			(path, filename, hash, size, mailbox, s3_uploaded, s3_uploaded_at, account_id)
			VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP, ?)`,
			path, entries[0].Name(), helpers.HashContent(body), len(body), folder.mailbox, accountID)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestImporterDestinationCompletion(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}
	ctx := context.Background()
	for _, batchTx := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch_transaction=%v", batchTx), func(t *testing.T) {
			a := newImporterDestinationDB(t, "a", "")
			b := newImporterDestinationDB(t, "b", "")
			opts := ImporterOptions{Incremental: true, PreserveFlags: true, TestMode: true, BatchSize: 10, BatchTransactionMode: batchTx}

			t.Run("independent_databases_roundtrip_and_reconnect", func(t *testing.T) {
				const email = "destination-roundtrip@example.com"
				idA, idB := rerunAccount(t, a.rdb, email), rerunAccount(t, b.rdb, email)
				if idA != idB {
					t.Fatalf("fixture must use the same numeric account ID: %d != %d", idA, idB)
				}
				maildir := rerunMaildir(t, 3)
				if got := runImport(t, a.rdb, maildir, email, opts).importedMessages; got != 3 {
					t.Fatalf("first A import = %d, want 3", got)
				}
				assertDestinationSubjects(t, a.rdb, idA, "Message 0", "Message 1", "Message 2")
				if _, err := a.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
					`UPDATE messages SET expunged_at = now() WHERE account_id = $1 AND subject = 'Message 1'`, idA); err != nil {
					t.Fatal(err)
				}
				if _, err := a.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
					`DELETE FROM messages WHERE account_id = $1 AND subject = 'Message 2'`, idA); err != nil {
					t.Fatal(err)
				}
				if got := runImport(t, b.rdb, maildir, email, opts).importedMessages; got != 3 {
					t.Fatalf("independent B import = %d, want all 3 despite equal account ID", got)
				}
				assertDestinationSubjects(t, b.rdb, idB, "Message 0", "Message 1", "Message 2")
				if got := runImport(t, a.rdb, maildir, email, opts).importedMessages; got != 0 {
					t.Fatalf("return to A imported %d deleted messages, want 0", got)
				}
				assertDestinationSubjects(t, a.rdb, idA, "Message 0")
				a.reopen(t)
				if got := runImport(t, a.rdb, maildir, email, opts).importedMessages; got != 0 {
					t.Fatalf("reconnected A imported %d deleted messages, want 0", got)
				}
				assertDestinationSubjects(t, a.rdb, idA, "Message 0")
				var expunged, purged int
				if err := a.rdb.QueryRowWithRetry(ctx, `SELECT
					COUNT(*) FILTER (WHERE subject = 'Message 1' AND expunged_at IS NOT NULL),
					COUNT(*) FILTER (WHERE subject = 'Message 2') FROM messages WHERE account_id = $1`, idA).Scan(&expunged, &purged); err != nil {
					t.Fatal(err)
				}
				if expunged != 1 || purged != 0 {
					t.Fatalf("A deletion state changed: expunged=%d purged rows=%d, want 1 and 0", expunged, purged)
				}
			})

			for _, numericStamp := range []bool{false, true} {
				t.Run(fmt.Sprintf("legacy_numeric_stamp=%v", numericStamp), func(t *testing.T) {
					email := fmt.Sprintf("destination-legacy-%v@example.com", numericStamp)
					idA, idB := rerunAccount(t, a.rdb, email), rerunAccount(t, b.rdb, email)
					if idA != idB {
						t.Fatalf("legacy fixture needs equal account IDs: %d != %d", idA, idB)
					}
					// Only INBOX already contains this body in B. A legacy mark on an
					// Archive copy must not be promoted by an account-wide hash lookup.
					runImport(t, b.rdb, rerunMaildir(t, 1), email, opts)
					maildir := rerunMaildir(t, 1)
					entries, err := os.ReadDir(filepath.Join(maildir, "cur"))
					if err != nil {
						t.Fatal(err)
					}
					for _, dir := range []string{"cur", "new", "tmp"} {
						if err := os.MkdirAll(filepath.Join(maildir, ".Archive", dir), 0o755); err != nil {
							t.Fatal(err)
						}
					}
					body, err := os.ReadFile(filepath.Join(maildir, "cur", entries[0].Name()))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(maildir, ".Archive", "cur", entries[0].Name()), body, 0o644); err != nil {
						t.Fatal(err)
					}
					var legacyAccount any
					if numericStamp {
						legacyAccount = idA
					}
					writeLegacyDestinationCache(t, maildir, legacyAccount)
					runImport(t, b.rdb, maildir, email, opts)
					var inbox, archive int
					if err := b.rdb.QueryRowWithRetry(ctx, `SELECT
						COUNT(*) FILTER (WHERE mb.name = 'INBOX'), COUNT(*) FILTER (WHERE mb.name = 'Archive')
						FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
						WHERE m.account_id = $1 AND m.expunged_at IS NULL`, idB).Scan(&inbox, &archive); err != nil {
						t.Fatal(err)
					}
					if inbox != 1 || archive != 1 {
						t.Fatalf("legacy cache promoted the wrong mailbox: INBOX=%d Archive=%d, want 1 each", inbox, archive)
					}
					if _, err := b.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
						`DELETE FROM messages WHERE account_id = $1`, idB); err != nil {
						t.Fatal(err)
					}
					if got := runImport(t, b.rdb, maildir, email, opts).importedMessages; got != 0 {
						t.Fatalf("verified legacy completion reimported %d deleted copies, want 0", got)
					}
					assertDestinationSubjects(t, b.rdb, idB)
				})
			}

			for _, incrementalReturn := range []bool{true, false} {
				t.Run(fmt.Sprintf("legacy_hash_rekey_return_incremental=%v", incrementalReturn), func(t *testing.T) {
					email := fmt.Sprintf("destination-legacy-hash-%v@example.com", incrementalReturn)
					idA, idB := rerunAccount(t, a.rdb, email), rerunAccount(t, b.rdb, email)
					if idA != idB {
						t.Fatalf("legacy hash fixture needs equal account IDs: %d != %d", idA, idB)
					}
					maildir := rerunMaildir(t, 1)
					runImport(t, a.rdb, maildir, email, opts)
					entries, err := os.ReadDir(filepath.Join(maildir, "cur"))
					if err != nil {
						t.Fatal(err)
					}
					body, err := os.ReadFile(filepath.Join(maildir, "cur", entries[0].Name()))
					if err != nil {
						t.Fatal(err)
					}
					legacyHash := legacyImportHash(body)
					cache, err := sql.Open("sqlite", filepath.Join(maildir, maildirCacheName))
					if err != nil {
						t.Fatal(err)
					}
					// Model a pre-BLAKE3 import: both stores use SHA-256 and the old
					// cache has no destination ledger. Recovery must establish A's
					// completion before its user deliberately removes the message.
					_, err = cache.Exec(`UPDATE messages SET hash = ?; DELETE FROM import_completions`, legacyHash)
					cache.Close()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := a.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
						`UPDATE messages SET content_hash = $1 WHERE account_id = $2`, legacyHash, idA); err != nil {
						t.Fatal(err)
					}
					if got := runImport(t, a.rdb, maildir, email, opts).importedMessages; got != 0 {
						t.Fatalf("verifying legacy A imported %d copies, want 0", got)
					}
					if incrementalReturn {
						if _, err := a.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
							`DELETE FROM messages WHERE account_id = $1`, idA); err != nil {
							t.Fatal(err)
						}
					}
					if got := runImport(t, b.rdb, maildir, email, opts).importedMessages; got != 1 {
						t.Fatalf("B imported %d legacy copies, want 1", got)
					}
					assertDestinationSubjects(t, b.rdb, idB, "Message 0")
					returnOpts := opts
					returnOpts.Incremental = incrementalReturn
					returned := runImport(t, a.rdb, maildir, email, returnOpts)
					if got := returned.importedMessages; got != 0 {
						t.Fatalf("cache hash upgrade lost A identity and imported %d deleted/duplicate copies (incremental=%v)", got, incrementalReturn)
					}
					if incrementalReturn {
						assertDestinationSubjects(t, a.rdb, idA)
					} else {
						assertDestinationSubjects(t, a.rdb, idA, "Message 0")
						var hash string
						if err := a.rdb.QueryRowWithRetry(ctx, `SELECT content_hash FROM messages
							WHERE account_id = $1 AND expunged_at IS NULL`, idA).Scan(&hash); err != nil {
							t.Fatal(err)
						}
						if hash != legacyHash || returned.skippedMessages != 1 {
							t.Fatalf("default rerun changed legacy identity or did not skip its one copy: hash preserved=%v skipped=%d", hash == legacyHash, returned.skippedMessages)
						}
					}
				})
			}

			t.Run("another_destination_changes_shared_projection", func(t *testing.T) {
				const email = "destination-projection@example.com"
				idA, idB := rerunAccount(t, a.rdb, email), rerunAccount(t, b.rdb, email)
				if idA != idB {
					t.Fatalf("projection fixture needs equal account IDs: %d != %d", idA, idB)
				}
				maildir := rerunMaildir(t, 1)
				runImport(t, a.rdb, maildir, email, opts)
				if _, err := a.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
					`DELETE FROM messages WHERE account_id = $1`, idA); err != nil {
					t.Fatal(err)
				}
				pending, err := NewImporter(ctx, maildir, email, 1, b.rdb, nil, opts)
				if err != nil {
					t.Fatal(err)
				}
				defer pending.Close()
				if err := pending.lookupAccount(); err != nil {
					t.Fatal(err)
				}
				if err := pending.recoverOrphanedSQLiteState(); err != nil {
					t.Fatal(err)
				}
				completed, err := NewImporter(ctx, maildir, email, 1, a.rdb, nil, opts)
				if err != nil {
					t.Fatal(err)
				}
				defer completed.Close()
				if err := completed.lookupAccount(); err != nil {
					t.Fatal(err)
				}
				if err := completed.recoverOrphanedSQLiteState(); err != nil {
					t.Fatal(err)
				}
				// A's recovery has restored the global compatibility mark after B's
				// preparation. B must still select its own missing copy.
				pending.totalMessages = 1
				if err := pending.importMessages(); err != nil {
					t.Fatal(err)
				}
				if pending.importedMessages != 1 {
					t.Fatalf("B imported %d copies after A changed the shared mark, want 1", pending.importedMessages)
				}
				assertDestinationSubjects(t, b.rdb, idB, "Message 0")
				// Model a later destination projecting this same row as pending,
				// between A's preparation and its actual selection. A's durable
				// completion must keep its deliberately deleted copy absent.
				if _, err := pending.sqliteDB.Exec(`UPDATE messages SET s3_uploaded = 0`); err != nil {
					t.Fatal(err)
				}
				completed.totalMessages = 1
				if err := completed.importMessages(); err != nil {
					t.Fatal(err)
				}
				if completed.importedMessages != 0 {
					t.Fatalf("A reimported %d deleted copies after another destination changed the mark", completed.importedMessages)
				}
				assertDestinationSubjects(t, a.rdb, idA)
			})

			t.Run("independent_clone_explicit_identity_rotation", func(t *testing.T) {
				const email = "destination-clone@example.com"
				accountID := rerunAccount(t, a.rdb, email)
				maildir := rerunMaildir(t, 3)
				runImport(t, a.rdb, maildir, email, opts)
				identityA, err := a.rdb.GetDatabaseIdentityWithRetry(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// TEMPLATE copies the real identity row as a backup/clone would.
				// PostgreSQL requires the source database's connections to be closed.
				a.rdb.Close()
				a.rdb = nil
				clone := newImporterDestinationDB(t, "clone", a.name)
				a.reopen(t)
				identityClone, err := clone.rdb.GetDatabaseIdentityWithRetry(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if identityClone != identityA {
					t.Fatal("template clone did not preserve the logical database identity")
				}
				if _, err := clone.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
					`DELETE FROM messages WHERE account_id = $1`, accountID); err != nil {
					t.Fatal(err)
				}
				if got := runImport(t, clone.rdb, maildir, email, opts).importedMessages; got != 0 {
					t.Fatalf("same logical identity reimported %d deleted copies, want 0", got)
				}
				// An independently operated clone needs an explicit new identity;
				// connection settings alone must neither imply nor rotate one.
				if _, err := clone.rdb.GetOperationalDatabase().WritePool.Exec(ctx,
					`UPDATE public.database_identity SET identity = gen_random_uuid() WHERE singleton`); err != nil {
					t.Fatal(err)
				}
				rotated, err := clone.rdb.GetDatabaseIdentityWithRetry(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if rotated == identityA {
					t.Fatal("explicit clone identity rotation had no effect")
				}
				if got := runImport(t, clone.rdb, maildir, email, opts).importedMessages; got != 3 {
					t.Fatalf("independent clone import = %d, want all 3 after rotation", got)
				}
				assertDestinationSubjects(t, clone.rdb, accountID, "Message 0", "Message 1", "Message 2")
			})
		})
	}
}
