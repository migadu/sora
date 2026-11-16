package lmtpproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"golang.org/x/crypto/bcrypt"
)

func setupSplitLMTPTestDatabase(t *testing.T, address string) (*resilient.ResilientDatabase, int64) {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database test in short mode")
	}

	ctx := context.Background()
	admin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
	if err != nil {
		t.Skipf("PostgreSQL not available on localhost:5432: %v", err)
	}
	defer admin.Close(ctx)

	base := os.Getenv("SORA_TEST_DB_NAME")
	if base == "" {
		base = "sora_test_db"
	}
	stamp := time.Now().UnixNano()
	primaryName := fmt.Sprintf("%s_lmtp_pri_%d", base, stamp)
	replicaName := fmt.Sprintf("%s_lmtp_rep_%d", base, stamp)

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{primaryName}.Sanitize()); err != nil {
		t.Fatalf("CREATE DATABASE %s: %v", primaryName, err)
	}
	t.Cleanup(func() {
		cleanAdmin, err := pgx.Connect(ctx, "postgres://postgres@localhost:5432/postgres?sslmode=disable")
		if err != nil {
			t.Errorf("admin connect for cleanup: %v", err)
			return
		}
		defer cleanAdmin.Close(ctx)
		for _, name := range []string{replicaName, primaryName} {
			if _, err := cleanAdmin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
				t.Errorf("DROP DATABASE %s: %v", name, err)
			}
		}
	})

	primaryEndpoint := &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"},
		Port:  "5432",
		User:  "postgres",
		Name:  primaryName,
	}
	replicaEndpoint := &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"},
		Port:  "5432",
		User:  "postgres",
		Name:  replicaName,
	}

	setupDB, err := db.NewDatabaseFromConfig(ctx, &config.DatabaseConfig{Write: primaryEndpoint}, true)
	if err != nil {
		t.Fatalf("migrate primary %s: %v", primaryName, err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.MinCost)
	if err != nil {
		setupDB.Close()
		t.Fatalf("bcrypt: %v", err)
	}
	var accountID int64
	if err := setupDB.GetWritePool().QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&accountID); err != nil {
		setupDB.Close()
		t.Fatalf("insert account: %v", err)
	}
	if _, err := setupDB.GetWritePool().Exec(ctx,
		`INSERT INTO credentials (account_id, address, password, primary_identity) VALUES ($1, $2, $3, true)`,
		accountID, address, string(hash),
	); err != nil {
		setupDB.Close()
		t.Fatalf("insert credential: %v", err)
	}
	setupDB.Close()

	// Snapshot primary into replica before deleting the account on primary so the
	// replica retains the active pre-deletion row while primary commits revocation.
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		"CREATE DATABASE %s TEMPLATE %s",
		pgx.Identifier{replicaName}.Sanitize(),
		pgx.Identifier{primaryName}.Sanitize(),
	)); err != nil {
		t.Fatalf("CREATE DATABASE %s TEMPLATE %s: %v", replicaName, primaryName, err)
	}

	rdb, err := resilient.NewResilientDatabaseWithOptions(ctx, &config.DatabaseConfig{
		Write: primaryEndpoint,
		Read:  replicaEndpoint,
	}, false, false, false)
	if err != nil {
		t.Fatalf("NewResilientDatabaseWithOptions: %v", err)
	}
	t.Cleanup(rdb.Close)

	return rdb, accountID
}

// TestLMTPProxyRecipientLookupUsesPrimaryDatabase verifies that LMTP proxy active-account
// lookups read from [database.write] (consts.UseMasterDBKey = true) rather than a lagging
// [database.read] replica. Otherwise, once credchanges.Watcher invalidates a deleted
// recipient and advances its cursor past that XID, a subsequent RCPT TO reads the stale
// replica row and refills lookupCache with a fresh positive AuthSuccess entry at the
// post-invalidation generation that Watcher will never evict again.
func TestLMTPProxyRecipientLookupUsesPrimaryDatabase(t *testing.T) {
	const recipient = "revoked-recipient@example.com"
	rdb, accountID := setupSplitLMTPTestDatabase(t, recipient)
	ctx := context.Background()

	lookup404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(lookup404.Close)

	for _, tc := range []struct {
		name         string
		remoteLookup *config.RemoteLookupConfig
	}{
		{
			name:         "direct main database",
			remoteLookup: nil,
		},
		{
			name: "remotelookup 404 with lookup_local_users",
			remoteLookup: &config.RemoteLookupConfig{
				Enabled:          true,
				URL:              lookup404.URL + "?email=$email",
				Timeout:          "2s",
				LookupLocalUsers: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Restore active state on primary before seeding the initial cached entry,
			// then revoke on primary while the replica continues holding deleted_at IS NULL.
			if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(ctx,
				`UPDATE accounts SET deleted_at = NULL WHERE id = $1`, accountID,
			); err != nil {
				t.Fatalf("reset primary account state: %v", err)
			}

			srv, err := New(ctx, rdb, "test-host", ServerOptions{
				Name:           "lmtp-primary-pin-" + tc.name,
				RemoteAddrs:    []string{"127.0.0.1:1"},
				RemotePort:     24,
				ConnectTimeout: time.Second,
				RemoteLookup:   tc.remoteLookup,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { srv.Stop() })

			// 1. Initial lookup succeeds and populates lookupCache.
			if err := recipientError(t, srv, recipient); err != nil {
				t.Fatalf("initial recipient lookup failed: %v", err)
			}
			if cached, found := srv.GetLookupCache().Get(srv.name, recipient); !found || cached.IsNegative {
				t.Fatalf("expected initial positive lookupCache entry, got found=%v entry=%+v", found, cached)
			}

			// 2. Delete the account on primary and run the Watcher invalidation.
			// The read replica still holds deleted_at IS NULL.
			if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(ctx,
				`UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID,
			); err != nil {
				t.Fatalf("delete account on primary: %v", err)
			}
			srv.GetLookupCache().InvalidateAccounts([]int64{accountID})
			if _, found := srv.GetLookupCache().Get(srv.name, recipient); found {
				t.Fatal("expected lookupCache entry to be evicted after InvalidateAccounts")
			}

			// 3. Subsequent RCPT TO must consult primary, reject the deleted account,
			// and never refill lookupCache with a stale positive AuthSuccess entry.
			err = recipientError(t, srv, recipient)
			if !errors.Is(err, server.ErrUserNotFound) {
				t.Fatalf("RCPT TO for primary-deleted account returned %v, want %v (read from stale replica)", err, server.ErrUserNotFound)
			}
			cached, found := srv.GetLookupCache().Get(srv.name, recipient)
			if !found {
				t.Fatal("expected negative lookupCache entry after primary confirmed ErrUserNotFound")
			}
			if !cached.IsNegative || cached.Result != lookupcache.AuthUserNotFound {
				t.Fatalf("lookupCache refilled with non-negative entry %+v from stale replica", cached)
			}
		})
	}
}
