package userapiproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"golang.org/x/crypto/bcrypt"
)

func setupSplitUserAPITestDatabase(t *testing.T, address string) (*resilient.ResilientDatabase, int64) {
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
	primaryName := fmt.Sprintf("%s_uapi_pri_%d", base, stamp)
	replicaName := fmt.Sprintf("%s_uapi_rep_%d", base, stamp)

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

// TestUserAPIProxyLocalFallbackUsesPrimaryDatabase verifies that when remotelookup returns
// 404 on a named-pool User API proxy with lookup_local_users enabled, local token ownership
// checks read from [database.write] (consts.UseMasterDBKey = true) rather than a lagging
// [database.read] replica. Otherwise a deleted local account's still-unexpired JWT continues
// to route into the default backend pool (where non-refresh endpoints trust JWT claims).
func TestUserAPIProxyLocalFallbackUsesPrimaryDatabase(t *testing.T) {
	const (
		email  = "revoked@local.example"
		secret = "test-secret-key-at-least-32-bytes!!"
	)
	rdb, accountID := setupSplitUserAPITestDatabase(t, email)
	ctx := context.Background()

	var backendHits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	lookup404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(lookup404.Close)

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	srv, err := New(ctx, rdb, ServerOptions{
		Name:      "uapi-primary-pin",
		Addr:      "127.0.0.1:0",
		JWTSecret: secret,
		Pools: []proxy.PoolSpec{
			{Name: "default", Default: true, Backends: []string{backendAddr}},
		},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              lookup404.URL + "?email=$email",
			Timeout:          "2s",
			LookupLocalUsers: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:     true,
			PositiveTTL: "1m",
			NegativeTTL: "1m",
			MaxSize:     100,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })

	// Ensure maintenance gate is marked loaded so HTTP handler reaches routing.
	maintenance := proxy.NewMaintenance()
	maintenance.Set(nil)
	srv.connManager.SetMaintenance(maintenance)

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email:     email,
		AccountID: accountID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	handler := srv.setupHandler()

	// Control: while the account is active on primary, JWT request routes to backend.
	req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || backendHits.Load() != 1 {
		t.Fatalf("active local account control failed: status=%d backendHits=%d", rec.Code, backendHits.Load())
	}

	// Revoke the account on primary while the read replica still holds deleted_at IS NULL,
	// and invalidate lookupCache just as credchanges.Watcher does.
	if _, err := rdb.GetOperationalDatabase().GetWritePool().Exec(ctx,
		`UPDATE accounts SET deleted_at = now() WHERE id = $1`, accountID,
	); err != nil {
		t.Fatalf("delete account on primary: %v", err)
	}
	srv.GetLookupCache().InvalidateAccounts([]int64{accountID})

	// 1. Authenticated Bearer JWT request (both uncached 404 fallback and cached negative 404).
	for i, phase := range []string{"uncached lookup 404", "negative-cache 404"} {
		if i == 1 {
			// Ensure negative remote-lookup entry is present for the second pass.
			srv.GetLookupCache().Set(srv.name, email, &lookupcache.CacheEntry{
				AccountID:  accountID,
				IsNegative: true,
			})
		}
		req := httptest.NewRequest(http.MethodGet, "/user/mailboxes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK || backendHits.Load() != 1 {
			t.Fatalf("%s: primary-deleted local user's JWT was routed to backend (status=%d backendHits=%d)",
				phase, rec.Code, backendHits.Load())
		}
	}

	// 2. Refresh endpoint carrying the deleted local user's token must also be refused.
	refreshReq := httptest.NewRequest(http.MethodPost, "/user/auth/refresh",
		strings.NewReader(`{"token":"`+token+`"}`))
	refreshRec := httptest.NewRecorder()
	if route, _, err := srv.routeAuthRequest(refreshRec, refreshReq); err == nil {
		t.Fatalf("refresh for primary-deleted local user routed to %+v instead of failing", route)
	}
}
