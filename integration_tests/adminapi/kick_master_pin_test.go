//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
)

// A kick must resolve every address on the primary: a lagging read pool can omit
// a newly added alias whose remote-lookup session already exists.
func TestAdminAPI_Kick_ResolvesRemoteIDsOnPrimary(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name},
	}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rdb.Close)
	primary := fmt.Sprintf("kick-primary-%d@example.com", time.Now().UnixNano())
	alias := "alias-" + primary
	id, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{Email: primary, Password: "primary-password-1", HashType: "bcrypt", IsPrimary: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{AccountID: id, NewEmail: alias, NewPassword: "alias-password-2", NewHashType: "bcrypt"}); err != nil {
		t.Fatal(err)
	}

	database := rdb.GetDatabase()
	schema := pgx.Identifier{fmt.Sprintf("kick_replica_%d", time.Now().UnixNano())}.Sanitize()
	if _, err := database.WritePool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.WritePool.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE") })
	if _, err := database.WritePool.Exec(ctx, "CREATE TABLE "+schema+".credentials AS SELECT * FROM public.credentials WHERE address <> $1", alias); err != nil {
		t.Fatal(err)
	}
	replicaConfig := database.WritePool.Config().Copy()
	replicaConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+schema+", public")
		return err
	}
	replica, err := pgxpool.NewWithConfig(ctx, replicaConfig)
	if err != nil {
		t.Fatal(err)
	}
	originalRead := database.ReadPool
	t.Cleanup(originalRead.Close)
	database.ReadPool = replica // set before the HTTP server starts; health polling is off
	_, stale, err := rdb.GetAccountAddressesWithRetry(ctx, primary)
	if err != nil || slices.Contains(stale, alias) {
		t.Fatalf("lag fixture: addresses %v, err %v; want the alias absent", stale, err)
	}

	s := setupRemoteLookupProxyStack(t, rdb)
	kicked := s.session(t, alias)
	s.kick(t, primary, http.StatusOK)
	if !ended(kicked) {
		t.Fatal("successful kick resolved the lagging read pool and left the alias session open")
	}
}
