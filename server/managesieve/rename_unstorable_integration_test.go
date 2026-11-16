//go:build integration

package managesieve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-managesieve/managesieveserver"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// TestManageSieveRenameScriptRefusesUnstorableNewName verifies ManageSieveSession.RenameScript
// maps db.ErrSieveScriptNotStorable to a permanent uncoded validation error (matching PutScript)
// rather than errTryLater (NO (TRYLATER)).
func TestManageSieveRenameScriptRefusesUnstorableNewName(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	dbName := os.Getenv("SORA_TEST_DB_NAME")
	if dbName == "" {
		dbName = "sora_test_db"
	}

	ctx := context.Background()
	rdb, err := resilient.NewResilientDatabase(ctx, &config.DatabaseConfig{
		Write: &config.DatabaseEndpointConfig{
			Hosts: []string{"localhost"},
			Port:  "5432",
			User:  "postgres",
			Name:  dbName,
		},
	}, true, true)
	if err != nil {
		t.Fatalf("NewResilientDatabase: %v", err)
	}
	t.Cleanup(rdb.Close)

	email := fmt.Sprintf("ms-rename-unstorable-%d@example.com", time.Now().UnixNano())
	accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		HashType:  "bcrypt",
		IsPrimary: true,
	})
	if err != nil {
		t.Fatalf("CreateAccountWithRetry: %v", err)
	}
	if _, _, err := rdb.CreateOrUpdateScriptWithRetry(ctx, accountID, "existing", "keep;"); err != nil {
		t.Fatalf("seed script: %v", err)
	}

	addr, err := server.NewAddress(email)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	session := &ManageSieveSession{
		Session:       server.Session{User: server.NewUser(addr, accountID)},
		authenticated: true,
		ctx:           ctx,
		server: &ManageSieveServer{
			rdb:                 rdb,
			supportedExtensions: DefaultEnabledExtensions,
		},
	}
	session.mutexHelper = server.NewMutexTimeoutHelper(&session.mutex, session.ctx, "MANAGESIEVE", func(string, ...any) {})

	for _, newName := range []string{"a\x00b", "\xff", "caf\xc3"} {
		renameErr := session.RenameScript(ctx, "existing", newName)
		var merr *managesieveserver.Error
		if !errors.As(renameErr, &merr) || merr.Code != "" || !strings.HasPrefix(merr.Message, `"Script validation failed:`) {
			t.Errorf("RenameScript(existing, %q) = %#v (%v), want uncoded validation *managesieveserver.Error", newName, renameErr, renameErr)
		}
	}
}
