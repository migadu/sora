//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
)

func TestSieveCommands(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	// Setup test database
	rdb := setupSieveTestDatabase(t)
	defer rdb.Close()

	// Create test account
	timestamp := time.Now().UnixNano()
	testEmail := fmt.Sprintf("sieve-test-%d@sieve-test-%d.com", timestamp, timestamp)
	accountID := createSieveTestAccount(t, rdb, testEmail, "password123")

	ctx := context.Background()

	t.Run("CreateOrUpdateScript", func(t *testing.T) {
		// Put/Create a script
		scriptName := "myscript"
		content := "keep;"
		_, err := rdb.CreateOrUpdateScriptWithRetry(ctx, accountID, scriptName, content)
		if err != nil {
			t.Fatalf("Failed to create script: %v", err)
		}

		// Verify list contains the script
		scripts, err := rdb.GetUserScriptsWithRetry(ctx, accountID)
		if err != nil {
			t.Fatalf("Failed to list scripts: %v", err)
		}
		if len(scripts) != 1 {
			t.Fatalf("Expected 1 script, got %d", len(scripts))
		}
		if scripts[0].Name != scriptName {
			t.Errorf("Expected script name '%s', got '%s'", scriptName, scripts[0].Name)
		}
		if scripts[0].Active {
			t.Error("Expected newly created script to be inactive by default")
		}

		// Update script
		contentUpdated := "discard;"
		_, err = rdb.CreateOrUpdateScriptWithRetry(ctx, accountID, scriptName, contentUpdated)
		if err != nil {
			t.Fatalf("Failed to update script: %v", err)
		}

		// Verify update worked
		script, err := rdb.GetScriptByNameWithRetry(ctx, scriptName, accountID)
		if err != nil {
			t.Fatalf("Failed to get script: %v", err)
		}
		if script.Script != contentUpdated {
			t.Errorf("Expected script content '%s', got '%s'", contentUpdated, script.Script)
		}
	})

	t.Run("ActivateScript", func(t *testing.T) {
		scriptName := "myscript"

		// Activate
		err := rdb.ActivateScriptWithRetry(ctx, scriptName, accountID)
		if err != nil {
			t.Fatalf("Failed to activate script: %v", err)
		}

		// Verify active status
		script, err := rdb.GetScriptByNameWithRetry(ctx, scriptName, accountID)
		if err != nil {
			t.Fatalf("Failed to get script: %v", err)
		}
		if !script.Active {
			t.Error("Expected script to be active")
		}

		// Get active script
		active, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
		if err != nil {
			t.Fatalf("Failed to get active script: %v", err)
		}
		if active.Name != scriptName {
			t.Errorf("Expected active script name '%s', got '%s'", scriptName, active.Name)
		}
	})

	t.Run("DeactivateAll", func(t *testing.T) {
		// Deactivate
		err := rdb.DeactivateAllScriptsWithRetry(ctx, accountID)
		if err != nil {
			t.Fatalf("Failed to deactivate scripts: %v", err)
		}

		// Verify active script is nil/not found
		_, err = rdb.GetActiveScriptWithRetry(ctx, accountID)
		if err == nil {
			t.Fatal("Expected no active script to be found")
		}
	})

	t.Run("RenameScript", func(t *testing.T) {
		oldName := "myscript"
		newName := "renamedscript"

		err := rdb.RenameScriptWithRetry(ctx, accountID, oldName, newName)
		if err != nil {
			t.Fatalf("Failed to rename script: %v", err)
		}

		// Verify old script not found
		_, err = rdb.GetScriptByNameWithRetry(ctx, oldName, accountID)
		if err == nil {
			t.Fatal("Expected old script not to be found")
		}

		// Verify new script found
		script, err := rdb.GetScriptByNameWithRetry(ctx, newName, accountID)
		if err != nil {
			t.Fatalf("Failed to get renamed script: %v", err)
		}
		if script.Name != newName {
			t.Errorf("Expected renamed script name '%s', got '%s'", newName, script.Name)
		}
	})

	t.Run("DeleteScript", func(t *testing.T) {
		scriptName := "renamedscript"

		err := rdb.DeleteScriptWithRetry(ctx, scriptName, accountID)
		if err != nil {
			t.Fatalf("Failed to delete script: %v", err)
		}

		// Verify script not found
		_, err = rdb.GetScriptByNameWithRetry(ctx, scriptName, accountID)
		if err == nil {
			t.Fatal("Expected script to be deleted")
		}
	})
}

func setupSieveTestDatabase(t *testing.T) *resilient.ResilientDatabase {
	t.Helper()

	var cfg AdminConfig
	if _, err := toml.DecodeFile("../../config-test.toml", &cfg); err != nil {
		t.Fatalf("Failed to load test configuration: %v", err)
	}

	ctx := context.Background()
	rdb, err := resilient.NewResilientDatabase(ctx, &cfg.Database, false, true)
	if err != nil {
		t.Fatalf("Failed to create resilient database: %v", err)
	}

	return rdb
}

func createSieveTestAccount(t *testing.T, rdb *resilient.ResilientDatabase, email, password string) int64 {
	t.Helper()

	ctx := context.Background()
	req := db.CreateAccountRequest{
		Email:     email,
		Password:  password,
		HashType:  "bcrypt",
		IsPrimary: true,
	}

	accountID, err := rdb.CreateAccountWithRetry(ctx, req)
	if err != nil {
		t.Fatalf("Failed to create test account: %v", err)
	}

	return accountID
}
