//go:build integration

package resilient

import (
	"context"
	"errors"
	"testing"

	"github.com/migadu/sora/consts"
)

// ManageSieve SETACTIVE and the User API activate route look the script up first and
// then activate it by ID. When the script was deleted in between, the activation
// deactivated the active script, activated nothing and answered success, so the
// account's filtering stopped. It must answer not found and roll the deactivation back.
func TestSetScriptActive_DeletedScriptKeepsActiveScript(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	primary := newTestPool(t, cfg, nil)
	rd := newTestResilientDatabase(cfg, primary)
	accountID := newSieveTestAccount(t, primary)

	active, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "active", "keep;")
	if err != nil {
		t.Fatalf("PUT active: %v", err)
	}
	if err := rd.SetScriptActiveWithRetry(ctx, active.ID, accountID, true); err != nil {
		t.Fatalf("activate: %v", err)
	}
	deleted, _, err := rd.CreateOrUpdateScriptWithRetry(ctx, accountID, "deleted", "keep;")
	if err != nil {
		t.Fatalf("PUT deleted: %v", err)
	}
	if err := rd.DeleteScriptWithRetry(ctx, "deleted", accountID); err != nil {
		t.Fatalf("DELETE: %v", err)
	}

	for _, activate := range []bool{true, false} {
		if err := rd.SetScriptActiveWithRetry(ctx, deleted.ID, accountID, activate); !errors.Is(err, consts.ErrDBNotFound) {
			t.Errorf("set active=%v on a deleted script: got %v, want %v", activate, err, consts.ErrDBNotFound)
		}
		if _, isActive := primaryScriptState(t, primary, accountID, "active"); !isActive {
			t.Fatalf("set active=%v on a deleted script deactivated the active script", activate)
		}
	}
}
