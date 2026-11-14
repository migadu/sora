//go:build integration

package resilient_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/resilient"
)

// A request the database layer rejects is not a database failure. On a node whose write
// pool sees no other traffic, three rejected writes in a row (six breaker requests, three
// failures) used to open the write circuit breaker, refusing every write on the node —
// deliveries included — until it half-opened 30s later (issue #386).
func TestRejectedWritesKeepWriteBreakerClosed(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	// Fixtures go through their own ResilientDatabase so their successful writes do not
	// dilute the failure ratio of the breaker under test.
	setup := common.SetupTestDatabase(t)
	live := common.CreateTestAccount(t, setup)
	liveID, err := setup.GetAccountIDByAddressWithRetry(ctx, live.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	deleted := common.CreateTestAccount(t, setup)
	if err := setup.DeleteAccountWithRetry(ctx, deleted.Email); err != nil {
		t.Fatalf("soft-delete fixture: %v", err)
	}

	tests := []struct {
		name  string
		write func(rdb *resilient.ResilientDatabase) error
		want  error // nil: any rejection
	}{
		{"delete the primary credential", func(rdb *resilient.ResilientDatabase) error {
			return rdb.DeleteCredentialWithRetry(ctx, live.Email)
		}, db.ErrCannotDeletePrimaryCredential},
		{"delete an already deleted account", func(rdb *resilient.ResilientDatabase) error {
			return rdb.DeleteAccountWithRetry(ctx, deleted.Email)
		}, db.ErrAccountAlreadyDeleted},
		{"restore an account that is not deleted", func(rdb *resilient.ResilientDatabase) error {
			return rdb.RestoreAccountWithRetry(ctx, live.Email)
		}, db.ErrAccountNotDeleted},
		{"add a credential with an invalid address", func(rdb *resilient.ResilientDatabase) error {
			return rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{AccountID: liveID, NewEmail: "not-an-address", NewPassword: "pw-123456", NewHashType: "bcrypt"})
		}, nil},
		{"add a credential with an unknown hash type", func(rdb *resilient.ResilientDatabase) error {
			return rdb.AddCredentialWithRetry(ctx, db.AddCredentialRequest{AccountID: liveID, NewEmail: uniqueAddress("alias"), NewPassword: "pw-123456", NewHashType: "no-such-hash"})
		}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdb := common.SetupTestDatabase(t)

			for i := 1; i <= 4; i++ {
				err := tt.write(rdb)
				switch {
				case err == nil:
					t.Fatalf("attempt %d: rejected write succeeded", i)
				case errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen):
					t.Errorf("attempt %d: %v", i, err)
				case tt.want != nil && !errors.Is(err, tt.want):
					t.Errorf("attempt %d: got %v, want %v", i, err, tt.want)
				}
			}
			if state := rdb.GetWriteBreakerState(); state != circuitbreaker.StateClosed {
				t.Errorf("write breaker %s after rejected writes, want %s", state, circuitbreaker.StateClosed)
			}

			if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{Email: uniqueAddress("after-rejections"), Password: "pw-123456", HashType: "bcrypt", IsPrimary: true}); err != nil {
				t.Errorf("valid write after rejected writes: %v", err)
			}
		})
	}
}

func uniqueAddress(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}
