//go:build integration

package resilient_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
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

// The database failing inside a write still counts when the db layer reports it through
// one of its own sentinels (InsertMessage's consts.ErrDBUpdateFailed and the like): the
// breakers go by the kind of error, so a sentinel that dropped the database's error would
// read as an answer from a working database, and deliveries against a failing database
// would never open the write breaker. Here InsertMessage's highest_uid UPDATE waits on a
// row lock and its backend is terminated (57P01) while it waits.
func TestDatabaseFailureBehindDBSentinelCountsAgainstWriteBreaker(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	setup := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, setup)
	accountID, err := setup.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	inbox, err := setup.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("INBOX: %v", err)
	}

	pool := setup.GetDatabase().WritePool
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocker: %v", err)
	}
	defer blocker.Rollback(context.Background())
	var blockerPID uint32
	if err := blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatalf("blocker pid: %v", err)
	}
	if _, err := blocker.Exec(ctx, "SELECT id FROM mailboxes WHERE id = $1 FOR UPDATE", inbox.ID); err != nil {
		t.Fatalf("lock INBOX row: %v", err)
	}

	rdb := common.SetupTestDatabase(t)
	for i := 1; i <= 3; i++ {
		now := time.Now()
		opts := &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     inbox.ID,
			MailboxName:   "INBOX",
			S3Domain:      "example.com",
			S3Localpart:   "breaker",
			ContentHash:   fmt.Sprintf("breaker-hash-%d-%d", i, now.UnixNano()),
			MessageID:     fmt.Sprintf("<breaker-%d-%d@example.com>", i, now.UnixNano()),
			InternalDate:  now,
			Size:          128,
			Subject:       "breaker",
			PlaintextBody: "body",
			SentDate:      now,
			InReplyTo:     []string{},
		}
		upload := db.PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash, InstanceID: "test", Size: 128}

		done := make(chan error, 1)
		go func() {
			_, _, err := rdb.InsertMessageWithRetry(ctx, opts, upload)
			done <- err
		}()

		// Terminate the insert's backend once it waits on the blocker's row lock.
		var waiterPID uint32
		deadline := time.Now().Add(10 * time.Second)
		for {
			err := pool.QueryRow(ctx, "SELECT pid FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))", blockerPID).Scan(&waiterPID)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("attempt %d: insert never waited on the row lock: %v", i, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, err := pool.Exec(ctx, "SELECT pg_terminate_backend($1)", waiterPID); err != nil {
			t.Fatalf("attempt %d: terminate backend %d: %v", i, waiterPID, err)
		}

		err := <-done
		if err == nil {
			t.Fatalf("attempt %d: insert succeeded on a terminated connection", i)
		}
		if !errors.Is(err, consts.ErrDBUpdateFailed) {
			t.Errorf("attempt %d: got %v, want %v", i, err, consts.ErrDBUpdateFailed)
		}
	}

	if state := rdb.GetWriteBreakerState(); state != circuitbreaker.StateOpen {
		t.Errorf("write breaker %s after three writes failed by the database, want %s", state, circuitbreaker.StateOpen)
	}
}

func uniqueAddress(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}
