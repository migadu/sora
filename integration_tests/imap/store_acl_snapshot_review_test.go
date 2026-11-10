//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_StoreRestrictedReplacePreservesConcurrentFlags(t *testing.T) {
	for _, conditional := range []bool{false, true} {
		for _, tc := range []struct {
			name, rights, initial, concurrent, desired string
			present, absent                            []string
		}{
			{"protected other flags added", "lrs", "", `+FLAGS (\Flagged Work \Deleted)`, `\Seen`, []string{`\Seen`, `\Flagged`, "Work", `\Deleted`}, nil},
			{"protected seen and deleted added", "lrw", "", `+FLAGS (\Seen \Deleted)`, `\Flagged Fresh`, []string{`\Seen`, `\Deleted`, `\Flagged`, "Fresh"}, nil},
			{"protected flags cleared", "lrs", `\Flagged Work \Deleted`, "FLAGS ()", `\Seen`, []string{`\Seen`}, []string{`\Flagged`, "Work", `\Deleted`}},
		} {
			t.Run(fmt.Sprintf("conditional=%v/%s", conditional, tc.name), func(t *testing.T) {
				common.SkipIfDatabaseUnavailable(t)
				server, owner := common.SetupIMAPServer(t)
				defer server.Close()
				readerEmail, readerPassword := createSecondUser(t, server, "example.com", "store-snapshot")
				writer := dialRawIMAP(t, server.Address)
				writer.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
				writer.do("CREATE Shared/StoreReview")
				writer.do(fmt.Sprintf("SETACL Shared/StoreReview %s %s", readerEmail, tc.rights))
				writer.appendMsg("Shared/StoreReview", "Subject: race\r\n\r\nbody\r\n")
				writer.do("SELECT Shared/StoreReview")
				writer.do("UID STORE 1 FLAGS (" + tc.initial + ")")
				ctx := context.Background()
				ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
				require.NoError(t, err)
				mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "Shared/StoreReview")
				require.NoError(t, err)
				gate := &storeSnapshotGate{mailboxID: mailbox.ID, reached: make(chan struct{}), release: make(chan struct{})}
				defer gate.resume()
				addr := startStoreSnapshotServer(t, server.ResilientDB, gate)
				c := dialRawIMAP(t, addr)
				c.do(fmt.Sprintf("LOGIN %s %s", readerEmail, readerPassword))
				c.do("SELECT Shared/StoreReview (CONDSTORE)")
				gate.armed.Store(true)
				done := make(chan string, 1)
				go func() {
					modifier := ""
					if conditional {
						modifier = "(UNCHANGEDSINCE 18446744073709551615) "
					}
					_, tagged := c.do("UID STORE 1 " + modifier + "FLAGS (" + tc.desired + ")")
					done <- tagged
				}()
				select {
				case <-gate.reached:
				case <-time.After(5 * time.Second):
					t.Fatal("STORE did not reach snapshot gate")
				}
				writer.do("UID STORE 1 " + tc.concurrent)
				gate.resume()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("STORE did not finish")
				}
				lines, _ := writer.do("UID FETCH 1 FLAGS")
				flags := strings.Join(lines, " ")
				for _, flag := range tc.present {
					require.Contains(t, flags, flag, "STORE must retain current protected flags")
				}
				for _, flag := range tc.absent {
					require.NotContains(t, flags, flag, "STORE must not restore cleared protected flags")
				}
			})
		}
	}
}
