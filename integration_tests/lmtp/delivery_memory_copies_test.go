//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/sieveengine"
)

// TestLMTP_DeliveryMemoryChargesTraceAndEditheaderCopies (#2116): the copy the
// Received/Delivered-To prepend makes and the copy a Sieve editheader rewrite
// makes are charged to the delivery memory budget before they are allocated,
// like the DATA buffer. A ~28 KiB message charges 32 KiB for its DATA buffer,
// and about 28 KiB more for each of those copies.
func TestLMTP_DeliveryMemoryChargesTraceAndEditheaderCopies(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account := common.SetupIMAPServer(t)
	t.Cleanup(imapSrv.Close)
	rdb := imapSrv.ResilientDB
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("GetAccountIDByAddress: %v", err)
	}
	if _, err := rdb.ExecWithRetry(context.Background(), "DELETE FROM sieve_scripts WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear sieve: %v", err)
	}

	message := func(subject, body string) string {
		return fmt.Sprintf("From: sender@example.org\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", account.Email, subject, body)
	}
	small := message("small", "hello\r\n")
	sized := message("sized", strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", (28<<10)/64))
	if len(sized) < 27<<10 || len(sized) > 29<<10 {
		t.Fatalf("fixture is %d bytes, want about 28 KiB", len(sized))
	}
	deliver := func(t *testing.T, addr, name, msg, want string) {
		t.Helper()
		if reply := deliverLMTPRaw(t, addr, "sender@example.org", account.Email, msg); !strings.HasPrefix(reply, want) {
			t.Errorf("%s: reply %q, want %s", name, reply, want)
		}
	}

	t.Run("trace header prepend copy", func(t *testing.T) {
		// Fits the 32 KiB DATA buffer, not the buffer plus the stamped copy.
		addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{DeliveryMemoryLimit: 48 << 10})
		deliver(t, addr, "small message", small, "250")
		deliver(t, addr, "DATA fits, the stamped copy does not", sized, "452 4.3.1")
		deliver(t, addr, "small message after the refusal", small, "250")
	})

	t.Run("editheader rewrite copy", func(t *testing.T) {
		// Fits the DATA buffer and the stamped copy, not a third copy.
		addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
			DeliveryMemoryLimit: 72 << 10,
			SieveExtensions:     append(append([]string{}, sieveengine.DefaultSieveExtensions...), "editheader"),
		})
		deliver(t, addr, "no script: DATA and stamped copy fit", sized, "250")
		setActiveSieveScript(t, rdb, accountID, "require \"editheader\";\r\naddheader \"X-Edited\" \"yes\";\r\nkeep;\r\n")
		t.Cleanup(func() {
			_, _ = rdb.ExecWithRetry(context.Background(), "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
		})
		deliver(t, addr, "editheader copy does not fit", sized, "452 4.3.1")
		deliver(t, addr, "small message with editheader", small, "250")
	})
}
