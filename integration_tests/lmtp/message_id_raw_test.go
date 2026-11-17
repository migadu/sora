//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

func TestLMTP_MessageIDRawUsesFinalEditedHeaders(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{})
	setActiveSieveScript(t, rdb, id, `require ["editheader"]; deleteheader "Message-ID"; addheader "Message-ID" "(FinalNeedle) <edited@example.com>"; keep;`)
	msg := fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nMessage-ID: (OriginalNeedle) <original@example.com>\r\nSubject: final raw id\r\n\r\nbody\r\n", account.Email)
	if response := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg); !strings.HasPrefix(response, "250") {
		t.Fatalf("not accepted: %s", response)
	}
	var raw, normalized string
	if err := rdb.QueryRowWithRetry(ctx, `SELECT message_id_raw,message_id FROM messages WHERE account_id=$1 AND expunged_at IS NULL`, id).Scan(&raw, &normalized); err != nil {
		t.Fatal(err)
	}
	if raw != "(FinalNeedle) <edited@example.com>" || normalized != "edited@example.com" {
		t.Fatalf("stored raw/normalized Message-ID = %q/%q, want final edited headers", raw, normalized)
	}
}
