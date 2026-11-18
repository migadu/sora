//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_NULPartRedirectKeepsRawDeliveryIdentity: with a redirect-only Sieve
// script, a binary message M and a separate submission of EncodeNULParts(M) are
// two submissions and must queue two redirects, although both are stored alike.
// The retry identity is the bytes as received; each submission's own retry (the
// same bytes again) is still absorbed.
func TestLMTP_NULPartRedirectKeepsRawDeliveryIdentity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account := common.SetupIMAPServer(t)
	t.Cleanup(imapSrv.Close)
	rdb := imapSrv.ResilientDB
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("GetAccountIDByAddress: %v", err)
	}
	setActiveSieveScript(t, rdb, accountID, `redirect "fwd@example.org";`+"\r\n")
	queue := &captureRelayQueue{}
	addr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{RelayQueue: queue})

	raw := []byte(fmt.Sprintf("From: sender@example.org\r\nTo: %s\r\nMessage-ID: <%d.nul@example.org>\r\n", account.Email, time.Now().UnixNano()) +
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		"raw\x00body\r\n--b--\r\n")
	encoded, changed, _ := helpers.EncodeNULParts(raw, nil)
	if !changed {
		t.Fatal("fixture must need re-encoding")
	}

	for n, submission := range []struct {
		name  string
		bytes []byte
	}{
		{"binary submission", raw},
		{"already encoded submission", encoded},
	} {
		for attempt := 1; attempt <= 2; attempt++ {
			if reply := deliverLMTPRaw(t, addr, "sender@example.org", account.Email, string(submission.bytes)); !strings.HasPrefix(reply, "250") {
				t.Fatalf("%s, attempt %d: %s", submission.name, attempt, reply)
			}
			if got, want := len(queue.relayedTo()), n+1; got != want {
				t.Fatalf("%s, attempt %d: %d redirects queued, want %d (distinct submissions must not collapse, a retry must not redirect again)",
					submission.name, attempt, got, want)
			}
		}
	}
}
