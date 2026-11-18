//go:build integration

package lmtp_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_DeliveryMemoryLimit (#2111): the DATA buffer and the base64 copy of
// its NUL-bearing parts are charged to the server's delivery memory budget
// (limits.delivery_memory_limit) before they are allocated. A delivery that does
// not fit is refused as temporary, 452 4.3.1, so the MTA retries it; whatever it
// had charged is released, and a delivery that fits is accepted afterwards.
func TestLMTP_DeliveryMemoryLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account := common.SetupIMAPServer(t)
	t.Cleanup(imapSrv.Close)

	const budget = 64 << 10
	addr, _ := startTestLMTPServerWithOptions(t, imapSrv.ResilientDB, lmtpserver.LMTPServerOptions{DeliveryMemoryLimit: budget})

	message := func(subject, header, body string) string {
		return fmt.Sprintf("From: sender@example.org\r\nTo: %s\r\nSubject: %s\r\n%s\r\n%s", account.Email, subject, header, body)
	}
	small := message("small", "", "hello\r\n")
	// Twice the budget: the DATA buffer alone cannot fit.
	large := message("large", "", strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop\r\n", 2*budget/64))
	// Its DATA buffer fits the budget; the buffer plus the base64 copy of its
	// NUL-bearing part (about 4/3 of it) does not.
	nul := message("nul", "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n",
		strings.Repeat("\x00\xe4abcdefghijklmnopqrstuvwxyz\r\n", (28<<10)/30))
	if len(nul) >= 32<<10 || len(large) <= budget {
		t.Fatalf("fixtures do not straddle the budget: nul %d, large %d", len(nul), len(large))
	}

	for _, step := range []struct {
		name, msg, want string
	}{
		{"small message fits", small, "250"},
		{"message larger than the budget", large, "452 4.3.1"},
		{"DATA fits but its encoded copy does not", nul, "452 4.3.1"},
		{"small message fits after the refusals", small, "250"},
	} {
		if reply := deliverLMTPRaw(t, addr, "sender@example.org", account.Email, step.msg); !strings.HasPrefix(reply, step.want) {
			t.Errorf("%s: reply %q, want %s", step.name, reply, step.want)
		}
	}
}
