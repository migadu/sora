//go:build integration

package lmtp_test

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

func TestLMTP_FTSKeepsTextBesideSkippedPart(t *testing.T) {
	testLMTPFTSBody(t, "", "hello words")
}

func TestLMTP_FTSRelatedContentIDCFWS(t *testing.T) {
	testLMTPFTSBody(t, "Content-Type: multipart/related; boundary=related; start=\"<root@example.com>\"\r\n\r\n--related\r\nContent-Type: text/plain\r\nContent-ID: <resource@example.com>\r\n\r\nauxiliarywords\r\n--related\r\nContent-Type: text/plain\r\nContent-ID: (selected) <root@example.com> (root)\r\n\r\nrootwords\r\n--related--\r\n", "rootwords")
}

func testLMTPFTSBody(t *testing.T, mimeBody, want string) {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	id, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatal(err)
	}
	addr := startTestLMTPServer(t, rdb)
	if mimeBody == "" {
		mimeBody = "Content-Type: multipart/mixed; boundary=b1\r\n\r\n--b1\r\nContent-Type: image/png; name=a b.png\r\nContent-Disposition: inline\r\n\r\nPNG\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello words\r\n--b1--\r\n"
	}
	raw := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: lmtp parity\r\nMIME-Version: 1.0\r\n" + mimeBody
	if reply := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, raw); !strings.HasPrefix(reply, "250") {
		t.Fatalf("LMTP failed: %s", reply)
	}
	var text string
	var indexed bool
	if err := rdb.QueryRowWithRetry(context.Background(), `SELECT COALESCE(f.text_body,''),COALESCE(f.text_body_tsv @@ plainto_tsquery('simple',$2),false) FROM messages m LEFT JOIN messages_fts_v2 f ON f.account_id=m.account_id AND f.content_hash=m.content_hash WHERE m.account_id=$1 AND m.expunged_at IS NULL`, id, want).Scan(&text, &indexed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, want) && !indexed {
		t.Fatalf("LMTP lost partial FTS text: %q", text)
	}
}
