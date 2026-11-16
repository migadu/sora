//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

func TestBodyFirstContentFieldsDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatal(err)
	}
	addr, up := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{})
	const prefix = `require ["body", "mime", "foreverypart", "extracttext", "variables", "fileinto", "mailbox"]; `
	const bodyRule = `if body :text :contains "needle" {fileinto :create "Body";}`
	const agree = bodyRule + ` if header :mime :anychild :contenttype "Content-Type" "text/plain" {fileinto :create "Mime";} foreverypart {extracttext "x"; if string :contains "${x}" "needle" {fileinto :create "Extract";}}`
	multipart := func(fields, body string) string { return "--B\r\n" + fields + "\r\n" + body + "\r\n--B--" }
	for i, tc := range []struct {
		name, fields, body, rule string
		want                     []string
	}{
		{"part plain first", "Content-Type: multipart/mixed; boundary=B\r\n", multipart("Content-Type: text/plain\r\nContent-Type: application/octet-stream\r\n", "needle words"), agree, []string{"Body", "Extract", "Mime"}},
		{"part binary first", "Content-Type: multipart/mixed; boundary=B\r\n", multipart("Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n", "needle words"), bodyRule, []string{"INBOX"}},
		{"part base64 first", "Content-Type: multipart/mixed; boundary=B\r\n", multipart("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n", "bmVlZGxlIHdvcmRz"), agree, []string{"Body", "Extract", "Mime"}},
		{"root plain first", "Content-Type: text/plain\r\nContent-Type: application/octet-stream\r\n", "needle words", bodyRule, []string{"Body"}},
		{"root binary first", "Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n", "needle words", bodyRule, []string{"INBOX"}},
		{"root charset first", "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Type: text/plain; charset=utf-8\r\n", "caf\xe9", `if body :text :contains "café" {fileinto :create "Body";}`, []string{"Body"}},
		{"empty first type", "Content-Type:\r\nContent-Type: application/octet-stream\r\n", "needle words", bodyRule, []string{"Body"}},
		{"empty first encoding", "Content-Type: text/plain\r\nContent-Transfer-Encoding:\r\nContent-Transfer-Encoding: base64\r\n", "bmVlZGxlIHdvcmRz", `if body :text :contains "bmVlZGxlIHdvcmRz" {fileinto :create "Body";} if body :text :contains "needle" {fileinto :create "Wrong";}`, []string{"Body"}},
		{"unknown first encoding", "Content-Type: text/plain\r\nContent-Transfer-Encoding: x-unknown\r\nContent-Transfer-Encoding: 7bit\r\n", "needle words", bodyRule, []string{"INBOX"}},
		{"absent content fields", "", "needle words", bodyRule, []string{"Body"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setActiveSieveScript(t, rdb, id, prefix+tc.rule)
			marker := fmt.Sprintf("first-fields-%d-%d", time.Now().UnixNano(), i)
			msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\nMIME-Version: 1.0\r\n" + tc.fields + "\r\n" + tc.body
			if resp := deliverLMTPRaw(t, addr, "sender@example.com", account.Email, msg); !strings.HasPrefix(resp, "250") {
				t.Fatalf("not accepted: %s", resp)
			}
			var names []string
			var hash string
			err := rdb.QueryRowWithRetry(ctx, `SELECT array_agg(mb.name ORDER BY mb.name),MIN(m.content_hash) FROM messages m JOIN mailboxes mb ON mb.id=m.mailbox_id WHERE m.account_id=$1 AND m.subject=$2 AND m.expunged_at IS NULL`, id, marker).Scan(&names, &hash)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(names, tc.want) {
				t.Errorf("stored copies %v, want %v", names, tc.want)
			}
			raw, err := os.ReadFile(up.FilePath(hash, id))
			if err != nil {
				t.Fatal(err)
			}
			_, body, ok := strings.Cut(string(raw), "\r\n\r\n")
			if !ok {
				t.Fatal("stored bytes lack header boundary")
			}
			if body != tc.body+"\r\n" {
				t.Errorf("stored MIME body changed: got %q want %q", body, tc.body+"\r\n")
			}
		})
	}
}
