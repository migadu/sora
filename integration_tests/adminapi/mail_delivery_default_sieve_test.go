//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// TestAdminAPI_DeliverMail_RunsDefaultSieveAndCreate is issue #325: a message
// delivered through /admin/mail/deliver must be filtered as the same message over
// LMTP is. The built-in default script runs first (X-Spam: Yes into Junk, a
// +detail recipient into the detail folder), the user's script then overrides or
// keeps its filing, and fileinto :create creates a missing folder (RFC 5490 §3.2:
// ":create" "instructs the Sieve interpreter to create the specified mailbox, if
// needed, before attempting to deliver the message into the specified mailbox").
func TestAdminAPI_DeliverMail_RunsDefaultSieveAndCreate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := setupHTTPAPIServerWithUploader(t)
	defer server.Close()
	ctx := context.Background()

	cases := []struct {
		name   string
		detail string   // recipient +detail, "" for none
		header string   // an extra header line
		script []string // the user's active script, nil for none
		want   string   // the mailbox the message must be stored in
	}{
		{name: "default files spam", header: "X-Spam: Yes", want: "Junk"},
		{name: "default files by detail", detail: "receipts", want: "receipts"},
		{name: "user keep leaves the default filing", header: "X-Spam: Yes", script: []string{`keep;`}, want: "Junk"},
		{
			name:   "user fileinto overrides the default",
			header: "X-Spam: Yes",
			script: []string{`require ["fileinto"];`, `fileinto "INBOX";`},
			want:   "INBOX",
		},
		{
			name:   "user fileinto :create",
			script: []string{`require ["fileinto", "mailbox"];`, `fileinto :create "Receipts/2026";`},
			want:   "Receipts/2026",
		},
		// A name the mailstore refuses can never be created: RFC 5490 §3.2 makes
		// that an error, and RFC 5228 §2.10.6 an implicit keep, not a delivery
		// failure the caller would retry forever. Through the default script any
		// sender can pick such a name with the +detail.
		{
			name:   "user fileinto :create of an invalid name keeps",
			script: []string{`require ["fileinto", "mailbox"];`, `fileinto :create "Bad/./Name";`},
			want:   "INBOX",
		},
		{name: "default fileinto :create of an invalid detail keeps", detail: "a/./b", want: "INBOX"},
		// Issue #457: an empty hierarchy level is refused as a "." level is, and a
		// trailing delimiter is no part of the name (RFC 3501 §6.3.3: "the name
		// created is without the trailing hierarchy delimiter"), so neither makes a
		// mailbox with an empty level ("x/", "Trail/").
		{
			name:   "user fileinto :create of a name with an empty level keeps",
			script: []string{`require ["fileinto", "mailbox"];`, `fileinto :create "x//y";`},
			want:   "INBOX",
		},
		{name: "default fileinto :create of a detail with an empty level keeps", detail: "x//y", want: "INBOX"},
		{
			name:   "user fileinto :create of a name with a trailing delimiter",
			script: []string{`require ["fileinto", "mailbox"];`, `fileinto :create "Trail/";`},
			want:   "Trail",
		},
		{name: "default fileinto :create of a detail with a trailing delimiter", detail: "foo/", want: "foo"},
		// A NUL or a byte that is not UTF-8 cannot be stored in a PostgreSQL text
		// value; the lookup of such a name failed the delivery, with :create or
		// without.
		{
			name:   "user fileinto :create of a name with a NUL keeps",
			script: []string{`require ["fileinto", "mailbox", "encoded-character"];`, `fileinto :create "a${hex:00}b";`},
			want:   "INBOX",
		},
		{
			name:   "user fileinto :create of a name that is not UTF-8 keeps",
			script: []string{`require ["fileinto", "mailbox", "encoded-character"];`, `fileinto :create "a${hex:ff}b";`},
			want:   "INBOX",
		},
		{
			name:   "user fileinto of a name that is not UTF-8 keeps",
			script: []string{`require ["fileinto", "encoded-character"];`, `fileinto "a${hex:ff}b";`},
			want:   "INBOX",
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			local := fmt.Sprintf("apidefault-%d-%d", i, time.Now().UnixNano())
			email := local + "@example.com"
			createDeliveryAccount(t, server, email)
			accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}
			if tc.script != nil {
				// The account address in a comment keeps the script text unique, so a
				// compile cached by another test cannot serve it.
				script := strings.Join(append([]string{"# " + email}, tc.script...), "\r\n") + "\r\n"
				sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
				if err != nil {
					t.Fatalf("create sieve script: %v", err)
				}
				if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
					t.Fatalf("activate sieve script: %v", err)
				}
			}

			rcpt := email
			if tc.detail != "" {
				rcpt = local + "+" + tc.detail + "@example.com"
			}
			subject := fmt.Sprintf("default-sieve-%d", time.Now().UnixNano())
			lines := []string{"From: sender@example.com", "To: " + rcpt, "Subject: " + subject,
				"Message-ID: <" + subject + "@example.com>"}
			if tc.header != "" {
				lines = append(lines, tc.header)
			}
			msg := strings.Join(append(lines, "", "Body via API.", ""), "\r\n")
			resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
				"recipients": []string{rcpt},
				"from":       "sender@example.com",
				"message":    msg,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
			}

			var mailbox string
			if err := server.rdb.QueryRowWithRetry(ctx, `
				SELECT mb.name FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL`,
				accountID, subject).Scan(&mailbox); err != nil {
				t.Fatalf("find delivered message: %v", err)
			}
			if mailbox != tc.want {
				t.Errorf("stored in %s, want %s", mailbox, tc.want)
			}

			mailboxes, err := server.rdb.GetMailboxesWithRetry(ctx, accountID, false)
			if err != nil {
				t.Fatalf("list mailboxes: %v", err)
			}
			for _, mb := range mailboxes {
				if mb.Name == "" || strings.HasPrefix(mb.Name, "/") || strings.HasSuffix(mb.Name, "/") || strings.Contains(mb.Name, "//") {
					t.Errorf("created mailbox %q with an empty hierarchy level", mb.Name)
				}
			}
		})
	}
}

// TestAdminAPI_DeliverMail_SieveCreateNotInSharedNamespace: fileinto :create of a
// missing name in the [shared_mailboxes] namespace keeps the message in INBOX and
// makes no personal mailbox there (the LMTP side is #323); such a namesake would
// shadow a shared mailbox of that name in every later lookup by this user.
func TestAdminAPI_DeliverMail_SieveCreateNotInSharedNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.SharedMailboxes = config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"}
	})
	defer server.Close()
	ctx := context.Background()

	email := fmt.Sprintf("apicreateshared-%d@example.com", time.Now().UnixNano())
	createDeliveryAccount(t, server, email)
	accountID, err := server.rdb.GetAccountIDByAddressWithRetry(ctx, email)
	if err != nil {
		t.Fatalf("lookup account: %v", err)
	}
	missing := fmt.Sprintf("Shared/Missing-%d", time.Now().UnixNano())
	script := "# " + email + "\r\nrequire [\"fileinto\", \"mailbox\"];\r\nfileinto :create \"" + missing + "\";\r\n"
	sc, err := server.rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	if err != nil {
		t.Fatalf("create sieve script: %v", err)
	}
	if err := server.rdb.SetScriptActiveWithRetry(ctx, sc.ID, accountID, true); err != nil {
		t.Fatalf("activate sieve script: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: " + email + "\r\nSubject: create-shared\r\n\r\nBody via API.\r\n"
	resp, body := server.makeRequest(t, "POST", "/admin/mail/deliver", map[string]any{
		"recipients": []string{email},
		"message":    msg,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliver: %d %s", resp.StatusCode, string(body))
	}

	var mailbox string
	if err := server.rdb.QueryRowWithRetry(ctx, `
		SELECT mb.name FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE m.account_id = $1 AND m.subject = 'create-shared' AND m.expunged_at IS NULL`,
		accountID).Scan(&mailbox); err != nil {
		t.Fatalf("find delivered message: %v", err)
	}
	if mailbox != "INBOX" {
		t.Errorf("stored in %s, want INBOX", mailbox)
	}
	var personal int
	if err := server.rdb.QueryRowWithRetry(ctx, `
		SELECT COUNT(*) FROM mailboxes
		WHERE account_id = $1 AND LOWER(name) IN ('shared', LOWER($2)) AND deleted_at IS NULL`,
		accountID, missing).Scan(&personal); err != nil {
		t.Fatalf("count mailboxes: %v", err)
	}
	if personal != 0 {
		t.Errorf("fileinto :create made %d personal mailboxes in the shared namespace", personal)
	}
}
