//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTP_SieveFileIntoCreateNames is issue #457: the name a Sieve fileinto
// :create makes is checked as IMAP CREATE checks it.
//
// A name with a ".", ".." or empty hierarchy level is never created, and that is
// no delivery failure: RFC 5490 §3.2 says "Failure to create the specified mailbox
// is considered to be an error", and RFC 5228 §2.10.6 that on an error
// implementations MUST "do an implicit keep". It was answered 451 on every
// attempt, so the message sat in the sender's queue until it bounced.
//
// A trailing delimiter is no part of the name (RFC 3501 §6.3.3: "the name created
// is without the trailing hierarchy delimiter"); it made a second mailbox "Foo/"
// next to "Foo".
//
// The built-in default script files a +detail recipient with fileinto :create, so
// any sender picks these names through the recipient address.
func TestLMTP_SieveFileIntoCreateNames(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)

	up, err := uploader.NewWithS3Interface(
		t.TempDir(), 10, 2, 3, time.Second, 0, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("create uploader: %v", err)
	}
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(ctx, "test-lmtp", "localhost", lmtpAddr,
		&storage.S3Storage{}, rdb, up, lmtpserver.LMTPServerOptions{})
	if err != nil {
		t.Fatalf("create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()
	errChan := make(chan error, 1)
	go lmtpSrv.Start(errChan)
	waitForLMTPListener(t, lmtpAddr, errChan)

	cases := []struct {
		name   string
		detail string // recipient +detail, filed by the default script
		script string // the user's active script, "" for none
		want   string // the one mailbox the message must be stored in
		header string // an extra header line, "" for none
	}{
		{name: "parent level", script: `require ["fileinto", "mailbox"]; fileinto :create "a/../b";`, want: "INBOX"},
		{name: "dot level from the detail", detail: "a/./b", want: "INBOX"},
		{name: "empty level", script: `require ["fileinto", "mailbox"]; fileinto :create "x//y";`, want: "INBOX"},
		{name: "empty level from the detail", detail: "x//y", want: "INBOX"},
		{name: "leading delimiter", script: `require ["fileinto", "mailbox"]; fileinto :create "/lead";`, want: "INBOX"},
		{name: "copy to a parent level", script: `require ["fileinto", "mailbox", "copy"]; fileinto :copy :create "a/../b";`, want: "INBOX"},
		{name: "trailing delimiter", script: `require ["fileinto", "mailbox"]; fileinto :create "Foo/";`, want: "Foo"},
		{name: "trailing delimiter from the detail", detail: "foo/", want: "foo"},
		// A NUL or a byte that is not UTF-8 cannot be stored in a PostgreSQL text
		// value: such a name made the mailbox lookup fail with SQLSTATE 22021, and
		// every attempt was answered 451, with :create or without. A script that
		// files by a header value hands the sender that choice: a raw 8-bit header
		// or an encoded-word decoding to a NUL.
		{name: "NUL", script: `require ["fileinto", "mailbox", "encoded-character"]; fileinto :create "a${hex:00}b";`, want: "INBOX"},
		{name: "invalid UTF-8", script: `require ["fileinto", "mailbox", "encoded-character"]; fileinto :create "a${hex:ff}b";`, want: "INBOX"},
		{name: "invalid UTF-8 without create", script: `require ["fileinto", "encoded-character"]; fileinto "a${hex:ff}b";`, want: "INBOX"},
		{
			name:   "8-bit header value",
			script: `require ["fileinto", "mailbox", "variables"]; if header :matches "X-Folder" "*" { fileinto :create "${1}"; }`,
			header: "X-Folder: caf\xe9",
			want:   "INBOX",
		},
		{
			name:   "header encoded-word with a NUL",
			script: `require ["fileinto", "mailbox", "variables"]; if header :matches "X-Folder" "*" { fileinto :create "${1}"; }`,
			header: "X-Folder: =?UTF-8?Q?a=00b?=",
			want:   "INBOX",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			if err != nil {
				t.Fatalf("lookup account: %v", err)
			}
			if tc.script != "" {
				if _, err := rdb.ExecWithRetry(ctx, `
					INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
					VALUES ($1, 'create-names', $2, TRUE, NOW(), NOW())`,
					accountID, "# "+account.Email+"\r\n"+tc.script+"\r\n"); err != nil {
					t.Fatalf("insert sieve script: %v", err)
				}
			}
			rcpt := account.Email
			if tc.detail != "" {
				local, domain, _ := strings.Cut(account.Email, "@")
				rcpt = local + "+" + tc.detail + "@" + domain
			}
			subject := fmt.Sprintf("create-names-%d", time.Now().UnixNano())

			c, err := NewLMTPClient(lmtpAddr)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer c.Close()
			if err := c.SendCommand("LHLO test.example.com"); err != nil {
				t.Fatalf("LHLO: %v", err)
			}
			if _, err := c.ReadMultilineResponse(); err != nil {
				t.Fatalf("LHLO response: %v", err)
			}
			for _, cmd := range []string{"MAIL FROM:<sender@example.com>", "RCPT TO:<" + rcpt + ">", "DATA"} {
				if err := c.SendCommand(cmd); err != nil {
					t.Fatalf("%s: %v", cmd, err)
				}
				resp, err := c.ReadResponse()
				if err != nil {
					t.Fatalf("%s response: %v", cmd, err)
				}
				if !strings.HasPrefix(resp, "250") && !strings.HasPrefix(resp, "354") {
					t.Fatalf("%s: %s", cmd, resp)
				}
			}
			lines := []string{
				"From: sender@example.com",
				"To: " + rcpt,
				"Subject: " + subject,
				"Message-ID: <" + subject + "@example.com>",
				"Date: " + time.Now().Format(time.RFC1123Z),
			}
			if tc.header != "" {
				lines = append(lines, tc.header)
			}
			msg := strings.Join(append(lines, "", "body"), "\r\n")
			if err := c.SendCommand(msg + "\r\n."); err != nil {
				t.Fatalf("send message: %v", err)
			}
			replies, err := c.ReadDataResponses(1)
			if err != nil {
				t.Fatalf("DATA replies: %v", err)
			}
			if !strings.HasPrefix(replies[0], "250") {
				t.Fatalf("delivery answered %s, want 250 (stored in %s)", replies[0], tc.want)
			}

			rows, err := rdb.QueryWithRetry(ctx, `
				SELECT mb.name FROM messages m JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE m.account_id = $1 AND m.subject = $2 AND m.expunged_at IS NULL`, accountID, subject)
			if err != nil {
				t.Fatalf("find delivered message: %v", err)
			}
			var stored []string
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					t.Fatalf("scan: %v", err)
				}
				stored = append(stored, name)
			}
			rows.Close()
			if !slices.Equal(stored, []string{tc.want}) {
				t.Errorf("stored in %q, want [%s]", stored, tc.want)
			}

			mailboxes, err := rdb.GetMailboxesWithRetry(ctx, accountID, false)
			if err != nil {
				t.Fatalf("list mailboxes: %v", err)
			}
			for _, mb := range mailboxes {
				if mb.Name == "" || strings.HasPrefix(mb.Name, "/") || strings.HasSuffix(mb.Name, "/") || strings.Contains(mb.Name, "//") {
					t.Errorf("created mailbox %q with an empty hierarchy level", mb.Name)
				}
				if mb.Name == "a" || mb.Name == "x" {
					t.Errorf("created the parent %q of a refused name", mb.Name)
				}
			}
		})
	}
}
