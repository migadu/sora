//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// TestLMTP_SieveFileintoSharedNamespaceRootKeepsInInbox: LMTP stores nothing in the
// shared namespace root ("Shared" for "Shared/"), which IMAP SELECT refuses (#1299).
// A Sieve fileinto of the root keeps the message in INBOX, as for a target that does
// not exist. RFC 5228 §4.1: "Implementations MAY place restrictions on mailbox names;
// use of an invalid mailbox name MAY be treated as an error or result in delivery to
// an implementation-defined mailbox". Sieve mailboxexists does not report the root,
// which no message can be delivered into (RFC 5490 §3.1). The default script files
// user+detail@ into the detail, so without this any sender could hide a message from
// the user by writing to user+shared@.
func TestLMTP_SieveFileintoSharedNamespaceRootKeepsInInbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}

	// The account's CREATE of a shared mailbox also creates the root, the account's
	// own, with the creator's rights (insert among them).
	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	c, err := imapclient.DialInsecure(imapSrv.Address, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := c.Create(team, nil).Wait(); err != nil {
		t.Fatalf("create %s: %v", team, err)
	}
	_ = c.Logout()

	lmtpAddr, _ := startTestLMTPServerWithOptions(t, rdb, lmtpserver.LMTPServerOptions{
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	})
	local, domain, _ := strings.Cut(account.Email, "@")

	cases := []struct {
		name   string
		script string // the active Sieve script; "" runs the default script alone
		rcpt   string
	}{
		// First, before any script of the account's is active.
		{name: "default script +detail", rcpt: local + "+shared@" + domain},
		{name: "fileinto", script: `require "fileinto"; fileinto "Shared";`},
		{name: "fileinto :create", script: `require ["fileinto", "mailbox"]; fileinto :create "SHARED";`},
		{name: "fileinto :copy", script: `require ["fileinto", "copy"]; fileinto :copy "Shared";`},
		{name: "mailboxexists", script: `require ["fileinto", "mailbox"]; if mailboxexists "Shared" { fileinto "` + team + `"; }`},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.script != "" {
				setActiveSieveScript(t, rdb, accountID, tc.script)
			}
			rcpt := tc.rcpt
			if rcpt == "" {
				rcpt = account.Email
			}
			subject := fmt.Sprintf("shared-root-%d-%d", i, time.Now().UnixNano())
			deliverLMTP(t, lmtpAddr, rcpt, subject)
			if got := mailboxesHolding(t, rdb, accountID, subject); len(got) != 1 || got[0] != "INBOX" {
				t.Errorf("the message must be kept in INBOX alone, found it in %v", got)
			}
		})
	}
}
