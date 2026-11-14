//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
)

// createSharedMailbox makes a same-domain owner account for recipientEmail, has it
// create name over IMAP (which makes it shared) and grant the recipient rights. It
// returns the owner's account id.
func createSharedMailbox(t *testing.T, imapSrv *common.TestServer, recipientEmail, name, rights string) int64 {
	t.Helper()
	ctx := context.Background()
	rdb := imapSrv.ResilientDB
	domain := strings.Split(recipientEmail, "@")[1]
	ownerEmail := fmt.Sprintf("owner-%d@%s", common.GetTimestamp(), domain)
	const ownerPassword = "owner-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: ownerEmail, Password: ownerPassword, HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	c, err := imapclient.DialInsecure(imapSrv.Address, nil)
	if err != nil {
		t.Fatalf("owner dial: %v", err)
	}
	if err := c.Login(ownerEmail, ownerPassword).Wait(); err != nil {
		t.Fatalf("owner login: %v", err)
	}
	if err := c.Create(name, nil).Wait(); err != nil {
		t.Fatalf("create shared mailbox %s: %v", name, err)
	}
	_ = c.Logout()
	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, ownerEmail)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}
	if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, recipientEmail, name, rights); err != nil {
		t.Fatalf("grant %q on %s: %v", rights, name, err)
	}
	return ownerID
}

// ownMailboxNames lists the names of accountID's own mailboxes among names, ignoring case.
func ownMailboxNames(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, names ...string) []string {
	t.Helper()
	lowered := make([]string, len(names))
	for i, n := range names {
		lowered[i] = strings.ToLower(n)
	}
	rows, err := rdb.QueryWithRetry(context.Background(), `
		SELECT name FROM mailboxes
		WHERE account_id = $1 AND LOWER(name) = ANY($2) AND deleted_at IS NULL
		ORDER BY name`, accountID, lowered)
	if err != nil {
		t.Fatalf("list mailboxes: %v", err)
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan mailbox: %v", err)
		}
		found = append(found, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list mailboxes: %v", err)
	}
	return found
}

// TestLMTP_SieveMailboxExists is issue #323 (1). RFC 5490 §3.1: "The
// "mailboxexists" test is true if all mailboxes listed in the "mailbox-names"
// argument exist in the mailstore, and each allows the user in whose context the
// Sieve script runs to "deliver" messages into it." It used to be true for any name.
func TestLMTP_SieveMailboxExists(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, account := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	for _, name := range []string{"Exists", "Fallback"} {
		if _, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, name); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	stamp := common.GetTimestamp()
	lookupOnly := fmt.Sprintf("Shared/LookupOnly-%d", stamp)
	createSharedMailbox(t, imapSrv, account.Email, lookupOnly, "l")
	insertable := fmt.Sprintf("Shared/Insert-%d", stamp)
	createSharedMailbox(t, imapSrv, account.Email, insertable, "li")

	lmtpAddr := startTestLMTPServer(t, rdb)

	cases := []struct {
		name    string
		mailbox string
		exists  bool
	}{
		{name: "own mailbox", mailbox: "Exists", exists: true},
		{name: "own mailbox in another case", mailbox: "exists", exists: true},
		{name: "missing mailbox", mailbox: fmt.Sprintf("Nonexistent-%d", stamp), exists: false},
		{name: "shared with insert right", mailbox: insertable, exists: true},
		{name: "shared with lookup only", mailbox: lookupOnly, exists: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setActiveSieveScript(t, rdb, accountID, strings.Join([]string{
				`require ["fileinto", "mailbox"];`,
				`if mailboxexists "` + tc.mailbox + `" { fileinto "Exists"; } else { fileinto "Fallback"; }`,
			}, "\r\n")+"\r\n")

			subject := fmt.Sprintf("mailboxexists %s %d", tc.name, time.Now().UnixNano())
			deliverLMTP(t, lmtpAddr, account.Email, subject)

			want := "Fallback"
			if tc.exists {
				want = "Exists"
			}
			if got := mailboxesHolding(t, rdb, accountID, subject); len(got) != 1 || got[0] != want {
				t.Errorf("mailboxexists %q: message stored in %v, want %s", tc.mailbox, got, want)
			}
		})
	}
}

// TestLMTP_SieveFileintoCreateFindsSharedMailbox is issue #323 (2). RFC 5490 §3.2:
// ":create" instructs the interpreter "to create the specified mailbox, if needed";
// "If the mailbox already exists, this argument is ignored." A mailbox shared with
// the recipient exists for it, so fileinto :create must deliver into it as fileinto
// does, and not create a personal namesake (and its parent) in the recipient's account.
func TestLMTP_SieveFileintoCreateFindsSharedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapSrv, member := common.SetupIMAPServer(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	memberID, err := rdb.GetAccountIDByAddressWithRetry(ctx, member.Email)
	if err != nil {
		t.Fatalf("member id: %v", err)
	}
	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	ownerID := createSharedMailbox(t, imapSrv, member.Email, team, "lrswi")

	setActiveSieveScript(t, rdb, memberID,
		"require [\"fileinto\", \"mailbox\"];\r\nfileinto :create \""+team+"\";\r\n")
	lmtpAddr := startTestLMTPServer(t, rdb)

	subject := fmt.Sprintf("create-shared %d", time.Now().UnixNano())
	deliverLMTP(t, lmtpAddr, member.Email, subject)

	if got := mailboxesHolding(t, rdb, ownerID, subject); len(got) != 1 || got[0] != team {
		t.Errorf("the message must be in the owner's %s, owner holds it in %v", team, got)
	}
	if got := ownMailboxNames(t, rdb, memberID, "Shared", team); len(got) != 0 {
		t.Errorf("fileinto :create made personal mailboxes %v for the member", got)
	}
}
