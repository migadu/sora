//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// Deleting a shared mailbox needs the 'x' right (RFC 4314 §2.1: "x - delete mailbox
// (DELETE mailbox, old mailbox name in RENAME)"). A grantee who may see the mailbox
// but lacks it is refused with 403, as IMAP DELETE answers NO [NOPERM]; it was
// answered 500 and logged as a server failure (issue #992).
func TestUserAPI_SharedMailbox_DeleteNeedsDeleteRight(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	imapServer, owner := common.SetupIMAPServer(t)
	defer imapServer.Close()
	rdb := imapServer.ResilientDB
	ctx := context.Background()

	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-del-%d@%s", common.GetTimestamp(), domain)
	const granteePassword = "grantee-pass-123"
	if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
		Email: granteeEmail, Password: granteePassword, HashType: "bcrypt", IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}
	ownerID, err := rdb.GetAccountIDByAddressWithRetry(ctx, owner.Email)
	if err != nil {
		t.Fatalf("owner id: %v", err)
	}

	shared := fmt.Sprintf("Shared/Del-%d", common.GetTimestamp())
	imapAppend(t, imapServer.Address, owner.Email, owner.Password, shared,
		"From: owner@"+domain+"\r\nTo: team@"+domain+"\r\nSubject: keep\r\n\r\nbody\r\n", true)

	ts := newUserAPITestServer(t, rdb)
	client := ts.Client()
	token := h2Login(t, ts, client, granteeEmail, granteePassword)
	path := "/user/mailboxes/" + url.PathEscape(shared)
	grant := func(rights string) {
		t.Helper()
		if err := rdb.GrantMailboxAccessByIdentifierWithRetry(ctx, ownerID, granteeEmail, shared, rights); err != nil {
			t.Fatalf("grant %q: %v", rights, err)
		}
	}

	grant("lr")
	if code, body := apiDo(t, ts, client, token, "DELETE", path, nil); code != http.StatusForbidden || !strings.Contains(body, `"error"`) {
		t.Errorf("DELETE %s with 'lr': %d (%s), want 403 with a JSON error", path, code, body)
	}
	if _, err := rdb.GetMailboxByNameWithRetry(ctx, ownerID, shared); err != nil {
		t.Fatalf("refused delete must leave the mailbox live: %v", err)
	}

	grant("lrx")
	if code, body := apiDo(t, ts, client, token, "DELETE", path, nil); code != http.StatusOK {
		t.Errorf("DELETE %s with 'lrx': %d (%s), want 200", path, code, body)
	}
	if _, found := h2MailboxEntry(t, ts, client, token, shared); found {
		t.Errorf("mailbox %s still listed after a permitted delete", shared)
	}
}
