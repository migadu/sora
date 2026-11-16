//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ESearchIn_PersonalExcludesSharedNamespace: ESEARCH IN (PERSONAL)
// searches the personal namespace NAMESPACE advertises, not every mailbox the
// user owns. RFC 7377 §2.2 takes the source options from RFC 5465 §6, whose
// §6.2 reads: "Personal refers to all selectable mailboxes in the user's
// personal namespace(s), as defined in [RFC2342]." A shared mailbox the user
// created is in the shared namespace, as is the root CREATE makes for it.
func TestIMAP_ESearchIn_PersonalExcludesSharedNamespace(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()

	ns := esearchCmdOK(t, conn, r, "a", "NAMESPACE")
	if len(ns) != 1 || !strings.HasPrefix(ns[0], `* NAMESPACE (("" "/")) NIL (("Shared/" "/"))`) {
		t.Fatalf("NAMESPACE = %q, want the personal namespace \"\" and the shared namespace \"Shared/\"", ns)
	}

	shared := fmt.Sprintf("Shared/Probe-%d", common.GetTimestamp())
	esearchCreate(t, conn, r, "b", shared)
	esearchAppend(t, conn, r, "c", shared, "probefind")
	esearchAppend(t, conn, r, "d", "INBOX", "probefind")

	got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "e", `ESEARCH IN (PERSONAL) RETURN (ALL) SUBJECT "probefind"`))
	if _, ok := got["INBOX"]; !ok || len(got) != 1 {
		t.Errorf("ESEARCH IN (PERSONAL) answered for %v, want INBOX only", got)
	}

	// The shared mailbox stays searchable by a source that names it.
	got = esearchMailboxes(t, esearchCmdOK(t, conn, r, "f", `ESEARCH IN (MAILBOXES `+esearchQuote(shared)+`) RETURN (ALL) SUBJECT "probefind"`))
	esearchAssertHas(t, got, shared)
}
