//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// listSubscribedRecursive returns LIST (SUBSCRIBED RECURSIVEMATCH) entries.
func listSubscribedRecursive(t *testing.T, c *imapclient.Client, pattern string) []*imap.ListData {
	t.Helper()
	mboxes, err := c.List("", pattern, &imap.ListOptions{
		SelectSubscribed:     true,
		SelectRecursiveMatch: true,
	}).Collect()
	if err != nil {
		t.Fatalf("LIST (SUBSCRIBED RECURSIVEMATCH) %q failed: %v", pattern, err)
	}
	return mboxes
}

// TestIMAP_RecursiveMatch_LiveParent verifies RFC 5258 §3.5 / RFC 3501 §6.3.9:
// when a child ("Foo/Baz") is subscribed but its live parent ("Foo") is not, a
// LIST (SUBSCRIBED RECURSIVEMATCH) with the "%" wildcard reports the parent —
// which does not itself match the SUBSCRIBED criterion — with a CHILDINFO
// ("SUBSCRIBED") extended data item and WITHOUT the \Subscribed attribute.
func TestIMAP_RecursiveMatch_LiveParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialLogin(t, server, account)
	defer c.Logout()

	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo failed: %v", err)
	}
	if err := c.Create("Foo/Baz", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo/Baz failed: %v", err)
	}
	if err := c.Subscribe("Foo/Baz").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE Foo/Baz failed: %v", err)
	}

	// "%" does not descend into children: Foo/Baz does not match, but its parent
	// Foo does. Foo must appear with CHILDINFO and no \Subscribed.
	got := findSub(listSubscribedRecursive(t, c, "%"), "Foo")
	if got == nil {
		t.Fatalf("RECURSIVEMATCH %%: non-subscribed parent Foo missing (must be reported via CHILDINFO)")
	}
	if got.ChildInfo == nil || !got.ChildInfo.Subscribed {
		t.Errorf("Foo must carry CHILDINFO (SUBSCRIBED); got ChildInfo=%+v", got.ChildInfo)
	}
	if hasAttr(got.Attrs, imap.MailboxAttrSubscribed) {
		t.Errorf("non-subscribed parent Foo must NOT carry \\Subscribed; attrs=%v", got.Attrs)
	}

	// Foo/Baz itself does not match "%", so it must not be returned here.
	if got := findSub(listSubscribedRecursive(t, c, "%"), "Foo/Baz"); got != nil {
		t.Errorf("Foo/Baz does not match %%, must not appear: %v", got)
	}
}

// TestIMAP_Subscribed_NoOverReturnOfParent verifies that plain LIST (SUBSCRIBED)
// — without RECURSIVEMATCH — does NOT return the non-subscribed parent. The
// \Noselect/CHILDINFO parent behavior is a RECURSIVEMATCH-only feature (RFC 5258
// §3.5); the previous ad-hoc implementation wrongly returned it for every
// SUBSCRIBED listing.
func TestIMAP_Subscribed_NoOverReturnOfParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialLogin(t, server, account)
	defer c.Logout()

	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo failed: %v", err)
	}
	if err := c.Create("Foo/Baz", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo/Baz failed: %v", err)
	}
	if err := c.Subscribe("Foo/Baz").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE Foo/Baz failed: %v", err)
	}

	if got := findSub(listSubscribed(t, c, "%"), "Foo"); got != nil {
		t.Errorf("plain LIST (SUBSCRIBED) %% must not return non-subscribed parent Foo; attrs=%v childinfo=%+v", got.Attrs, got.ChildInfo)
	}
}

// TestIMAP_RecursiveMatch_NonExistentParent verifies the same §6.3.9 rule when
// the parent has no live mailbox at all: subscribing "Ghost/Child" (a name-based
// subscription, migration 000046) with neither "Ghost" nor "Ghost/Child"
// existing must still surface "Ghost" under RECURSIVEMATCH "%", flagged
// \NonExistent (implies \Noselect) and carrying CHILDINFO.
func TestIMAP_RecursiveMatch_NonExistentParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialLogin(t, server, account)
	defer c.Logout()

	if err := c.Subscribe("Ghost/Child").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE Ghost/Child failed: %v", err)
	}

	got := findSub(listSubscribedRecursive(t, c, "%"), "Ghost")
	if got == nil {
		t.Fatalf("RECURSIVEMATCH %%: non-existent parent Ghost missing (subscribed descendant Ghost/Child exists)")
	}
	if got.ChildInfo == nil || !got.ChildInfo.Subscribed {
		t.Errorf("Ghost must carry CHILDINFO (SUBSCRIBED); got ChildInfo=%+v", got.ChildInfo)
	}
	if !hasAttr(got.Attrs, imap.MailboxAttrNonExistent) {
		t.Errorf("non-existent parent Ghost must carry \\NonExistent; attrs=%v", got.Attrs)
	}
	if hasAttr(got.Attrs, imap.MailboxAttrSubscribed) {
		t.Errorf("Ghost is not itself subscribed and must NOT carry \\Subscribed; attrs=%v", got.Attrs)
	}
}

// TestIMAP_RecursiveMatch_StarReturnsParent verifies that "*" also surfaces the
// non-subscribed parent with CHILDINFO (RFC 5258 Example 9): even though the
// subscribed child is matched directly by "*", the parent is still returned with
// CHILDINFO — Sora mirrors RECURSIVEMATCH semantics rather than special-casing
// "%".
func TestIMAP_RecursiveMatch_StarReturnsParent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialLogin(t, server, account)
	defer c.Logout()

	if err := c.Create("Foo", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo failed: %v", err)
	}
	if err := c.Create("Foo/Baz", nil).Wait(); err != nil {
		t.Fatalf("CREATE Foo/Baz failed: %v", err)
	}
	if err := c.Subscribe("Foo/Baz").Wait(); err != nil {
		t.Fatalf("SUBSCRIBE Foo/Baz failed: %v", err)
	}

	all := listSubscribedRecursive(t, c, "*")

	parent := findSub(all, "Foo")
	if parent == nil {
		t.Fatalf("RECURSIVEMATCH *: parent Foo missing")
	}
	if parent.ChildInfo == nil || !parent.ChildInfo.Subscribed {
		t.Errorf("Foo must carry CHILDINFO (SUBSCRIBED) under *; got ChildInfo=%+v", parent.ChildInfo)
	}
	if hasAttr(parent.Attrs, imap.MailboxAttrSubscribed) {
		t.Errorf("non-subscribed parent Foo must NOT carry \\Subscribed under *; attrs=%v", parent.Attrs)
	}

	child := findSub(all, "Foo/Baz")
	if child == nil {
		t.Fatalf("RECURSIVEMATCH *: subscribed child Foo/Baz missing")
	}
	if !hasAttr(child.Attrs, imap.MailboxAttrSubscribed) {
		t.Errorf("subscribed child Foo/Baz must carry \\Subscribed; attrs=%v", child.Attrs)
	}
}

// dialLogin dials the server and logs in, failing the test on error.
func dialLogin(t *testing.T, server *common.TestServer, account common.TestAccount) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	return c
}
