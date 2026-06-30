//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// assertLimitNo asserts that err is a tagged NO carrying the RFC 5530 [LIMIT]
// response code — the standard signal for "too many flags on a message".
func assertLimitNo(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a NO [LIMIT] error, got nil")
	}
	var ierr *imap.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("expected *imap.Error, got %T: %v", err, err)
	}
	if ierr.Code != imap.ResponseCodeLimit {
		t.Errorf("expected response code LIMIT, got %q (%v)", ierr.Code, err)
	}
}

// These tests rebut the specific reason eM Client gives for keeping a server
// allowlist before it will synchronise IMAP keywords/tags:
//
//	"A lot of servers (even though they advertised mentioned capabilities) do
//	 not behave correctly. One of the common and really big problem here is
//	 that many servers allow only limited IMAP keywords to be used per folder
//	 or per account which results a lot of issues and misbehavior."
//
// Sora imposes NO per-folder or per-account keyword limit:
//   - The per-folder keyword registry (mailbox_stats.custom_flags_cache,
//     surfaced as the SELECT/EXAMINE FLAGS list) is an unbounded JSONB array.
//   - Keywords are stored per message (message_state.custom_flags); there is
//     no shared, slot-limited keyword pool per folder or per account.
//
// The ONLY cap Sora enforces is 50 custom keywords on a single message
// (the message_state CHECK constraint, jsonb_array_length(custom_flags) <= 50).
// That is per-message — not the per-folder/per-account limit the quote
// describes — and is far above any realistic tagging scheme.

// flagSet builds a case-insensitive lookup set from a FLAGS list. Keyword
// identity is case-insensitive (RFC 9051 §2.3.2), so membership tests fold case.
func flagSet(flags []imap.Flag) map[string]bool {
	m := make(map[string]bool, len(flags))
	for _, f := range flags {
		m[strings.ToLower(string(f))] = true
	}
	return m
}

// TestIMAP_NoPerFolderKeywordLimit proves a single folder can carry far more
// than 50 distinct keywords (here 96, spread across messages so no single
// message approaches the per-message cap), and that every one of them is both
// announced in the mailbox FLAGS list and round-tripped on its own message.
// A server with a per-folder keyword limit would silently drop the overflow —
// exactly the misbehavior eM Client cites.
func TestIMAP_NoPerFolderKeywordLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	const (
		numMessages    = 16
		keywordsPerMsg = 6 // well under the 50-per-message cap
	)

	type tagged struct {
		uid  imap.UID
		kwds []imap.Flag
	}
	var msgs []tagged
	all := make([]imap.Flag, 0, numMessages*keywordsPerMsg) // 96 distinct keywords
	for i := 0; i < numMessages; i++ {
		kwds := make([]imap.Flag, keywordsPerMsg)
		for j := 0; j < keywordsPerMsg; j++ {
			n := i*keywordsPerMsg + j
			kwds[j] = imap.Flag(fmt.Sprintf("Folder-Kwd-%03d", n))
		}
		uid := appendWithFlags(t, c, "INBOX", kwds)
		msgs = append(msgs, tagged{uid: uid, kwds: kwds})
		all = append(all, kwds...)
	}

	// Every distinct keyword must be advertised in the mailbox FLAGS list.
	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	announced := flagSet(selData.Flags)
	missing := 0
	for _, kw := range all {
		if !announced[strings.ToLower(string(kw))] {
			missing++
			if missing <= 10 { // cap the noise; the count below is authoritative
				t.Errorf("keyword %q not announced in SELECT FLAGS", kw)
			}
		}
	}
	if missing > 0 {
		t.Fatalf("%d/%d distinct keywords missing from the folder FLAGS list (a per-folder limit would do exactly this)", missing, len(all))
	}

	// Each message must round-trip exactly the keywords it was given.
	for _, m := range msgs {
		got := flagSet(fetchFlags(t, c, m.uid))
		for _, kw := range m.kwds {
			if !got[strings.ToLower(string(kw))] {
				t.Errorf("UID %d: keyword %q set but not returned by FETCH", m.uid, kw)
			}
		}
	}
}

// TestIMAP_NoPerAccountKeywordLimit proves keywords are not pooled or limited
// per account: distinct keywords spread across several different folders all
// persist and surface in their own folder's FLAGS list. A per-account limit
// would drop keywords once the account-wide count grew, regardless of folder.
func TestIMAP_NoPerAccountKeywordLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	const (
		numFolders     = 8
		keywordsPerMsg = 8 // 8 folders * 8 = 64 distinct keywords account-wide
	)

	folderKwds := make(map[string][]imap.Flag, numFolders)
	for f := 0; f < numFolders; f++ {
		mailbox := fmt.Sprintf("AcctKwd-%d", f)
		if err := c.Create(mailbox, nil).Wait(); err != nil {
			t.Fatalf("CREATE %q failed: %v", mailbox, err)
		}
		kwds := make([]imap.Flag, keywordsPerMsg)
		for j := 0; j < keywordsPerMsg; j++ {
			// Globally unique across folders so an account-wide pool would overflow.
			kwds[j] = imap.Flag(fmt.Sprintf("Acct-Kwd-%02d", f*keywordsPerMsg+j))
		}
		appendWithFlags(t, c, mailbox, kwds)
		folderKwds[mailbox] = kwds
	}

	// Each folder must independently advertise its own keywords.
	for mailbox, kwds := range folderKwds {
		selData, err := c.Select(mailbox, nil).Wait()
		if err != nil {
			t.Fatalf("SELECT %q failed: %v", mailbox, err)
		}
		announced := flagSet(selData.Flags)
		for _, kw := range kwds {
			if !announced[strings.ToLower(string(kw))] {
				t.Errorf("%s: keyword %q not announced in FLAGS (a per-account limit would drop it): %v", mailbox, kw, selData.Flags)
			}
		}
	}
}

// TestIMAP_KeywordsVisibleAcrossSessions mirrors the exact eM Client symptom
// ("externally-set IMAP keywords/tags no longer displayed"): a keyword set by
// one session must be visible to a second, fully independent session — both in
// that session's mailbox FLAGS list and in the message's FETCH flags. This is
// the server-side behavior eM Client verifies before whitelisting a server.
func TestIMAP_KeywordsVisibleAcrossSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Session A sets the keywords.
	ca, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("session A dial failed: %v", err)
	}
	defer ca.Logout()
	if err := ca.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("session A login failed: %v", err)
	}

	appendKwd := imap.Flag("$ExternalAppend")
	storeKwd := imap.Flag("$ExternalStore")

	// One keyword set at APPEND time, a second added later via STORE.
	uid := appendWithFlags(t, ca, "INBOX", []imap.Flag{appendKwd})
	if _, err := ca.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("session A SELECT failed: %v", err)
	}
	if _, err := ca.Store(imap.UIDSetNum(uid), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{storeKwd},
	}, nil).Collect(); err != nil {
		t.Fatalf("session A STORE failed: %v", err)
	}

	// Session B is a completely independent connection and login.
	cb, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("session B dial failed: %v", err)
	}
	defer cb.Logout()
	if err := cb.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("session B login failed: %v", err)
	}

	selData, err := cb.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("session B SELECT failed: %v", err)
	}
	announced := flagSet(selData.Flags)
	for _, kw := range []imap.Flag{appendKwd, storeKwd} {
		if !announced[strings.ToLower(string(kw))] {
			t.Errorf("externally-set keyword %q not announced in session B FLAGS: %v", kw, selData.Flags)
		}
	}

	got := flagSet(fetchFlags(t, cb, uid))
	for _, kw := range []imap.Flag{appendKwd, storeKwd} {
		if !got[strings.ToLower(string(kw))] {
			t.Errorf("externally-set keyword %q not visible to session B FETCH", kw)
		}
	}
}

// TestIMAP_FiftyKeywordsOnSingleMessage documents that the one keyword cap Sora
// does enforce — 50 custom keywords on a single message — is both generous and
// fully functional: all 50 persist and round-trip via FETCH. This is unrelated
// to the per-folder/per-account limits eM Client warns about; it is a sanity
// bound on a single message and well above any real tagging scheme.
func TestIMAP_FiftyKeywordsOnSingleMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	const n = 50 // the per-message cap; exactly at the boundary must succeed
	kwds := make([]imap.Flag, n)
	for i := 0; i < n; i++ {
		kwds[i] = imap.Flag(fmt.Sprintf("Cap-Kwd-%02d", i))
	}
	uid := appendWithFlags(t, c, "INBOX", kwds)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	got := flagSet(fetchFlags(t, c, uid))
	missing := 0
	for _, kw := range kwds {
		if !got[strings.ToLower(string(kw))] {
			missing++
			t.Errorf("keyword %q not round-tripped on the 50-keyword message", kw)
		}
	}
	if missing == 0 {
		t.Logf("all %d keywords on a single message persisted and round-tripped", n)
	}
}

// TestIMAP_KeywordCapAppendReturnsLimit verifies that an APPEND carrying more
// keywords than a single message may hold is rejected with NO [LIMIT] (RFC 5530)
// and stores nothing — rather than silently dropping the surplus and reporting
// success. (Sieve-set keywords on delivery and bulk import clamp instead, so a
// runaway addflag or a migration is never bounced.)
func TestIMAP_KeywordCapAppendReturnsLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	over := db.MaxCustomKeywordsPerMessage + 15
	kwds := make([]imap.Flag, over)
	for i := range kwds {
		kwds[i] = imap.Flag(fmt.Sprintf("OverCap-%03d", i))
	}

	msg := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Over\r\n\r\nBody\r\n"
	ac := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{Flags: kwds})
	_, _ = ac.Write([]byte(msg))
	_ = ac.Close()
	_, err = ac.Wait()
	assertLimitNo(t, err)

	// A rejected APPEND must store nothing.
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	if sel.NumMessages != 0 {
		t.Errorf("rejected APPEND must not store a message; INBOX has %d", sel.NumMessages)
	}
}

// TestIMAP_KeywordCapStoreReturnsLimit verifies that a STORE which would push an
// at-capacity message past the per-message keyword cap is rejected with
// NO [LIMIT] and applies nothing — the message is left exactly as it was, rather
// than silently dropping the surplus and falsely reporting success.
func TestIMAP_KeywordCapStoreReturnsLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	maxKw := db.MaxCustomKeywordsPerMessage
	existing := make([]imap.Flag, maxKw)
	for i := 0; i < maxKw; i++ {
		existing[i] = imap.Flag(fmt.Sprintf("Keep-%02d", i))
	}
	uid := appendWithFlags(t, c, "INBOX", existing)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// STORE-add 10 new keywords onto an already-full message: 50 + 10 > cap.
	overflow := make([]imap.Flag, 10)
	for i := range overflow {
		overflow[i] = imap.Flag(fmt.Sprintf("Zadd-%02d", i))
	}
	_, err = c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: overflow,
	}, nil).Collect()
	assertLimitNo(t, err)

	// The STORE must have applied nothing: the original keywords remain, the
	// overflow keywords are absent, and the distinct count is unchanged.
	got := flagSet(fetchFlags(t, c, uid))
	if n := len(got); n != maxKw {
		t.Errorf("rejected STORE must leave the message unchanged (%d keywords), got %d", maxKw, n)
	}
	for _, kw := range existing {
		if !got[strings.ToLower(string(kw))] {
			t.Errorf("existing keyword %q must be preserved after a rejected STORE", kw)
		}
	}
	for _, kw := range overflow {
		if got[strings.ToLower(string(kw))] {
			t.Errorf("overflow keyword %q must not be present after a rejected STORE", kw)
		}
	}
}
