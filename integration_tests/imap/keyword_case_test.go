//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// appendWithFlags appends a small message to the given mailbox with the supplied
// flags and returns its UID.
func appendWithFlags(t *testing.T, c *imapclient.Client, mailbox string, flags []imap.Flag) imap.UID {
	t.Helper()
	msg := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Case Test\r\n\r\nBody\r\n"
	appendCmd := c.Append(mailbox, int64(len(msg)), &imap.AppendOptions{Flags: flags})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	data, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	return data.UID
}

// countFold returns how many flags fold (case-insensitively) to want, plus the
// distinct exact-case spellings seen.
func countFold(flags []imap.Flag, want string) (int, []string) {
	want = strings.ToLower(want)
	count := 0
	var spellings []string
	for _, f := range flags {
		if strings.ToLower(string(f)) == want {
			count++
			spellings = append(spellings, string(f))
		}
	}
	return count, spellings
}

// TestIMAP_KeywordCaseInsensitive is the regression test for the eM Client
// repair-loop bug: a mailbox must treat keywords case-insensitively (RFC 9051
// §2.3.2) and never store/advertise two case-variants of the same keyword.
func TestIMAP_KeywordCaseInsensitive(t *testing.T) {
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

	// Establish "WAREHOUSING" (uppercase) as the first case seen in this mailbox.
	uid1 := appendWithFlags(t, c, "INBOX", []imap.Flag{"WAREHOUSING"})
	// A second message that we will tag with the lowercase spelling via STORE.
	uid2 := appendWithFlags(t, c, "INBOX", nil)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// STORE the keyword in a DIFFERENT case. It must fold onto the established
	// case rather than create a second variant.
	storeRes, err := c.Store(imap.UIDSetNum(uid2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{"warehousing"},
	}, nil).Collect()
	if err != nil {
		t.Fatalf("STORE failed: %v", err)
	}
	if len(storeRes) == 1 {
		if n, sp := countFold(storeRes[0].Flags, "warehousing"); n != 1 || sp[0] != "WAREHOUSING" {
			t.Errorf("STORE response flags: expected single canonical \"WAREHOUSING\", got %v (folded count=%d)", storeRes[0].Flags, n)
		}
	}

	// FETCH must report the canonical case on the message tagged with lowercase.
	flags2 := fetchFlags(t, c, uid2)
	if n, sp := countFold(flags2, "warehousing"); n != 1 || sp[0] != "WAREHOUSING" {
		t.Errorf("UID %d FETCH flags: expected single canonical \"WAREHOUSING\", got %v", uid2, flags2)
	}

	// The mailbox FLAGS list must advertise the keyword in exactly one case.
	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("re-SELECT INBOX failed: %v", err)
	}
	if n, sp := countFold(selData.Flags, "warehousing"); n != 1 {
		t.Errorf("SELECT FLAGS advertised %d case-variants of WAREHOUSING %v; want exactly 1\nfull FLAGS: %v", n, sp, selData.Flags)
	} else if sp[0] != "WAREHOUSING" {
		t.Errorf("SELECT FLAGS advertised %q; want canonical \"WAREHOUSING\"", sp[0])
	}

	// Removal must be case-insensitive: removing "Warehousing" (yet another case)
	// from uid1 must clear the keyword.
	if _, err := c.Store(imap.UIDSetNum(uid1), &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{"Warehousing"},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE -FLAGS failed: %v", err)
	}
	flags1 := fetchFlags(t, c, uid1)
	if n, _ := countFold(flags1, "warehousing"); n != 0 {
		t.Errorf("UID %d still carries the keyword after case-insensitive removal: %v", uid1, flags1)
	}
}

// TestIMAP_KeywordSearchCaseInsensitive verifies that SEARCH/UNKEYWORD on a custom
// keyword matches regardless of the case used in the search, and excludes the right
// messages for the negative form. Before the JSONB-containment fix, custom-keyword
// SEARCH mapped to "flags & 0 != 0" and always returned zero results.
func TestIMAP_KeywordSearchCaseInsensitive(t *testing.T) {
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

	// uidTagged carries the keyword (stored canonical "WAREHOUSING"); uidPlain does not.
	uidTagged := appendWithFlags(t, c, "INBOX", []imap.Flag{"WAREHOUSING"})
	uidPlain := appendWithFlags(t, c, "INBOX", nil)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// Positive KEYWORD search must match regardless of the case the client uses.
	for _, term := range []imap.Flag{"warehousing", "WAREHOUSING", "Warehousing"} {
		res, err := c.UIDSearch(&imap.SearchCriteria{Flag: []imap.Flag{term}}, nil).Wait()
		if err != nil {
			t.Fatalf("UID SEARCH KEYWORD %q failed: %v", term, err)
		}
		uids := res.AllUIDs()
		if len(uids) != 1 || uids[0] != uidTagged {
			t.Errorf("SEARCH KEYWORD %q: got UIDs %v, want [%d]", term, uids, uidTagged)
		}
	}

	// Negative UNKEYWORD search must exclude the tagged message and return the plain
	// one, also case-insensitively.
	for _, term := range []imap.Flag{"warehousing", "WAREHOUSING"} {
		res, err := c.UIDSearch(&imap.SearchCriteria{NotFlag: []imap.Flag{term}}, nil).Wait()
		if err != nil {
			t.Fatalf("UID SEARCH UNKEYWORD %q failed: %v", term, err)
		}
		uids := res.AllUIDs()
		if len(uids) != 1 || uids[0] != uidPlain {
			t.Errorf("SEARCH UNKEYWORD %q: got UIDs %v, want [%d]", term, uids, uidPlain)
		}
	}
}

// distinctKeywordSpellings selects the mailbox, fetches every message, and returns
// the distinct exact-case spellings of keywords that fold to `fold`.
func distinctKeywordSpellings(t *testing.T, c *imapclient.Client, mailbox, fold string) []string {
	t.Helper()
	if _, err := c.Select(mailbox, nil).Wait(); err != nil {
		t.Fatalf("SELECT %q failed: %v", mailbox, err)
	}
	res, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH ALL in %q failed: %v", mailbox, err)
	}
	uids := res.AllUIDs()
	if len(uids) == 0 {
		return nil
	}
	msgs, err := c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH all in %q failed: %v", mailbox, err)
	}
	set := map[string]struct{}{}
	for _, m := range msgs {
		if _, sp := countFold(m.Flags, fold); len(sp) > 0 {
			for _, s := range sp {
				set[s] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}

// TestIMAP_KeywordCaseInsensitiveCrossMailbox verifies that COPY and MOVE fold a
// moved message's keywords onto the DESTINATION mailbox's canonical case, so the
// destination never reports two case-variants of the same keyword across messages.
func TestIMAP_KeywordCaseInsensitiveCrossMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, tc := range []struct {
		name string
		op   func(c *imapclient.Client, uid imap.UID, dest string) error
	}{
		{"COPY", func(c *imapclient.Client, uid imap.UID, dest string) error {
			_, err := c.Copy(imap.UIDSetNum(uid), dest).Wait()
			return err
		}},
		{"MOVE", func(c *imapclient.Client, uid imap.UID, dest string) error {
			_, err := c.Move(imap.UIDSetNum(uid), dest).Wait()
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
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

			const dest = "KwDest"
			if err := c.Create(dest, nil).Wait(); err != nil {
				t.Fatalf("CREATE %q failed: %v", dest, err)
			}

			// Destination establishes the lowercase canonical "warehousing".
			appendWithFlags(t, c, dest, []imap.Flag{"warehousing"})
			// Source message carries the uppercase spelling.
			srcUID := appendWithFlags(t, c, "INBOX", []imap.Flag{"WAREHOUSING"})

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Fatalf("SELECT INBOX failed: %v", err)
			}
			if err := tc.op(c, srcUID, dest); err != nil {
				t.Fatalf("%s to %q failed: %v", tc.name, dest, err)
			}

			// Across all destination messages, the keyword must appear in exactly
			// one case — the destination's canonical "warehousing".
			spellings := distinctKeywordSpellings(t, c, dest, "warehousing")
			if len(spellings) != 1 || spellings[0] != "warehousing" {
				t.Errorf("after %s, destination reports keyword spellings %v; want exactly [\"warehousing\"]", tc.name, spellings)
			}

			selData, err := c.Select(dest, nil).Wait()
			if err != nil {
				t.Fatalf("SELECT %q failed: %v", dest, err)
			}
			if n, sp := countFold(selData.Flags, "warehousing"); n != 1 {
				t.Errorf("destination FLAGS advertised %d case-variants %v; want exactly 1", n, sp)
			}
		})
	}
}

// TestIMAP_KeywordCaseInsensitiveAppend verifies that two APPENDs using different
// cases of the same keyword converge on a single stored case.
func TestIMAP_KeywordCaseInsensitiveAppend(t *testing.T) {
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

	// First case seen wins; the second APPEND uses a different case.
	uid1 := appendWithFlags(t, c, "INBOX", []imap.Flag{"Project-X"})
	uid2 := appendWithFlags(t, c, "INBOX", []imap.Flag{"PROJECT-X"})

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	f1 := fetchFlags(t, c, uid1)
	f2 := fetchFlags(t, c, uid2)
	_, sp1 := countFold(f1, "project-x")
	_, sp2 := countFold(f2, "project-x")
	if len(sp1) != 1 || len(sp2) != 1 {
		t.Fatalf("expected one Project-X spelling per message, got uid1=%v uid2=%v", f1, f2)
	}
	if sp1[0] != sp2[0] {
		t.Errorf("the same keyword is stored in two cases across messages: uid1=%q uid2=%q (must be identical)", sp1[0], sp2[0])
	}

	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("re-SELECT INBOX failed: %v", err)
	}
	if n, sp := countFold(selData.Flags, "project-x"); n != 1 {
		t.Errorf("SELECT FLAGS advertised %d case-variants %v; want exactly 1", n, sp)
	}
}
