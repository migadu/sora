//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// hasColorKeyword reports whether flags holds any RFC 9979 flag color keyword.
func hasColorKeyword(flags []imap.Flag) bool {
	for _, f := range flags {
		if strings.HasPrefix(strings.ToLower(string(f)), "$mailflagbit") {
			return true
		}
	}
	return false
}

func hasFlagFold(flags []imap.Flag, want imap.Flag) bool {
	for _, f := range flags {
		if strings.EqualFold(string(f), string(want)) {
			return true
		}
	}
	return false
}

func storeFlags(t *testing.T, c *imapclient.Client, uid imap.UID, sf *imap.StoreFlags) []*imapclient.FetchMessageBuffer {
	t.Helper()
	res, err := c.Store(imap.UIDSetNum(uid), sf, nil).Collect()
	if err != nil {
		t.Fatalf("UID STORE %d %v: %v", uid, sf, err)
	}
	return res
}

// TestIMAP_UnflagClearsFlagColor covers RFC 9979 §3.2: clearing \Flagged also
// clears the $MailFlagBit color keywords. A .SILENT client must still be told,
// since it did not name them; the session's update poll reports the change (see
// server/imap/flag_color.go), and the .SILENT subtests fail if it stops doing so.
func TestIMAP_UnflagClearsFlagColor(t *testing.T) {
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

	green := []imap.Flag{imap.FlagFlagged, "$MailFlagBit0", "$MailFlagBit1"}
	uidUnflag := appendWithFlags(t, c, "INBOX", green)
	uidSilent := appendWithFlags(t, c, "INBOX", []imap.Flag{imap.FlagFlagged, "$MailFlagBit2"})
	uidReplace := appendWithFlags(t, c, "INBOX", []imap.Flag{imap.FlagFlagged, "$MailFlagBit0"})
	uidAdd := appendWithFlags(t, c, "INBOX", nil)

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	t.Run("-FLAGS (\\Flagged) clears the colors", func(t *testing.T) {
		res := storeFlags(t, c, uidUnflag, &imap.StoreFlags{Op: imap.StoreFlagsDel, Flags: []imap.Flag{imap.FlagFlagged}})
		if len(res) != 1 || hasFlagFold(res[0].Flags, imap.FlagFlagged) || hasColorKeyword(res[0].Flags) {
			t.Fatalf("STORE reply = %+v, want one FETCH without \\Flagged or colors", res)
		}
		if flags := fetchFlags(t, c, uidUnflag); hasColorKeyword(flags) {
			t.Errorf("flags after unflag = %v, want no color keywords", flags)
		}
	})

	t.Run("-FLAGS.SILENT client is told of the cleared colors", func(t *testing.T) {
		res := storeFlags(t, c, uidSilent, &imap.StoreFlags{Op: imap.StoreFlagsDel, Silent: true, Flags: []imap.Flag{imap.FlagFlagged}})
		if len(res) != 1 || hasColorKeyword(res[0].Flags) {
			t.Fatalf("STORE reply = %+v, want one FETCH without colors despite .SILENT", res)
		}
	})

	t.Run("FLAGS.SILENT without \\Flagged drops listed colors and says so", func(t *testing.T) {
		res := storeFlags(t, c, uidReplace, &imap.StoreFlags{Op: imap.StoreFlagsSet, Silent: true, Flags: []imap.Flag{imap.FlagSeen, "$MailFlagBit0", "Work"}})
		if len(res) != 1 || hasColorKeyword(res[0].Flags) {
			t.Fatalf("STORE reply = %+v, want one FETCH without colors: the server dropped a listed keyword", res)
		}
		flags := fetchFlags(t, c, uidReplace)
		if hasColorKeyword(flags) || !hasFlagFold(flags, imap.FlagSeen) || !hasFlagFold(flags, "Work") {
			t.Errorf("flags = %v, want \\Seen and Work without colors", flags)
		}
	})

	t.Run("+FLAGS leaves an added color alone", func(t *testing.T) {
		storeFlags(t, c, uidAdd, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{"$MailFlagBit0"}})
		if flags := fetchFlags(t, c, uidAdd); !hasFlagFold(flags, "$MailFlagBit0") {
			t.Errorf("flags = %v, want $MailFlagBit0 kept", flags)
		}
	})

	t.Run("colors stored in another case are cleared too", func(t *testing.T) {
		mbox := fmt.Sprintf("ColorCase-%d", common.GetTimestamp())
		if err := c.Create(mbox, nil).Wait(); err != nil {
			t.Fatalf("CREATE: %v", err)
		}
		uid := appendWithFlags(t, c, mbox, []imap.Flag{imap.FlagFlagged, "$mailflagbit0"})
		if _, err := c.Select(mbox, nil).Wait(); err != nil {
			t.Fatalf("SELECT: %v", err)
		}
		storeFlags(t, c, uid, &imap.StoreFlags{Op: imap.StoreFlagsDel, Flags: []imap.Flag{imap.FlagFlagged}})
		if flags := fetchFlags(t, c, uid); hasColorKeyword(flags) {
			t.Errorf("flags = %v, want the lowercase color keyword cleared", flags)
		}
	})
}

// TestIMAP_UnflagColorRespectsACL checks that a user without the 'w' right,
// who cannot change \Flagged or the color keywords, never has colors cleared
// by a FLAGS replace (RFC 4314 §4).
func TestIMAP_UnflagColorRespectsACL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	email2, password2 := createSecondUser(t, server, "example.com", "color")

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()
	if err := c1.Login(owner.Email, owner.Password).Wait(); err != nil {
		t.Fatalf("owner login failed: %v", err)
	}

	shared := fmt.Sprintf("Shared/Color-%d", common.GetTimestamp())
	if err := c1.Create(shared, nil).Wait(); err != nil {
		t.Fatalf("CREATE %s: %v", shared, err)
	}
	// A stale color on an unflagged message.
	uid := appendWithFlags(t, c1, shared, []imap.Flag{"$MailFlagBit0"})
	if err := c1.SetACL(shared, imap.RightsIdentifier(email2), imap.RightModificationReplace, imap.RightSet("lrs")).Wait(); err != nil {
		t.Fatalf("SETACL: %v", err)
	}

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()
	if err := c2.Login(email2, password2).Wait(); err != nil {
		t.Fatalf("accessor login failed: %v", err)
	}
	if _, err := c2.Select(shared, nil).Wait(); err != nil {
		t.Fatalf("SELECT %s: %v", shared, err)
	}

	storeFlags(t, c2, uid, &imap.StoreFlags{Op: imap.StoreFlagsSet, Flags: []imap.Flag{imap.FlagSeen}})
	if flags := fetchFlags(t, c2, uid); !hasFlagFold(flags, "$MailFlagBit0") {
		t.Errorf("flags = %v, want $MailFlagBit0 preserved for a user without 'w'", flags)
	}
}
