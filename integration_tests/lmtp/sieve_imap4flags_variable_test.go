//go:build integration

package lmtp_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveImap4FlagsVariable is issue #883 end to end: setflag and addflag
// naming a variable (RFC 5232 §3) fill that variable instead of the internal
// one, and "fileinto :flags "${flagvar}"" stores the copy with those flags.
func TestLMTP_SieveImap4FlagsVariable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// RFC 5232 §3.1's example, with an addflag on the variable and hasflag
	// checks: a script that fails to load or run is replaced by the default
	// script, which keeps the message in INBOX without these flags.
	setActiveSieveScript(t, rdb, accountID, `require ["imap4flags", "variables", "fileinto"];
setflag "flagvar" "\\Flagged";
addflag "flagvar" "$label1";
if hasflag "\\Flagged" { fileinto "Wrong"; }
if hasflag "flagvar" ["\\Flagged", "$label1"] {
    fileinto :flags "${flagvar}" "Archive";
}
`)

	lmtpAddr := startTestLMTPServer(t, rdb)
	deliverLMTP(t, lmtpAddr, account.Email, "imap4flags variable")

	var flagsBits int
	var customFlagsJSON []byte
	if err := rdb.QueryRowWithRetry(ctx, `
		SELECT ms.flags, ms.custom_flags
		FROM messages m
		JOIN mailboxes mb ON mb.id = m.mailbox_id
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1 AND mb.name = 'Archive' AND m.expunged_at IS NULL
	`, accountID).Scan(&flagsBits, &customFlagsJSON); err != nil {
		t.Fatalf("no message filed into Archive: %v", err)
	}
	if n := countInMailbox(t, rdb, accountID, "INBOX"); n != 0 {
		t.Errorf("INBOX holds %d messages, want 0: fileinto cancels the implicit keep", n)
	}

	if !slices.Contains(db.BitwiseToFlags(flagsBits), imap.FlagFlagged) {
		t.Errorf("Archive copy flags = %v, want \\Flagged from the variable", db.BitwiseToFlags(flagsBits))
	}
	var customFlags []string
	if err := json.Unmarshal(customFlagsJSON, &customFlags); err != nil {
		t.Fatalf("unmarshal custom_flags %q: %v", customFlagsJSON, err)
	}
	if !slices.ContainsFunc(customFlags, func(f string) bool { return strings.EqualFold(f, "$label1") }) {
		t.Errorf("Archive copy keywords = %v, want $label1 from the variable", customFlags)
	}
}
