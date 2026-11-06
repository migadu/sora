package imap

import (
	"slices"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

func TestWithColorsOnUnflag(t *testing.T) {
	got := withColorsOnUnflag([]imap.Flag{imap.FlagFlagged, "$mailflagbit1"})
	want := []imap.Flag{imap.FlagFlagged, "$mailflagbit1", "$MailFlagBit0", "$MailFlagBit2"}
	if !slices.Equal(got, want) {
		t.Errorf("withColorsOnUnflag(\\Flagged $mailflagbit1) = %v, want %v", got, want)
	}

	in := []imap.Flag{imap.FlagSeen, "$MailFlagBit0"}
	if got := withColorsOnUnflag(in); !slices.Equal(got, in) {
		t.Errorf("withColorsOnUnflag without \\Flagged = %v, want it unchanged", got)
	}
}

func TestStoreReplaceTarget(t *testing.T) {
	current := []imap.Flag{imap.FlagFlagged, "$MailFlagBit0", "$MailFlagBit2", "Work"}

	// Owner (every right): a replace without \Flagged drops the color keywords,
	// including any the client listed.
	got := storeReplaceTarget(current, []imap.Flag{imap.FlagSeen, "$MailFlagBit0", "Work"}, db.AllACLRights)
	if want := []imap.Flag{imap.FlagSeen, "Work"}; !slices.Equal(got, want) {
		t.Errorf("replace without \\Flagged = %v, want %v", got, want)
	}

	// A replace that keeps \Flagged keeps the colors the client listed.
	got = storeReplaceTarget(current, []imap.Flag{imap.FlagFlagged, "$MailFlagBit1"}, db.AllACLRights)
	if want := []imap.Flag{imap.FlagFlagged, "$MailFlagBit1"}; !slices.Equal(got, want) {
		t.Errorf("replace with \\Flagged = %v, want %v", got, want)
	}

	// Without 'w' the user can change neither \Flagged nor the color keywords:
	// both keep their current values, even stale colors on an unflagged message.
	stale := []imap.Flag{"$MailFlagBit0"}
	got = storeReplaceTarget(stale, []imap.Flag{imap.FlagSeen}, "lrs")
	if !slices.Contains(got, "$MailFlagBit0") {
		t.Errorf("replace without 'w' = %v, want $MailFlagBit0 preserved", got)
	}
}
