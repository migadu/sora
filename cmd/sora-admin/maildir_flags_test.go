package main

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
)

// Maildir info flags per the maildir specification, which the exporter writes and the
// importer must read the same way: D = Draft, T = Trashed (\Deleted), S = Seen,
// R = Replied (\Answered), F = Flagged. The importer once had D and T swapped, which
// turned every imported Dovecot draft into a \Deleted message (destroyed by the user's
// next EXPUNGE) and every trashed message into an undeleted draft.
func TestParseMaildirFlagsMatchesMaildirSpec(t *testing.T) {
	imp := &Importer{}
	cases := []struct {
		filename string
		want     []imap.Flag
	}{
		{"1700000000.M1P1.host:2,D", []imap.Flag{imap.FlagDraft}},
		{"1700000000.M1P1.host:2,T", []imap.Flag{imap.FlagDeleted}},
		{"1700000000.M1P1.host:2,DS", []imap.Flag{imap.FlagDraft, imap.FlagSeen}},
		{"1700000000.M1P1.host:2,ST", []imap.Flag{imap.FlagSeen, imap.FlagDeleted}},
		{"1700000000.M1P1.host:2,FRS", []imap.Flag{imap.FlagFlagged, imap.FlagAnswered, imap.FlagSeen}},
		{"1700000000.M1P1.host:2,", nil},
		{"1700000000.M1P1.host", nil},
	}
	for _, tc := range cases {
		assert.ElementsMatch(t, tc.want, imp.parseMaildirFlags(tc.filename), tc.filename)
	}
}

// The exporter and the importer must agree on every system flag, so a Sora → maildir →
// Sora round trip is flag-identical.
func TestMaildirFlagRoundTrip(t *testing.T) {
	imp := &Importer{}
	exp := &Exporter{}
	for _, flag := range []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft} {
		info := exp.buildMaildirFlags(&db.Message{BitwiseFlags: db.FlagsToBitwise([]imap.Flag{flag})}, "INBOX")
		got := imp.parseMaildirFlags("1700000000.M1P1.host:2," + info)
		assert.Equal(t, []imap.Flag{flag}, got, "flag %s → info %q → %v", flag, info, got)
	}
}
