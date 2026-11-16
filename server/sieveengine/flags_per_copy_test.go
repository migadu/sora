package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestFlagsBelongToTheirCopy: imap4flags flags are those of one stored copy, not of
// the message. RFC 5232 §5: "The copy of the message filed into the mailbox will
// have only flags listed after the :flags tagged argument." §3: "If the :flags
// tagged argument is not specified with those two actions, the current value of the
// internal variable is used instead. The value of the internal variable also applies
// to the implicit keep." :flags used to overwrite the internal variable, and the one
// resulting list was applied to every copy (#453).
func TestFlagsBelongToTheirCopy(t *testing.T) {
	cases := []struct {
		name        string
		script      string
		wantAction  Action
		wantMailbox []string // the flags of the copy filed into Archive
		wantKeep    []string // the flags of the copy kept in INBOX
	}{
		{
			name:        "fileinto :flags then keep",
			script:      `fileinto :flags "\\Flagged" "Archive"; keep;`,
			wantAction:  ActionFileInto,
			wantMailbox: []string{`\flagged`},
		},
		{
			name:        "fileinto :copy :flags, the implicit keep has the internal variable",
			script:      `setflag "\\Seen"; fileinto :copy :flags "Work" "Archive";`,
			wantAction:  ActionFileInto,
			wantMailbox: []string{"work"},
			wantKeep:    []string{`\seen`},
		},
		{
			name:        "the internal variable as it is when fileinto runs",
			script:      `addflag "Work"; fileinto :copy "Archive"; removeflag "Work"; addflag "\\Seen";`,
			wantAction:  ActionFileInto,
			wantMailbox: []string{"work"},
			wantKeep:    []string{`\seen`},
		},
		{
			name:        "keep :flags then fileinto :flags",
			script:      `keep :flags "\\Flagged"; fileinto :flags "\\Seen" "Archive";`,
			wantAction:  ActionFileInto,
			wantMailbox: []string{`\seen`},
			wantKeep:    []string{`\flagged`},
		},
		{
			name:       "keep :flags",
			script:     `addflag "Work"; keep :flags "\\Flagged";`,
			wantAction: ActionKeep,
			wantKeep:   []string{`\flagged`},
		},
		{
			name:       "implicit keep",
			script:     `addflag "Work";`,
			wantAction: ActionKeep,
			wantKeep:   []string{"work"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exts := []string{"fileinto", "imap4flags", "copy"}
			executor, err := NewSieveExecutorWithOracleAndExtensions(
				`require ["fileinto", "imap4flags", "copy"]; `+tc.script, 1, nil, nil, 0, 0, 0, exts)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			res, err := executor.Evaluate(context.Background(), cleanRedirectCtx())
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Action != tc.wantAction {
				t.Fatalf("action = %s, want %s", res.Action, tc.wantAction)
			}
			if tc.wantAction == ActionFileInto {
				if got := res.MailboxFlags["Archive"]; !slices.Equal(got, tc.wantMailbox) {
					t.Errorf("flags of the copy in Archive = %v, want %v", got, tc.wantMailbox)
				}
			}
			if !slices.Equal(res.KeepFlags, tc.wantKeep) {
				t.Errorf("flags of the copy kept in INBOX = %v, want %v", res.KeepFlags, tc.wantKeep)
			}
			if !slices.Equal(res.Flags, res.KeepFlags) {
				t.Errorf("legacy Flags = %v, want KeepFlags %v", res.Flags, res.KeepFlags)
			}
		})
	}
}

// Different spellings, :create normalization and keep can name the same stored
// mailbox. RFC 5232 §3 requires its last action's flags when copies are eliminated.
func TestFlagsLastStoreWins(t *testing.T) {
	cases := []struct {
		name, script, mailbox string
		create                bool
		want                  []string
	}{
		{"fileinto then keep", `fileinto :copy :flags "A" "INBOX"; keep :flags "B";`, "INBOX", false, []string{"b"}},
		{"keep then fileinto", `keep :flags "A"; fileinto :flags "B" "INBOX";`, "INBOX", false, []string{"b"}},
		{"implicit keep preserves explicit fileinto", `fileinto :copy :flags "A" "INBOX"; setflag "B";`, "INBOX", false, []string{"a"}},
		{"case variant fileinto", `fileinto :flags "A" "Archive"; fileinto :flags "B" "archive";`, "Archive", false, []string{"b"}},
		{"repeat first spelling last", `fileinto :flags "A" "Archive"; fileinto :flags "B" "archive"; fileinto :flags "C" "Archive";`, "Archive", false, []string{"c"}},
		{"repeat keep last", `keep :flags "A"; fileinto :flags "B" "inbox"; keep :flags "C";`, "inbox", false, []string{"c"}},
		{"later internal flags do not change explicit actions", `keep :flags "A"; fileinto :flags "B" "INBOX"; setflag "C";`, "INBOX", false, []string{"b"}},
		{"created name alias", `fileinto :create :flags "A" "Foo/"; fileinto :flags "B" "Foo";`, "Foo", true, []string{"b"}},
		{"empty keep flags clear earlier fileinto flags", `fileinto :flags "A" "INBOX"; keep :flags "";`, "INBOX", false, nil},
		{"empty alias flags clear earlier flags", `fileinto :flags "A" "Archive"; fileinto :flags "" "archive";`, "Archive", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(`require ["fileinto", "imap4flags", "copy", "mailbox"]; `+tc.script,
				[]string{"fileinto", "imap4flags", "copy", "mailbox"})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), cleanRedirectCtx())
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			dests := result.Destinations(false)
			if len(dests) != 1 || dests[0].Mailbox != tc.mailbox || dests[0].Create != tc.create || !slices.Equal(dests[0].Flags, tc.want) {
				t.Fatalf("destinations = %+v, want one copy in %s (create=%v) with flags %v", dests, tc.mailbox, tc.create, tc.want)
			}
		})
	}
}
