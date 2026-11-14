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
		})
	}
}
