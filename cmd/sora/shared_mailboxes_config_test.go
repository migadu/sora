package main

import (
	"strings"
	"testing"
)

// TestStartupRefusesInvalidSharedNamespacePrefix: with sharing enabled, a
// [shared_mailboxes] namespace_prefix that is not a mailbox name followed by the
// hierarchy delimiter stops the server at start-up (#338). The personal namespace has
// the empty prefix, so the shared namespace is told apart by name alone: an empty prefix
// put every mailbox in it, and "Shared" also took in personal names such as "SharedDocs".
func TestStartupRefusesInvalidSharedNamespacePrefix(t *testing.T) {
	tests := []struct {
		name    string
		section string
		wantErr string // substring of the refusal, "" when start-up goes on
	}{
		{name: "default prefix", section: "enabled = true\n"},
		{name: "Shared/", section: "enabled = true\nnamespace_prefix = \"Shared/\"\n"},
		{name: "#shared/", section: "enabled = true\nnamespace_prefix = \"#shared/\"\n"},
		{name: "two levels", section: "enabled = true\nnamespace_prefix = \"Public/Rooms/\"\n"},
		{name: "disabled with an empty prefix", section: "enabled = false\nnamespace_prefix = \"\"\n"},
		{name: "empty", section: "enabled = true\nnamespace_prefix = \"\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix ""`},
		{name: "no trailing delimiter", section: "enabled = true\nnamespace_prefix = \"Shared\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "Shared"`},
		{name: "delimiter only", section: "enabled = true\nnamespace_prefix = \"/\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "/"`},
		{name: "empty level", section: "enabled = true\nnamespace_prefix = \"Shared//\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "Shared//"`},
		{name: "leading delimiter", section: "enabled = true\nnamespace_prefix = \"/Shared/\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "/Shared/"`},
		{name: "personal inbox", section: "enabled = true\nnamespace_prefix = \"INBOX/\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "INBOX/"`},
		{name: "personal inbox case variant", section: "enabled = true\nnamespace_prefix = \"Inbox/\"\n",
			wantErr: `[shared_mailboxes]: namespace_prefix "Inbox/"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := storageTOML + "[shared_mailboxes]\n" + tt.section +
				"\n[[server]]\ntype = \"imap\"\nname = \"imap\"\naddr = \"127.0.0.1:0\"\n"
			refused, problems, out := checkStartupConfig(t, content)
			if tt.wantErr == "" {
				if refused {
					t.Fatalf("start-up refused a valid configuration:\n%s%s", problems, out)
				}
				return
			}
			if !refused {
				t.Fatalf("start-up went on; want it refused with %q", tt.wantErr)
			}
			if !strings.Contains(problems, tt.wantErr) {
				t.Errorf("start-up refused, but the log does not say %q:\nlog:\n%s\noutput:\n%s", tt.wantErr, problems, out)
			}
		})
	}
}
