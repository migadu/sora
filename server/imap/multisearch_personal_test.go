package imap

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	serverPkg "github.com/migadu/sora/server"
)

// TestResolveSearchSourcePersonalNamespace checks the mailboxes ESEARCH IN
// (PERSONAL) searches. RFC 7377 §2.2 takes the source options from RFC 5465 §6,
// and RFC 5465 §6.2 reads: "Personal refers to all selectable mailboxes in the
// user's personal namespace(s), as defined in [RFC2342]." NAMESPACE gives the
// personal namespace the prefix "" and the shared one namespace_prefix, so a
// shared mailbox the user created, and the shared namespace root, are not
// personal although the user owns them. NOTIFY's PERSONAL must name the same
// mailboxes.
func TestResolveSearchSourcePersonalNamespace(t *testing.T) {
	const me, other = 1, 2
	mailbox := func(id, owner int64, name string) *db.DBMailbox {
		return &db.DBMailbox{ID: id, AccountID: owner, Name: name, NameKey: testNameKey(name)}
	}

	tests := []struct {
		name   string
		shared config.SharedMailboxesConfig
		all    []*db.DBMailbox
		want   []string
	}{
		{
			name:   "SharingEnabled",
			shared: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
			all: []*db.DBMailbox{
				mailbox(1, me, "INBOX"),
				mailbox(2, me, "Archive"),
				mailbox(3, me, "SharedDocs"),     // a sibling of the shared root's name
				mailbox(4, me, "Shared"),         // the shared root, which CREATE Shared/Probe makes
				mailbox(5, me, "Shared/Probe"),   // the user's own shared mailbox
				mailbox(6, me, "shared/Lower"),   // the shared namespace in another case
				mailbox(7, other, "Shared/Team"), // another owner's shared mailbox
			},
			want: []string{"INBOX", "Archive", "SharedDocs"},
		},
		{
			name:   "SharingEnabledMultiLevelPrefix",
			shared: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Org/Shared/"},
			all: []*db.DBMailbox{
				mailbox(1, me, "INBOX"),
				mailbox(2, me, "Org"), // above the shared root: personal
				mailbox(3, me, "Org/Shared"),
				mailbox(4, me, "Org/Shared/Probe"),
			},
			want: []string{"INBOX", "Org"},
		},
		{
			// NAMESPACE advertises no shared namespace: every name is personal.
			name:   "SharingDisabled",
			shared: config.SharedMailboxesConfig{Enabled: false, NamespacePrefix: "Shared/"},
			all: []*db.DBMailbox{
				mailbox(1, me, "INBOX"),
				mailbox(2, me, "Shared"),
				mailbox(3, me, "Shared/Probe"),
			},
			want: []string{"INBOX", "Shared", "Shared/Probe"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newPersonalTestSession(t, me, tc.shared)

			got, err := s.resolveSearchSource(context.Background(), &imap.SearchSource{Personal: true}, tc.all)
			if err != nil {
				t.Fatalf("resolveSearchSource: %v", err)
			}
			var names []string
			for _, m := range got {
				names = append(names, m.Name)
			}
			if !slices.Equal(names, tc.want) {
				t.Errorf("ESEARCH IN (PERSONAL) searches %q, want %q", names, tc.want)
			}

			// One rule for both: NOTIFY's PERSONAL watches exactly these mailboxes.
			watch := newTestWatch(imap.NotifyItem{
				MailboxSpec: imap.NotifyMailboxSpecPersonal,
				Events:      []imap.NotifyEvent{imap.NotifyEventMessageNew},
			})
			for _, m := range tc.all {
				inNotify := watch.eventsForMailbox(m.Name, m.NameKey, false, s.sharedNamespaceRoot()) != nil
				if inSearch := slices.Contains(names, m.Name); inNotify != inSearch {
					t.Errorf("%q: NOTIFY PERSONAL watches it = %v, ESEARCH IN (PERSONAL) searches it = %v", m.Name, inNotify, inSearch)
				}
			}
		})
	}
}

// newPersonalTestSession returns a session of account accountID with no
// database behind it, on a server whose shared mailboxes are configured as given.
func newPersonalTestSession(t *testing.T, accountID int64, shared config.SharedMailboxesConfig) *IMAPSession {
	t.Helper()
	addr, err := serverPkg.NewAddress("user@example.com")
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	s := &IMAPSession{server: &IMAPServer{config: &config.Config{SharedMailboxes: shared}}}
	s.IMAPUser = NewIMAPUser(addr, accountID)
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, context.Background(), "IMAP", func(string, ...any) {})
	return s
}
