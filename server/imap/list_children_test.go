package imap

import (
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
)

// RFC 5258 §4: "If the CHILDREN return option is present, the server MUST
// return these attributes even if their computation is expensive." Disabling
// CHILDREN also removes IMAP4rev2 but leaves LIST-EXTENDED, whose CHILDREN
// return option "MUST be supported by all servers" (§3.2), so RETURN (CHILDREN)
// must still get \HasChildren / \HasNoChildren (#1018). A LIST without it keeps
// them off, which is what disabling CHILDREN is for.
func TestList_ReturnChildrenWithChildrenDisabled(t *testing.T) {
	caps := newDisabledCapsTestServer(t, IMAPServerOptions{DisabledCaps: []string{"CHILDREN"}}).caps
	if caps.Has(imap.CapChildren) || caps.Has(imap.CapIMAP4rev2) || !caps.Has(imap.CapListExtended) {
		t.Fatalf("disabled_caps = [CHILDREN]: want LIST-EXTENDED without CHILDREN and IMAP4rev2, got %v", caps)
	}

	mboxes := []*db.DBMailbox{
		{ID: 1, Name: "Parent", NameKey: "parent", HasChildren: true, Subscribed: true},
		{ID: 2, Name: "Parent/Child", NameKey: "parent/child", Subscribed: true},
	}
	subscribed := map[string]string{"parent": "Parent", "parent/child": "Parent/Child"}
	want := map[string]imap.MailboxAttr{
		"Parent":       imap.MailboxAttrHasChildren,
		"Parent/Child": imap.MailboxAttrHasNoChildren,
	}
	childAttrs := []imap.MailboxAttr{imap.MailboxAttrHasChildren, imap.MailboxAttrHasNoChildren}

	list := func(options *imap.ListOptions) []imap.ListData {
		if options.SelectSubscribed {
			return buildSubscribedList("", []string{"*"}, options, mboxes, visibleSuperiors(mboxes), subscribed, caps, "")
		}
		var l []imap.ListData
		for _, m := range mboxes {
			if data := listMailbox(m, visibleSuperiors(mboxes)[m.NameKey], options, caps, ""); data != nil {
				l = append(l, *data)
			}
		}
		return l
	}

	for _, tc := range []struct {
		cmd     string
		options *imap.ListOptions
	}{
		{`LIST "" "*" RETURN (CHILDREN)`, &imap.ListOptions{ReturnChildren: true}},
		{`LIST (SUBSCRIBED) "" "*" RETURN (CHILDREN)`, &imap.ListOptions{SelectSubscribed: true, ReturnChildren: true}},
	} {
		l := list(tc.options)
		if len(l) != len(mboxes) {
			t.Fatalf("%s: got %d responses, want %d: %+v", tc.cmd, len(l), len(mboxes), l)
		}
		for _, data := range l {
			if !slices.Contains(data.Attrs, want[data.Mailbox]) {
				t.Errorf("%s: %s has attributes %v, want %s", tc.cmd, data.Mailbox, data.Attrs, want[data.Mailbox])
			}
		}
	}

	for _, data := range list(&imap.ListOptions{}) {
		for _, a := range childAttrs {
			if slices.Contains(data.Attrs, a) {
				t.Errorf(`LIST "" "*" with CHILDREN disabled: %s has %s`, data.Mailbox, a)
			}
		}
	}
}

// A \NonExistent name in a LIST (SUBSCRIBED) answer is a LIST response too, and
// RFC 5258 §4 says "If the CHILDREN return option is present, the server MUST
// return these attributes". It has \HasChildren when a mailbox the user can see
// lives under it (§3.5: "\NonExistent \HasChildren", e.g. a shared mailbox whose
// parent is not visible), \HasNoChildren otherwise. With CHILDREN advertised or
// not, the answer was "\NonExistent" alone.
func TestList_ReturnChildrenOnNonExistentNames(t *testing.T) {
	mboxes := []*db.DBMailbox{
		// Visible without its parent, as a shared mailbox granted on its own.
		{ID: 1, Name: "Shared/Team/Sub", NameKey: "shared/team/sub", Subscribed: true},
	}
	subscribed := map[string]string{"gone": "Gone", "shared/team/sub": "Shared/Team/Sub"}
	recursive := &imap.ListOptions{SelectSubscribed: true, SelectRecursiveMatch: true, ReturnChildren: true}

	for name, opts := range map[string]IMAPServerOptions{
		"CHILDREN advertised": {},
		"CHILDREN disabled":   {DisabledCaps: []string{"CHILDREN"}},
	} {
		caps := newDisabledCapsTestServer(t, opts).caps
		for _, tc := range []struct {
			pattern, mailbox string
			want             imap.MailboxAttr
		}{
			{"*", "Gone", imap.MailboxAttrHasNoChildren},
			{"Shared/%", "Shared/Team", imap.MailboxAttrHasChildren},
		} {
			l := buildSubscribedList("", []string{tc.pattern}, recursive, mboxes, visibleSuperiors(mboxes), subscribed, caps, "")
			i := slices.IndexFunc(l, func(d imap.ListData) bool { return d.Mailbox == tc.mailbox })
			if i < 0 {
				t.Fatalf("%s: LIST (SUBSCRIBED RECURSIVEMATCH) \"\" %q RETURN (CHILDREN): no response for %s: %+v", name, tc.pattern, tc.mailbox, l)
			}
			if attrs := l[i].Attrs; !slices.Contains(attrs, imap.MailboxAttrNonExistent) || !slices.Contains(attrs, tc.want) {
				t.Errorf("%s: LIST (SUBSCRIBED RECURSIVEMATCH) \"\" %q RETURN (CHILDREN): %s has %v, want \\NonExistent and %s", name, tc.pattern, tc.mailbox, attrs, tc.want)
			}
		}
	}
}

// RFC 5258 §4: \HasNoChildren "indicates that the mailbox has NO child mailboxes that
// are accessible to the currently authenticated user", and "A server SHOULD NOT set
// [\HasChildren] if there are child mailboxes and the user does not have permission
// to access any of them." The database's has_children looks at the owner's own
// hierarchy, which differs from what the user sees in both directions: the user's
// own shared namespace root had \HasNoChildren above another owner's shared mailbox
// listed right under it, and another owner's shared mailbox had \HasChildren for a
// child the user cannot look up.
func TestList_ChildAttributesFollowVisibleMailboxes(t *testing.T) {
	caps := newDisabledCapsTestServer(t, IMAPServerOptions{}).caps
	mboxes := []*db.DBMailbox{
		// The user's own root: no children of its own.
		{ID: 1, AccountID: 1, Name: "Shared", NameKey: "shared", HasChildren: false, Subscribed: true},
		// Another owner's, visible through an ACL; its own child is not.
		{ID: 2, AccountID: 2, Name: "Shared/Team", NameKey: "shared/team", HasChildren: true, Subscribed: true},
		{ID: 3, AccountID: 1, Name: "INBOX", NameKey: "inbox", HasChildren: false, Subscribed: true},
	}
	want := map[string]imap.MailboxAttr{
		"Shared":      imap.MailboxAttrHasChildren,
		"Shared/Team": imap.MailboxAttrHasNoChildren,
		"INBOX":       imap.MailboxAttrHasNoChildren,
	}
	superiors := visibleSuperiors(mboxes)
	subscribed := map[string]string{"shared": "Shared", "shared/team": "Shared/Team", "inbox": "INBOX"}

	for cmd, l := range map[string][]imap.ListData{
		`LIST "" "*"`: func() (l []imap.ListData) {
			for _, m := range mboxes {
				l = append(l, *listMailbox(m, superiors[m.NameKey], &imap.ListOptions{}, caps, "Shared"))
			}
			return l
		}(),
		`LIST (SUBSCRIBED) "" "*"`: buildSubscribedList("", []string{"*"}, &imap.ListOptions{SelectSubscribed: true}, mboxes, superiors, subscribed, caps, "Shared"),
	} {
		if len(l) != len(mboxes) {
			t.Fatalf("%s: got %d responses, want %d: %+v", cmd, len(l), len(mboxes), l)
		}
		for _, data := range l {
			other := imap.MailboxAttrHasChildren
			if want[data.Mailbox] == other {
				other = imap.MailboxAttrHasNoChildren
			}
			if !slices.Contains(data.Attrs, want[data.Mailbox]) || slices.Contains(data.Attrs, other) {
				t.Errorf("%s: %s has %v, want %s", cmd, data.Mailbox, data.Attrs, want[data.Mailbox])
			}
		}
	}
}
