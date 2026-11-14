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
		{ID: 1, Name: "Parent", HasChildren: true, Subscribed: true},
		{ID: 2, Name: "Parent/Child", Subscribed: true},
	}
	subscribed := map[string]string{"parent": "Parent", "parent/child": "Parent/Child"}
	want := map[string]imap.MailboxAttr{
		"Parent":       imap.MailboxAttrHasChildren,
		"Parent/Child": imap.MailboxAttrHasNoChildren,
	}
	childAttrs := []imap.MailboxAttr{imap.MailboxAttrHasChildren, imap.MailboxAttrHasNoChildren}

	list := func(options *imap.ListOptions) []imap.ListData {
		if options.SelectSubscribed {
			return buildSubscribedList("", []string{"*"}, options, mboxes, subscribed, caps, "")
		}
		var l []imap.ListData
		for _, m := range mboxes {
			if data := listMailbox(m, options, caps, ""); data != nil {
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
