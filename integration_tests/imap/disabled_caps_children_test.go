//go:build integration

package imap_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// TestIMAP_DisabledChildrenKeepsReturnChildren: the steps of #1018. Disabling
// CHILDREN removes IMAP4rev2 too but leaves LIST-EXTENDED, and RFC 5258 §4 says
// "If the CHILDREN return option is present, the server MUST return these
// attributes even if their computation is expensive." A LIST without RETURN
// (CHILDREN) keeps them off.
func TestIMAP_DisabledChildrenKeepsReturnChildren(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	disabled := []string{"CHILDREN"}

	for _, tc := range []struct {
		name      string
		configure func(*imapserver.IMAPServerOptions)
		identify  bool
	}{
		{"disabled_caps", func(o *imapserver.IMAPServerOptions) { o.DisabledCaps = disabled }, false},
		{"client_filters", func(o *imapserver.IMAPServerOptions) {
			o.CapabilityFilters = []config.ClientCapabilityFilter{{ClientName: "^buggy$", DisableCaps: disabled}}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := dialDisabledCaps(t, tc.configure, tc.identify)

			capLine, _, _ := strings.Cut(c.do("CAPABILITY"), "\r\n")
			caps := strings.Fields(capLine)
			for _, name := range []string{"CHILDREN", "IMAP4rev2"} {
				if slices.Contains(caps, name) {
					t.Errorf("CAPABILITY still offers %s:\n%s", name, capLine)
				}
			}
			if !slices.Contains(caps, "LIST-EXTENDED") {
				t.Fatalf("CAPABILITY lost LIST-EXTENDED:\n%s", capLine)
			}

			c.mustOK("CREATE Parent/Child")
			c.mustOK("SUBSCRIBE Parent")
			c.mustOK("SUBSCRIBE Parent/Child")
			c.mustOK("SUBSCRIBE Parent/Gone") // no mailbox: \NonExistent

			live := map[string]string{"Parent": `\HasChildren`, "Parent/Child": `\HasNoChildren`}
			subscribed := map[string]string{"Parent/Gone": `\HasNoChildren`}
			maps.Copy(subscribed, live)
			for cmd, want := range map[string]map[string]string{
				`LIST "" "Parent*" RETURN (CHILDREN)`:              live,
				`LIST (SUBSCRIBED) "" "Parent*" RETURN (CHILDREN)`: subscribed,
			} {
				resp := c.mustOK(cmd)
				for mailbox, attr := range want {
					attrs, ok := listedAttrs(resp, mailbox)
					if !ok {
						t.Errorf("%s: no LIST response for %s:\n%s", cmd, mailbox, resp)
					} else if !slices.Contains(attrs, attr) {
						t.Errorf("%s: %s has (%s), want %s:\n%s", cmd, mailbox, strings.Join(attrs, " "), attr, resp)
					}
				}
			}

			resp := c.mustOK(`LIST "" "Parent*"`)
			if strings.Contains(resp, `\HasChildren`) || strings.Contains(resp, `\HasNoChildren`) {
				t.Errorf(`LIST "" "Parent*" with CHILDREN disabled returned child attributes:\n%s`, resp)
			}
		})
	}
}

// listedAttrs returns the attributes of the "* LIST" line for mailbox in resp.
func listedAttrs(resp, mailbox string) ([]string, bool) {
	for _, line := range strings.Split(resp, "\r\n") {
		rest, ok := strings.CutPrefix(line, "* LIST (")
		if !ok {
			continue
		}
		attrs, rest, ok := strings.Cut(rest, ") ")
		if !ok {
			continue
		}
		if _, name, ok := strings.Cut(rest, " "); ok && strings.Trim(name, `"`) == mailbox {
			return strings.Fields(attrs), true
		}
	}
	return nil, false
}
