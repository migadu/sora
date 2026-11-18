package imaptest

import (
	"errors"
	"slices"
	"testing"
)

func pmTestResponse(t *testing.T, lines ...string) Response {
	t.Helper()
	r := Response{Status: "OK"}
	for _, line := range lines {
		_, reply, err := parseReply([]byte(line + "\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		r.Untagged = append(r.Untagged, reply)
	}
	return r
}

func TestPortMailboxUIDRepliesUseTheViewAtEachWirePosition(t *testing.T) {
	before := []uint64{10, 20, 30, 40}
	for _, lines := range [][]string{
		{"* 2 FETCH (UID 20)", "* 1 EXPUNGE", "* 2 FETCH (UID 30)", "* 2 EXPUNGE", "* 2 FETCH (UID 40)"},
		{"* 1 EXPUNGE", "* 1 FETCH (UID 20)", "* 2 EXPUNGE", "* 2 FETCH (UID 40)"},
	} {
		view, seen, err := pmApplyUIDReplies(before, pmTestResponse(t, lines...))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(view, []uint64{20, 40}) || !slices.Contains(seen, uint64(20)) || !slices.Contains(seen, uint64(40)) {
			t.Fatalf("view=%v seen=%v", view, seen)
		}
	}
	for _, line := range []string{"* 99 FETCH (UID 20)", "* 2 FETCH (UID 10)"} {
		if _, _, err := pmApplyUIDReplies(before, pmTestResponse(t, line)); err == nil {
			t.Fatalf("accepted invalid sequence/UID pair: %s", line)
		}
	}
	view, _, err := pmApplySequenceReplies(before, pmTestResponse(t, "* 1 EXPUNGE", "* 1 FETCH (UID 20)"))
	if err != nil || !slices.Equal(view, []uint64{20, 30, 40}) {
		t.Fatalf("queued EXPUNGE before FETCH was rejected: %v %v", view, err)
	}
	if _, _, err := pmApplySequenceReplies(before, pmTestResponse(t, "* 2 FETCH (UID 20)", "* 1 EXPUNGE")); err == nil {
		t.Fatal("EXPUNGE after sequence FETCH data was accepted")
	}
}

func TestPortMailboxPersistentSelectionPrecondition(t *testing.T) {
	if err := pmPersistentSelection(7, 7); err != nil {
		t.Fatal(err)
	}
	var skip *SkipError
	if err := pmPersistentSelection(7, 8); !errors.As(err, &skip) {
		t.Fatalf("new UID generation should skip persistent comparison: %v", err)
	}
	for _, after := range []uint64{0, 6} {
		if err := pmPersistentSelection(7, after); err == nil {
			t.Fatalf("invalid UIDVALIDITY %d accepted", after)
		}
	}
}

func TestPortMailboxFetchMacrosRejectStableMalformedMetadata(t *testing.T) {
	response := pmTestResponse(t, "* 1 FETCH (FLAGS (\\Seen $server-keyword) INTERNALDATE \"12-May-2026 09:30:00 +0000\" RFC822.SIZE 123 ENVELOPE (NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL) BODY (\"TEXT\" \"PLAIN\"))")
	rows, err := response.Fetches()
	if err != nil {
		t.Fatal(err)
	}
	valid := rows[0]
	if _, _, err := pmMacroMetadata(valid, "FULL"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		key   string
		value Value
	}{{"FLAGS", Value{Text: "garbage"}}, {"RFC822.SIZE", Value{Text: "garbage"}}, {"INTERNALDATE", Value{Text: "garbage"}}, {"ENVELOPE", Value{IsList: true, List: []Value{{Text: "not-an-envelope"}}}}, {"BODY", Value{Text: "not-a-structure"}}} {
		attrs := map[string]Value{}
		for k, v := range valid.Attrs {
			attrs[k] = v
		}
		attrs[tc.key] = tc.value
		if _, _, err := pmMacroMetadata(Fetch{Seq: 1, Attrs: attrs}, "FULL"); err == nil {
			t.Fatalf("malformed %s passed macro validation", tc.key)
		}
	}
}

func TestPortMailboxRedundantRecursiveParentsArePermitted(t *testing.T) {
	if err := pmOptionalRecursiveParent(map[string]pmListed{}, "parent"); err != nil {
		t.Fatal(err)
	}
	items, err := pmListData(pmTestResponse(t, "* LIST (\\HasChildren) \"/\" parent (CHILDINFO (SUBSCRIBED))"), "LIST")
	if err != nil {
		t.Fatal(err)
	}
	if err := pmOptionalRecursiveParent(items, "parent"); err != nil {
		t.Fatal(err)
	}
	items["parent"] = pmListed{Flags: Value{IsList: true, List: []Value{{Text: "\\Subscribed"}}}}
	if err := pmOptionalRecursiveParent(items, "parent"); err == nil {
		t.Fatal("incorrectly subscribed redundant parent passed")
	}
}

func TestPortMailboxExpungeViewsAcceptBothLegalOrders(t *testing.T) {
	for _, lines := range [][]string{{"* 2 EXPUNGE", "* 3 EXPUNGE"}, {"* 4 EXPUNGE", "* 2 EXPUNGE"}} {
		view, err := pmExpectExpunges([]uint64{10, 20, 30, 40}, pmTestResponse(t, lines...), 20, 40)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(view, []uint64{10, 30}) {
			t.Fatalf("view after %v = %v", lines, view)
		}
	}
	if _, _, err := pmApplyExpunges([]uint64{10, 20, 30, 40}, pmTestResponse(t, "* 2 EXPUNGE", "* 4 EXPUNGE")); err == nil {
		t.Fatal("accepted an original sequence number after the view shrank")
	}
}

func TestPortMailboxUIDReplyChecksIgnoreUnsolicitedFlags(t *testing.T) {
	r := pmTestResponse(t, "* 1 FETCH (FLAGS (\\Seen))", "* 2 FETCH (UID 301)", "* 4 FETCH (UID 907)")
	if err := pmFetchUIDs(r, map[uint64]uint64{2: 301, 4: 907}); err != nil {
		t.Fatal(err)
	}
	if err := pmFetchUIDs(r, map[uint64]uint64{2: 301, 4: 908}); err == nil {
		t.Fatal("wrong UID mapping passed")
	}
	if err := pmNoExpunge(pmTestResponse(t, "* 2 EXPUNGE")); err == nil {
		t.Fatal("sequence command EXPUNGE passed")
	}
}

func TestPortMailboxExtendedListChildInfoVariants(t *testing.T) {
	for _, line := range []string{
		"* LIST (\\HasChildren) \"/\" parent (CHILDINFO (SUBSCRIBED))",
		"* LIST (\\HasChildren) \"/\" parent CHILDINFO (\"subscribed\")",
	} {
		items, err := pmListData(pmTestResponse(t, line), "LIST")
		if err != nil {
			t.Fatal(err)
		}
		if err := pmChildInfo(items["parent"]); err != nil {
			t.Fatal(err)
		}
		if err := pmSystemFlags(items["parent"].Flags, []string{"\\HasChildren"}, []string{"\\Subscribed"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := pmChildInfo(pmListed{}); err == nil {
		t.Fatal("missing required CHILDINFO passed")
	}
}

func TestPortMailboxCatalogAccountsForAssignedScripts(t *testing.T) {
	want := []string{"append", "atoms", "close", "copy", "expunge", "expunge2", "fetch", "list", "listext", "logout", "mutf7", "pipeline", "pipeline-connections", "select", "store", "subscribe", "uidplus", "uidvalidity", "uidvalidity-rename"}
	var got []string
	for _, c := range portMailboxCases() {
		if c.Name != "imaptest/"+c.Upstream || c.Run == nil || c.RFC == "" {
			t.Fatalf("invalid upstream case: %+v", c)
		}
		got = append(got, c.Upstream)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("ported %v, want %v", got, want)
	}
}
