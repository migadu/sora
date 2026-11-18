package imaptest

import (
	"slices"
	"testing"
)

func portSortThreadTestValues(t *testing.T, text string) []Value {
	t.Helper()
	p := valueParser{data: []byte(text)}
	values, err := p.sequence(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestPortSortKeepsOrderAndRejectsMalformedResults(t *testing.T) {
	reply := Reply{Values: portSortThreadTestValues(t, "SORT 80 7 900")}
	got, err := portSortNumbers(Response{Untagged: []Reply{reply}})
	if err != nil || !slices.Equal(got, []uint64{80, 7, 900}) {
		t.Fatalf("SORT lost its returned order or sparse UIDs: %v %v", got, err)
	}
	for _, values := range []string{"SORT 1 1", "SORT 0", "SORT NIL", "SORT (1 2)"} {
		r := Response{Untagged: []Reply{{Values: portSortThreadTestValues(t, values)}}}
		if _, err := portSortNumbers(r); err == nil {
			t.Errorf("accepted invalid SORT result %s", values)
		}
	}
	if _, err := portSortNumbers(Response{}); err == nil {
		t.Error("missing SORT data accepted")
	}
	if _, err := portSortNumbers(Response{Untagged: []Reply{reply, reply}}); err == nil {
		t.Error("duplicate SORT data accepted")
	}
}

func TestPortThreadShapePreservesRelationshipsAndUIDMapping(t *testing.T) {
	shape := portSortThreadTestValues(t, "(1 (2 4)(3))((5)(6))")
	got, err := portThreadShape(shape, []uint64{7, 80, 900, 901, 1200, 2000})
	if err != nil || got != "(7 (80 901) (900))((1200) (2000))" {
		t.Fatalf("THREAD mapping/grouping changed: %q %v", got, err)
	}
	chain, err := portThreadShape(portSortThreadTestValues(t, "(1 2 3)"), nil)
	if err != nil {
		t.Fatal(err)
	}
	siblings, err := portThreadShape(portSortThreadTestValues(t, "(1 (2)(3))"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if chain == siblings {
		t.Fatal("THREAD canonicalization conflates chains and sibling branches")
	}
	roots, err := portThreadShape(portSortThreadTestValues(t, "(1)(2)"), nil)
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := portThreadShape(portSortThreadTestValues(t, "((1)(2))"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if roots == dummy {
		t.Fatal("THREAD canonicalization lost the dummy parent")
	}
}

func TestPortThreadRejectsInvalidTrees(t *testing.T) {
	for _, text := range []string{"()", "(0)", "(NIL)", "1", "(1)(1)", "(1 (2))", "((1))", "(1 (2)(3) 4)"} {
		if _, err := portThreadShape(portSortThreadTestValues(t, text), nil); err == nil {
			t.Errorf("accepted invalid THREAD tree %s", text)
		}
	}
	if _, err := portThreadShape(portSortThreadTestValues(t, "(1 3)"), []uint64{4, 7}); err == nil {
		t.Error("THREAD expectation accepted a nonexistent sequence")
	}
}

func TestPortSortThreadDateComparisonUsesInstants(t *testing.T) {
	for _, pair := range [][2]string{
		{"22-Feb-2008 23:00:00 +0200", "22-Feb-2008 21:00:00 +0000"},
		{" 1-Feb-2008 00:00:00 +0000", "01-Feb-2008 00:00:00 +0000"},
	} {
		equal, err := portSortThreadDateEqual(pair[0], pair[1])
		if err != nil || !equal {
			t.Errorf("equivalent dates differed: %v %v", pair, err)
		}
	}
	if equal, err := portSortThreadDateEqual("22-Feb-2008 23:00:00 +0200", "22-Feb-2008 23:00:01 +0200"); err != nil || equal {
		t.Errorf("different fixture instants compared equal: equal=%t err=%v", equal, err)
	}
	if _, err := portSortThreadDateEqual("not an IMAP date", "22-Feb-2008 23:00:00 +0200"); err == nil {
		t.Error("malformed server INTERNALDATE accepted")
	}
}

func TestPortSortThreadFixtureExpectationsAreComplete(t *testing.T) {
	for _, def := range portSortDefinitions() {
		messages, err := portFixture(def.name)
		if err != nil {
			t.Fatal(err)
		}
		dates, err := portFixtureDates(def.name)
		if err != nil || len(dates) != len(messages) {
			t.Fatalf("fixture %s date/message count mismatch: %d %d %v", def.name, len(dates), len(messages), err)
		}
		for _, step := range def.steps {
			if len(step.order) != len(messages) {
				t.Errorf("%s %s covers %d of %d messages", def.name, step.criteria, len(step.order), len(messages))
			}
			order := slices.Clone(step.order)
			slices.Sort(order)
			for i, seq := range order {
				if seq != uint64(i+1) {
					t.Errorf("%s %s is not a permutation: %v", def.name, step.criteria, step.order)
					break
				}
			}
		}
	}
	for _, def := range portThreadDefinitions() {
		messages, err := portFixture(def.name)
		if err != nil {
			t.Fatal(err)
		}
		initial := len(messages)
		if def.initial >= 0 {
			initial = def.initial
		}
		uids := make([]uint64, initial)
		for i := range uids {
			uids[i] = uint64(100 + i*3)
		}
		if _, err := portThreadShape(portSortThreadTestValues(t, def.shape), uids); err != nil {
			t.Errorf("fixture %s has invalid initial tree: %v", def.name, err)
		}
	}
}

func TestPortDisplaySortValueFollowsEnvelopeFallbacks(t *testing.T) {
	for _, tc := range []struct{ addresses, want string }{
		{"NIL", ""},
		{"((\"=?iso-8859-1?q?Foo_Aar?=\" NIL \"e\" \"f.g\"))", "foo aar"},
		{"((\"\" NIL \"Local\" \"Example.TEST\"))", "local@example.test"},
		{"((NIL NIL \"Local\" NIL))", "local"},
		{"((NIL NIL NIL NIL))", ""},
		{"((NIL NIL \"GroupName\" NIL)(NIL NIL \"first-member\" \"example.test\"))", "groupname"},
	} {
		p := valueParser{data: []byte(tc.addresses)}
		value, err := p.value(0)
		if err != nil {
			t.Fatal(err)
		}
		got, err := portDisplaySortValue(value)
		if err != nil || got != tc.want {
			t.Errorf("DISPLAY %s = %q, want %q (error=%v)", tc.addresses, got, tc.want, err)
		}
	}
}

func TestPortDisplaySortUsesActualEnvelopeAndStableReverseTies(t *testing.T) {
	// A server may return NIL for the fixture's malformed local-only address;
	// RFC 5957 then requires the empty sort value rather than guessed text.
	keys := []string{"foo bar", "b@c.d", "", "foo aar", "foo car"}
	if got := portDisplayOrder(keys, false); !slices.Equal(got, []uint64{3, 2, 4, 1, 5}) {
		t.Errorf("DISPLAY order = %v", got)
	}
	if got := portDisplayOrder(keys, true); !slices.Equal(got, []uint64{5, 1, 4, 2, 3}) {
		t.Errorf("reverse DISPLAY order = %v", got)
	}
	if got := portDisplayOrder([]string{"same", "same", "same"}, true); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Errorf("reverse changed implicit sequence tie-break: %v", got)
	}
}
