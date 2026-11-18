package imaptest

import (
	"fmt"
	"mime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// These cases retain the complete SORT/THREAD expectations of the pinned
// imaptest corpus. Fixture envelope dates are supplied explicitly as
// INTERNALDATE, so arrival sorting and missing-Date fallback are reproducible.
// See testdata/imaptest for the upstream fixture attribution.
func portSortThreadCases() []Case {
	cases := make([]Case, 0, 17)
	for _, definition := range portSortDefinitions() {
		def := definition
		rfc := "https://www.rfc-editor.org/rfc/rfc5256.html#section-3"
		capability := "SORT"
		if strings.HasPrefix(def.name, "sort-display-") {
			rfc = "https://www.rfc-editor.org/rfc/rfc5957.html#section-4"
			capability = "SORT=DISPLAY"
		}
		cases = append(cases, portCase(def.name, "Pinned fixture sorting, reverse keys and tie-breaks", rfc, []string{capability}, func(s *Session) error {
			return portSortScenario(s, def)
		}))
	}
	for _, definition := range portThreadDefinitions() {
		def := definition
		cases = append(cases, portCase(def.name, "Pinned fixture threading, grouping and message changes", "https://www.rfc-editor.org/rfc/rfc5256.html#section-3", []string{"THREAD=" + def.algorithm}, func(s *Session) error {
			return portThreadScenario(s, def)
		}))
	}
	return cases
}

type portSortExpectation struct {
	criteria string
	order    []uint64
}

type portSortDefinition struct {
	name  string
	steps []portSortExpectation
}

func portSortDefinitions() []portSortDefinition {
	return []portSortDefinition{
		{"sort-addresses", []portSortExpectation{
			{"FROM", []uint64{3, 1, 2}}, {"TO", []uint64{3, 1, 2}}, {"CC", []uint64{3, 1, 2}},
			{"REVERSE FROM", []uint64{1, 2, 3}}, {"REVERSE TO", []uint64{1, 2, 3}}, {"REVERSE CC", []uint64{1, 2, 3}},
			{"FROM REVERSE ARRIVAL", []uint64{3, 2, 1}}, {"TO REVERSE ARRIVAL", []uint64{3, 2, 1}}, {"CC REVERSE ARRIVAL", []uint64{3, 2, 1}},
		}},
		{"sort-arrival", []portSortExpectation{
			{"ARRIVAL", []uint64{1, 3, 2, 4, 5}}, {"REVERSE ARRIVAL", []uint64{2, 4, 5, 3, 1}}, {"ARRIVAL REVERSE SIZE", []uint64{1, 3, 5, 4, 2}},
		}},
		{"sort-date", []portSortExpectation{
			{"DATE", []uint64{1, 3, 7, 5, 2, 4, 6}}, {"REVERSE DATE", []uint64{2, 4, 6, 5, 3, 7, 1}}, {"DATE REVERSE SIZE", []uint64{1, 7, 3, 5, 6, 4, 2}},
		}},
		{"sort-display-from", []portSortExpectation{
			{"DISPLAYFROM", []uint64{2, 3, 4, 1, 5}}, {"REVERSE DISPLAYFROM", []uint64{5, 1, 4, 3, 2}},
		}},
		{"sort-display-to", []portSortExpectation{
			{"DISPLAYTO", []uint64{6, 2, 3, 8, 4, 1, 5, 7}}, {"REVERSE DISPLAYTO", []uint64{7, 5, 1, 4, 8, 3, 2, 6}},
		}},
		{"sort-size", []portSortExpectation{
			{"SIZE", []uint64{1, 8, 2, 6, 3, 5, 4, 7}}, {"REVERSE SIZE", []uint64{4, 7, 3, 5, 2, 6, 1, 8}}, {"SIZE REVERSE ARRIVAL", []uint64{8, 1, 6, 2, 5, 3, 7, 4}},
		}},
		{"sort-subject", []portSortExpectation{
			{"SUBJECT", []uint64{9, 10, 1, 14, 3, 5, 11, 6, 15, 2, 7, 12, 13, 8, 4}},
			{"REVERSE SUBJECT", []uint64{4, 8, 2, 7, 12, 13, 15, 6, 3, 5, 11, 14, 1, 9, 10}},
			{"SUBJECT REVERSE SIZE", []uint64{10, 9, 1, 14, 11, 5, 3, 6, 15, 13, 12, 7, 2, 8, 4}},
		}},
	}
}

func portSortScenario(s *Session, def portSortDefinition) error {
	_, messages, err := portMailbox(s, def.name, -1, true)
	if err != nil {
		return err
	}
	dates, err := portFixtureDates(def.name)
	if err != nil {
		return err
	}
	if err := portSortThreadDates(s.Client, dates); err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == len(messages), "fixture %s contains %d messages but SELECT/FETCH exposed %d", def.name, len(messages), len(uids)); err != nil {
		return err
	}
	var displayKeys []string
	if strings.HasPrefix(def.name, "sort-display-") {
		field := 2 // ENVELOPE from
		if def.name == "sort-display-to" {
			field = 5
		}
		displayKeys, err = portDisplayEnvelopeKeys(s.Client, field, len(messages))
		if err != nil {
			return err
		}
	}
	for _, step := range def.steps {
		for _, uid := range []bool{false, true} {
			command := "SORT (" + step.criteria + ") US-ASCII ALL"
			want := slices.Clone(step.order)
			if displayKeys != nil {
				// RFC 5957 section 4 derives DISPLAY values from FETCH
				// ENVELOPE. The upstream fixtures include malformed local-only
				// addresses; their parsing is not standardized, so do not
				// impose Dovecot's choice of reconstructed envelope here.
				want = portDisplayOrder(displayKeys, strings.HasPrefix(step.criteria, "REVERSE "))
			}
			if uid {
				command = "UID " + command
				for i, seq := range want {
					if seq == 0 || seq > uint64(len(uids)) {
						return fmt.Errorf("invalid pinned sort expectation %d for %s", seq, def.name)
					}
					want[i] = uids[seq-1]
				}
			}
			r, err := s.Client.OK(command)
			if err != nil {
				return err
			}
			if !uid && len(r.Data("EXPUNGE")) != 0 {
				return Check(false, "SORT sent EXPUNGE during a sequence-number command")
			}
			got, err := portSortNumbers(r)
			if err != nil {
				return err
			}
			if err := Check(slices.Equal(got, want), "%s returned %v, want %v", command, got, want); err != nil {
				return err
			}
		}
	}
	return nil
}

func portDisplayEnvelopeKeys(c *Client, field, count int) ([]string, error) {
	fetched, err := coreFetch(c, "FETCH 1:* ENVELOPE")
	if err != nil {
		return nil, err
	}
	keys := make([]string, count)
	seen := make(map[uint64]bool)
	for _, f := range fetched {
		envelope, ok := f.Attrs["ENVELOPE"]
		if !ok {
			continue
		} // unrelated unsolicited FLAGS update
		if err := Check(f.Seq > 0 && f.Seq <= uint64(count) && envelope.IsList && len(envelope.List) == 10, "DISPLAY sort fixture returned malformed ENVELOPE for sequence %d", f.Seq); err != nil {
			return nil, err
		}
		key, err := portDisplaySortValue(envelope.List[field])
		if err != nil {
			return nil, err
		}
		keys[f.Seq-1] = key
		seen[f.Seq] = true
	}
	if err := Check(len(seen) == count, "DISPLAY sort fixture returned %d ENVELOPE values, want %d", len(seen), count); err != nil {
		return nil, err
	}
	return keys, nil
}

// The DISPLAY oracle follows RFC 5957 sections 3 and 4 literally: decode the
// first address's name, then fall back to mailbox@host, mailbox, or the empty
// string. Group markers remain significant when present in the envelope;
// correctness of the envelope itself is checked by the fetch-envelope port.
func portDisplaySortValue(addresses Value) (string, error) {
	if addresses.IsNil {
		return "", nil
	}
	if err := Check(addresses.IsList && len(addresses.List) > 0 && addresses.List[0].IsList && len(addresses.List[0].List) == 4, "DISPLAY sort received malformed envelope address list"); err != nil {
		return "", err
	}
	address := addresses.List[0].List
	if !address[0].IsNil {
		name, err := new(mime.WordDecoder).DecodeHeader(address[0].Text)
		if err != nil {
			return "", Check(false, "DISPLAY sort could not decode envelope display-name")
		}
		if name != "" {
			return strings.ToLower(name), nil
		}
	}
	if !address[2].IsNil {
		if !address[3].IsNil {
			return strings.ToLower(address[2].Text + "@" + address[3].Text), nil
		}
		return strings.ToLower(address[2].Text), nil
	}
	return "", nil
}

func portDisplayOrder(keys []string, reverse bool) []uint64 {
	order := make([]uint64, len(keys))
	for i := range order {
		order[i] = uint64(i + 1)
	}
	slices.SortFunc(order, func(a, b uint64) int {
		comparison := strings.Compare(keys[a-1], keys[b-1])
		if reverse {
			comparison = -comparison
		}
		if comparison != 0 {
			return comparison
		}
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	})
	return order
}

func portSortNumbers(r Response) ([]uint64, error) {
	replies := r.Data("SORT")
	if err := Check(len(replies) == 1, "SORT returned %d data responses, want 1", len(replies)); err != nil {
		return nil, err
	}
	var result []uint64
	seen := make(map[uint64]bool)
	for _, value := range replies[0].Values[1:] {
		n, err := value.Uint()
		if err != nil || n == 0 {
			return nil, Check(false, "SORT returned a non-positive message number")
		}
		if seen[n] {
			return nil, Check(false, "SORT returned duplicate message number %d", n)
		}
		seen[n] = true
		result = append(result, n)
	}
	return result, nil
}

type portThreadDefinition struct {
	name      string
	algorithm string
	initial   int
	shape     string
}

func portThreadDefinitions() []portThreadDefinition {
	return []portThreadDefinition{
		{"thread", "REFERENCES", -1, "(3 2)(1)"},
		{"thread-orderedsubject", "ORDEREDSUBJECT", -1, "(1)(2 (7)(12)(13))(3 (5)(11))(4)(6)(8)(9 10)(14)(15)"},
		{"thread-orderedsubject2", "ORDEREDSUBJECT", -1, "(4 (2)(8)(6))(3 (1)(7)(5))"},
		{"thread2", "REFERENCES", -1, "(1)(2)"},
		{"thread3", "REFERENCES", -1, "(1 2)"},
		{"thread4", "REFERENCES", -1, "(1 2)"},
		{"thread5", "REFERENCES", 4, "(1 (2 4)(3))"},
		{"thread6", "REFERENCES", -1, "((1)(2))"},
		{"thread7", "REFERENCES", -1, "(1 (2 3)(4))"},
		{"thread8", "REFERENCES", 2, "(1 2)"},
	}
}

func portThreadScenario(s *Session, def portThreadDefinition) error {
	box, messages, err := portMailbox(s, def.name, def.initial, true)
	if err != nil {
		return err
	}
	dates, err := portFixtureDates(def.name)
	if err != nil {
		return err
	}
	initial := len(messages)
	if def.initial >= 0 {
		initial = def.initial
	}
	if err := portSortThreadDates(s.Client, dates[:initial]); err != nil {
		return err
	}
	if err := portThreadCheck(s.Client, def.algorithm, def.shape); err != nil {
		return err
	}
	var remove, nextShape, appendShape string
	var appendIndex int
	var appendedDates []string
	switch def.name {
	case "thread":
		remove, nextShape = "1", "(2 1)"
	case "thread5":
		remove, nextShape, appendShape, appendIndex = "1,2", "(1)(2)", "(1)((2)(3))", 4
		appendedDates = dates[2:5]
	case "thread7":
		remove, nextShape = "2", "(1 3 2)"
	case "thread8":
		remove, nextShape, appendShape, appendIndex = "2", "(1)", "(1 2)", 2
		appendedDates = []string{dates[0], dates[2]}
	default:
		return nil
	}
	if _, err := s.Client.OK("STORE " + remove + " +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	if _, err := s.Client.OK("EXPUNGE"); err != nil {
		return err
	}
	if err := portThreadCheck(s.Client, def.algorithm, nextShape); err != nil {
		return err
	}
	if appendShape != "" {
		if _, err := s.Client.Append(box, nil, dates[appendIndex], messages[appendIndex]); err != nil {
			return err
		}
		if err := portSortThreadDates(s.Client, appendedDates); err != nil {
			return err
		}
		if err := portThreadCheck(s.Client, def.algorithm, appendShape); err != nil {
			return err
		}
	}
	return nil
}

func portThreadCheck(c *Client, algorithm, shape string) error {
	p := valueParser{data: []byte(shape)}
	expected, err := p.sequence(0, 0)
	if err != nil {
		return fmt.Errorf("invalid pinned THREAD expectation: %w", err)
	}
	uids, err := coreUIDs(c)
	if err != nil {
		return err
	}
	for _, uid := range []bool{false, true} {
		command := "THREAD " + algorithm + " US-ASCII ALL"
		var mapping []uint64
		if uid {
			command = "UID " + command
			mapping = uids
		}
		want, err := portThreadShape(expected, mapping)
		if err != nil {
			return fmt.Errorf("invalid pinned THREAD expectation: %w", err)
		}
		r, err := c.OK(command)
		if err != nil {
			return err
		}
		if !uid && len(r.Data("EXPUNGE")) != 0 {
			return Check(false, "THREAD sent EXPUNGE during a sequence-number command")
		}
		replies := r.Data("THREAD")
		if err := Check(len(replies) == 1, "THREAD returned %d data responses, want 1", len(replies)); err != nil {
			return err
		}
		got, err := portThreadShape(replies[0].Values[1:], nil)
		if err != nil {
			return err
		}
		if err := Check(got == want, "%s returned %s, want %s", command, got, want); err != nil {
			return err
		}
	}
	return nil
}

// portThreadShape canonicalizes only presentation whitespace and UID labels.
// Root order, sibling order, dummy roots and parent/child relationships remain
// significant. Flattening the forest would hide the cases these fixtures test.
func portThreadShape(values []Value, mapping []uint64) (string, error) {
	seen := make(map[uint64]bool)
	var list func(Value) (string, error)
	list = func(value Value) (string, error) {
		if !value.IsList || len(value.List) == 0 {
			return "", Check(false, "THREAD returned an empty or non-list thread")
		}
		var parts []string
		numbers, children := 0, 0
		for _, child := range value.List {
			if child.IsList {
				children++
				rendered, err := list(child)
				if err != nil {
					return "", err
				}
				parts = append(parts, rendered)
				continue
			}
			if children != 0 {
				return "", Check(false, "THREAD returned a message after nested child threads")
			}
			n, err := child.Uint()
			if err != nil || n == 0 {
				return "", Check(false, "THREAD returned a non-positive message number")
			}
			if mapping != nil {
				if n > uint64(len(mapping)) {
					return "", Check(false, "THREAD expectation refers to nonexistent sequence %d", n)
				}
				n = mapping[n-1]
			}
			if seen[n] {
				return "", Check(false, "THREAD returned message %d more than once", n)
			}
			seen[n] = true
			numbers++
			parts = append(parts, strconv.FormatUint(n, 10))
		}
		if children == 1 || numbers == 0 && children < 2 {
			return "", Check(false, "THREAD nesting must contain at least two child thread lists")
		}
		return "(" + strings.Join(parts, " ") + ")", nil
	}
	var roots []string
	for _, value := range values {
		rendered, err := list(value)
		if err != nil {
			return "", err
		}
		roots = append(roots, rendered)
	}
	return strings.Join(roots, ""), nil
}

// Honoring APPEND's requested INTERNALDATE is a SHOULD, not a MUST. The fixed
// corpus requires those timestamps for an unambiguous expected order; make an
// unmet fixture precondition an explicit skip rather than mislabeling the
// server's SORT/THREAD implementation as nonconformant.
func portSortThreadDates(c *Client, dates []string) error {
	fetched, err := coreFetch(c, "FETCH 1:* INTERNALDATE")
	if err != nil {
		return err
	}
	actual := make(map[uint64]string)
	for _, f := range fetched {
		if date, ok := f.Attrs["INTERNALDATE"]; ok {
			actual[f.Seq] = date.Text
		}
	}
	if err := Check(len(actual) == len(dates), "FETCH returned %d INTERNALDATE values, want %d", len(actual), len(dates)); err != nil {
		return err
	}
	for i, date := range dates {
		equal, err := portSortThreadDateEqual(actual[uint64(i+1)], date)
		if err != nil {
			return err
		}
		if !equal {
			return Skip("server did not preserve the requested APPEND INTERNALDATE required by this fixture")
		}
	}
	return nil
}

func portSortThreadDateEqual(actual, expected string) (bool, error) {
	parse := func(value string) (time.Time, error) {
		return time.Parse("2-Jan-2006 15:04:05 -0700", strings.TrimSpace(value))
	}
	a, err := parse(actual)
	if err != nil {
		return false, Check(false, "invalid INTERNALDATE returned by server: %q", actual)
	}
	b, err := parse(expected)
	if err != nil {
		return false, fmt.Errorf("invalid fixture INTERNALDATE %q: %w", expected, err)
	}
	return a.Equal(b), nil
}
