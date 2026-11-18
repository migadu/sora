// Copyright (c) 2007-2026 ImapTest authors. Scenarios adapted under MIT;
// see testdata/imaptest/COPYING for the notice accompanying fixture data.
package imaptest

import (
	"fmt"
	"slices"
	"strings"
)

func portExtensionCases() []Case {
	return []Case{
		portCase("id", "Maximum RFC ID field/value lengths where ID is advertised", "https://www.rfc-editor.org/rfc/rfc2971.html#section-3", []string{"ID"}, portID),
		portCase("esearch", "Every upstream ESEARCH return option, sparse UIDs and empty results", "https://www.rfc-editor.org/rfc/rfc4731.html#section-3.1", []string{"ESEARCH"}, portESearch),
		portCase("esearch-condstore", "ESEARCH MODSEQ summaries and per-flag criteria", "https://www.rfc-editor.org/rfc/rfc4731.html#section-3.2", []string{"ESEARCH", "CONDSTORE"}, portESearchCondstore),
		portCase("esort", "Extended SORT MIN/MAX/ALL/COUNT return options", "https://www.rfc-editor.org/rfc/rfc5267.html#section-3", []string{"ESORT"}, portESort),
		portCase("move", "Sequence MOVE, UID MOVE and self-MOVE without allocation assumptions", "https://www.rfc-editor.org/rfc/rfc6851.html#section-3", []string{"MOVE"}, portMove),
		portCase("notify", "Initial NOTIFY STATUS includes the required mailbox state", "https://www.rfc-editor.org/rfc/rfc5465.html#section-3.1", []string{"NOTIFY", "QRESYNC"}, portNotify),
	}
}

func portID(s *Session) error {
	c, err := s.NewUnauthenticatedClient()
	if err != nil {
		return err
	}
	if !c.Capabilities["ID"] {
		// CAPABILITY can vary by authentication state. Exercise ID where it
		// is advertised instead of skipping its RFC length checks entirely.
		c = s.Client
	}
	pairs := make([]string, 0, 60)
	for i := 0; i < 30; i++ {
		pairs = append(pairs, Quote(fmt.Sprintf("%030d", i)), Quote(strings.Repeat("x", 1024)))
	}
	r, err := c.OK("ID (" + strings.Join(pairs, " ") + ")")
	if err != nil {
		return err
	}
	// RFC 2971 permits NIL and does not prescribe a server implementation name.
	for _, reply := range r.Data("ID") {
		if err := Check(len(reply.Values) == 2, "ID reply has malformed parameters"); err != nil {
			return err
		}
		v := reply.Values[1]
		if v.IsNil {
			continue
		}
		if err := Check(v.IsList && len(v.List)%2 == 0 && len(v.List) <= 60, "ID reply must contain at most 30 field/value pairs"); err != nil {
			return err
		}
		seen := map[string]bool{}
		for i := 0; i < len(v.List); i += 2 {
			field, value := v.List[i], v.List[i+1]
			key := strings.ToUpper(field.Text)
			if err := Check(!field.IsList && !field.IsNil && len(field.Text) <= 30 && !seen[key] && !value.IsList && (value.IsNil || len(value.Text) <= 1024), "ID reply violates field/value limits or repeats a field"); err != nil {
				return err
			}
			seen[key] = true
		}
	}
	return nil
}

func portESearchValues(r Response, uid bool) (map[string]Value, error) {
	replies := r.Data("ESEARCH")
	if err := Check(len(replies) == 1, "expected one ESEARCH reply, got %d", len(replies)); err != nil {
		return nil, err
	}
	values := map[string]Value{}
	hasUID := false
	for i := 1; i < len(replies[0].Values); {
		v := replies[0].Values[i]
		if v.IsList {
			if err := Check(len(v.List) == 2 && strings.EqualFold(v.List[0].Text, "TAG") && v.List[1].Text == r.Tag, "invalid ESEARCH command correlator"); err != nil {
				return nil, err
			}
			i++
			continue
		}
		key := strings.ToUpper(v.Text)
		if key == "UID" {
			if err := Check(!hasUID, "repeated ESEARCH UID marker"); err != nil {
				return nil, err
			}
			hasUID = true
			i++
			continue
		}
		if err := Check(i+1 < len(replies[0].Values), "ESEARCH %s has no value", key); err != nil {
			return nil, err
		}
		if _, exists := values[key]; exists {
			return nil, Check(false, "ESEARCH repeats %s", key)
		}
		values[key] = replies[0].Values[i+1]
		i += 2
	}
	return values, Check(hasUID == uid, "ESEARCH UID marker=%t, want %t", hasUID, uid)
}

func portCheckESearch(c *Client, command string, uid bool, numbers map[string]uint64, all []uint64, absent ...string) error {
	r, err := c.OK(command)
	if err != nil {
		return err
	}
	values, err := portESearchValues(r, uid)
	if err != nil {
		return err
	}
	for name, want := range numbers {
		v, ok := values[name]
		if err := Check(ok, "%s omitted %s", command, name); err != nil {
			return err
		}
		n, err := v.Uint()
		if err != nil {
			return err
		}
		if err := Check(n == want, "%s %s=%d, want %d", command, name, n, want); err != nil {
			return err
		}
	}
	if all != nil {
		v, ok := values["ALL"]
		if err := Check(ok, "%s omitted ALL", command); err != nil {
			return err
		}
		got, err := extUIDSet(v.Text)
		if err != nil {
			return err
		}
		want := slices.Clone(all)
		slices.Sort(want)
		if err := Check(slices.Equal(got, want), "%s ALL=%v, want %v", command, got, want); err != nil {
			return err
		}
	}
	for _, name := range absent {
		if _, ok := values[name]; ok {
			return Check(false, "%s must omit %s for empty results", command, name)
		}
	}
	return nil
}

func portESearch(s *Session) error {
	if _, _, err := portMailbox(s, "esearch", -1, true); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 4 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	if _, err := s.Client.OK("EXPUNGE"); err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 6, "want 6 messages after expunge, got %v", uids); err != nil {
		return err
	}
	for _, uid := range []bool{false, true} {
		prefix := "SEARCH"
		all := []uint64{1, 2, 3, 4, 5, 6}
		if uid {
			prefix = "UID SEARCH"
			all = uids
		}
		for _, option := range []string{"ALL", "", "MIN", "MAX", "COUNT"} {
			numbers := map[string]uint64{}
			var set []uint64
			switch option {
			case "ALL", "":
				set = all
			case "MIN":
				numbers["MIN"] = all[0]
			case "MAX":
				numbers["MAX"] = all[len(all)-1]
			case "COUNT":
				numbers["COUNT"] = uint64(len(all))
			}
			if err := portCheckESearch(s.Client, prefix+" RETURN ("+option+") ALL", uid, numbers, set); err != nil {
				return err
			}
		}
	}
	if _, err := s.Client.OK("STORE 2,4 +FLAGS (\\Seen)"); err != nil {
		return err
	}
	seen := []uint64{uids[1], uids[3]}
	for _, option := range []string{"ALL", "", "MIN", "MAX", "COUNT"} {
		numbers := map[string]uint64{}
		var set []uint64
		switch option {
		case "ALL", "":
			set = seen
		case "MIN":
			numbers["MIN"] = seen[0]
		case "MAX":
			numbers["MAX"] = seen[1]
		case "COUNT":
			numbers["COUNT"] = 2
		}
		if err := portCheckESearch(s.Client, "UID SEARCH RETURN ("+option+") SEEN", true, numbers, set); err != nil {
			return err
		}
	}
	for _, uid := range []bool{false, true} {
		prefix := "SEARCH"
		if uid {
			prefix = "UID SEARCH"
		}
		for _, option := range []string{"", "MIN", "MAX", "COUNT"} {
			numbers := map[string]uint64{}
			if option == "COUNT" {
				numbers["COUNT"] = 0
			}
			if err := portCheckESearch(s.Client, prefix+" RETURN ("+option+") 1000", uid, numbers, nil, "ALL", "MIN", "MAX"); err != nil {
				return err
			}
		}
	}
	return nil
}

func portESearchCondstore(s *Session) error {
	box, _, err := portMailbox(s, "esearch-condstore", 4, true)
	if err != nil {
		return err
	}
	selected, err := s.Client.OK("SELECT " + Quote(box))
	if err != nil {
		return err
	}
	if selected.Code("NOMODSEQ") != nil {
		return Skip("mailbox does not store persistent mod-sequences")
	}
	r, err := s.Client.OK("FETCH 1 MODSEQ")
	if err != nil {
		return err
	}
	if err := Check(len(r.Code("HIGHESTMODSEQ")) == 1, "first CONDSTORE-enabling FETCH omitted HIGHESTMODSEQ"); err != nil {
		return err
	}
	mods := map[uint64]uint64{}
	var previous uint64
	for _, seq := range []uint64{1, 3, 2, 4} {
		if _, err := s.Client.OK(fmt.Sprintf("STORE %d +FLAGS (\\Seen)", seq)); err != nil {
			return err
		}
		f, err := coreSingleFetch(s.Client, fmt.Sprintf("FETCH %d MODSEQ", seq))
		if err != nil {
			return err
		}
		mod, err := extModseq(f)
		if err != nil {
			return err
		}
		if err := Check(mod > previous, "successive STORE MODSEQ %d did not exceed %d", mod, previous); err != nil {
			return err
		}
		mods[seq] = mod
		previous = mod
	}
	type check struct {
		options, rangeSet string
		threshold         uint64
		numbers           map[string]uint64
		all               []uint64
	}
	checks := []check{
		{"MIN", "1:3", 1, map[string]uint64{"MIN": 1, "MODSEQ": mods[1]}, nil},
		{"MAX", "1:3", 1, map[string]uint64{"MAX": 3, "MODSEQ": mods[3]}, nil},
		{"", "1:3", 1, map[string]uint64{"MODSEQ": mods[2]}, []uint64{1, 2, 3}},
		{"MIN MAX", "2:3", 1, map[string]uint64{"MIN": 2, "MAX": 3, "MODSEQ": mods[2]}, nil},
		{"ALL", "2:3", mods[3], map[string]uint64{"MODSEQ": mods[2]}, []uint64{2, 3}},
		{"ALL", "2:3", mods[2], map[string]uint64{"MODSEQ": mods[2]}, []uint64{2}},
		{"ALL", "2:3", mods[4], map[string]uint64{}, nil},
	}
	for _, item := range checks {
		command := fmt.Sprintf("SEARCH RETURN (%s) %s MODSEQ %s ALL %d", item.options, item.rangeSet, Quote("/flags/\\seen"), item.threshold)
		var absent []string
		if item.threshold == mods[4] {
			absent = []string{"MIN", "MAX", "ALL", "MODSEQ"}
		}
		if err := portCheckESearch(s.Client, command, false, item.numbers, item.all, absent...); err != nil {
			return err
		}
	}
	return nil
}

func portESort(s *Session) error {
	if _, _, err := portMailbox(s, "esort", 5, true); err != nil {
		return err
	}
	for _, option := range []string{"MIN", "MAX", "ALL", "COUNT"} {
		numbers := map[string]uint64{}
		var all []uint64
		switch option {
		case "MIN":
			numbers["MIN"] = 1
		case "MAX":
			numbers["MAX"] = 5
		case "COUNT":
			numbers["COUNT"] = 5
		case "ALL":
			all = []uint64{1, 2, 3, 4, 5}
		}
		if err := portCheckESearch(s.Client, "SORT RETURN ("+option+") (ARRIVAL) US-ASCII 1:5", false, numbers, all); err != nil {
			return err
		}
	}
	return nil
}

func portMove(s *Session) error {
	source, messages, err := portMailbox(s, "move", 3, true)
	if err != nil {
		return err
	}
	selectedSource, err := s.Client.OK("SELECT " + Quote(source))
	if err != nil {
		return err
	}
	if selectedSource.Code("UIDNOTSTICKY") != nil {
		return Skip("MOVE identity checks across selections require persistent mailbox UIDs")
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 3, "MOVE fixture has %d messages, want 3", len(uids)); err != nil {
		return err
	}
	destination, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	for i, command := range []string{"MOVE 1 " + Quote(destination), fmt.Sprintf("UID MOVE %d %s", uids[1], Quote(destination))} {
		if _, err := s.Client.OK("SELECT " + Quote(source)); err != nil {
			return err
		}
		r, err := s.Client.OK(command)
		if err != nil {
			return err
		}
		if err := Check(len(r.Data("EXPUNGE")) == 1, "MOVE did not expunge exactly one source message"); err != nil {
			return err
		}
		destUIDs, selected, err := extSelectedUIDs(s.Client, destination)
		if err != nil {
			return err
		}
		if err := Check(len(destUIDs) == i+1, "MOVE destination has %d messages, want %d", len(destUIDs), i+1); err != nil {
			return err
		}
		if selected.Code("UIDNOTSTICKY") != nil {
			return Skip("MOVE mapping checks require persistent destination UIDs")
		}
		// COPYUID may be on tagged or untagged OK, and UIDNEXT is only a lower bound.
		if code := r.Code("COPYUID"); code != nil {
			if err := extCheckCopyUID(code, selected, uids[i], destUIDs[i]); err != nil {
				return err
			}
		}
		f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID BODY.PEEK[])", destUIDs[i]), destUIDs[i])
		if err != nil {
			return err
		}
		if err := Check(f.Attrs["BODY[]"].Text == string(messages[i]), "MOVE changed fixture message %d", i+1); err != nil {
			return err
		}
	}
	if _, err := s.Client.OK("SELECT " + Quote(source)); err != nil {
		return err
	}
	r, err := s.Client.Command("MOVE 1 " + Quote(source))
	if err != nil {
		return err
	}
	if err := Check(r.Status == "OK" || r.Status == "NO", "self-MOVE returned %s, want OK or permitted NO", r.Status); err != nil {
		return err
	}
	if _, err := s.Client.OK("SELECT " + Quote(source)); err != nil {
		return err
	}
	fetched, err := coreFetch(s.Client, "FETCH 1:* (UID BODY.PEEK[])")
	if err != nil {
		return err
	}
	var bodies []string
	for _, f := range fetched {
		if body, ok := f.Attrs["BODY[]"]; ok {
			bodies = append(bodies, body.Text)
		}
	}
	return Check(len(bodies) == 1 && bodies[0] == string(messages[2]), "self-MOVE lost or duplicated the remaining message")
}

func portNotify(s *Session) error {
	if _, _, err := portMailbox(s, "notify", -1, true); err != nil {
		return err
	}
	other, err := s.NewMailbox("watched")
	if err != nil {
		return err
	}
	message := extMessage("NOTIFY initial state")
	if _, err := s.Client.Append(other, nil, "", message); err != nil {
		return err
	}
	baseline, err := s.Client.OK("STATUS " + Quote(other) + " (MESSAGES UIDNEXT UIDVALIDITY HIGHESTMODSEQ)")
	if err != nil {
		return err
	}
	want, err := baseline.StatusValues(other)
	if err != nil {
		return err
	}
	for _, flags := range []bool{false, true} {
		events := "MessageNew MessageExpunge"
		keys := []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY"}
		if flags {
			events += " FlagChange"
			keys = append(keys, "HIGHESTMODSEQ")
		}
		r, err := s.Client.OK("NOTIFY SET STATUS (mailboxes " + Quote(other) + " (" + events + "))")
		if err != nil {
			return err
		}
		got, err := r.StatusValues(other)
		if err != nil {
			return err
		}
		for _, key := range keys {
			value, ok := got[key]
			if err := Check(ok && value == want[key], "NOTIFY initial STATUS %s=%d (present=%t), want %d", key, value, ok, want[key]); err != nil {
				return err
			}
		}
	}
	r, err := s.Client.OK("NOTIFY SET (mailboxes " + Quote(other) + " (MessageNew MessageExpunge FlagChange))")
	if err != nil {
		return err
	}
	for _, reply := range r.Data("STATUS") {
		if len(reply.Values) >= 2 && reply.Values[1].Text == other {
			return Check(false, "NOTIFY without STATUS sent an unrequested initial STATUS")
		}
	}
	_, err = s.Client.OK("NOTIFY NONE")
	return err
}
