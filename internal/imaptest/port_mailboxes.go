package imaptest

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// These cases port the command sequences in the pinned upstream corpus. Checks
// use actual UIDs and per-session sequence views, and avoid implementation-
// specific response text, keyword additions, and which session wins Recent.
func portMailboxCases() []Case {
	return []Case{
		portCase("append", "Three-session APPEND visibility, flags and Recent ownership", coreRFC+"6.3.11", nil, pmAppend),
		portCase("atoms", "Valid special-character atoms are distinct from literals", coreRFC+"4.1", nil, pmAtoms),
		portCase("close", "CLOSE expunges are reported to another selected session", coreRFC+"6.4.2", nil, pmClose),
		portCase("copy", "COPY ranges and keywords across selected sessions", coreRFC+"6.4.7", nil, pmCopy),
		portCase("expunge", "Sequence snapshots, flag changes and repeated expunges across sessions", coreRFC+"7.4.1", nil, pmExpunge),
		portCase("expunge2", "UID commands remap expunges while sequence commands defer them", coreRFC+"7.4.1", nil, pmExpunge2),
		portCase("fetch", "FETCH ranges, wildcards, UID holes and macros", coreRFC+"6.4.5", nil, pmFetch),
		portCase("list", "Hierarchy delimiters, reference names and LIST wildcards", coreRFC+"6.3.8", nil, pmList),
		portCase("listext", "LIST selection, return options and recursive subscriptions", "https://www.rfc-editor.org/rfc/rfc5258.html#section-3", []string{"LIST-EXTENDED"}, pmListExtended),
		portCase("logout", "NOOP and independent LOGOUT on two unauthenticated sessions", coreRFC+"6.1.3", nil, pmLogout),
		portCase("mutf7", "Modified UTF-7 mailbox names round-trip through LIST and STATUS", coreRFC+"5.1.3", nil, pmModifiedUTF7),
		portCase("pipeline", "Four independent CREATE and STATUS commands are pipelined", coreRFC+"5.5", nil, pmPipeline),
		portCase("pipeline-connections", "Pipelined mailbox mutations are visible on a second connection", coreRFC+"5.5", nil, pmPipelineConnections),
		portCase("select", "EXAMINE, STATUS and SELECT agree on UID and Recent state", coreRFC+"6.3.1", nil, pmSelect),
		portCase("store", "STORE flags and keywords remain coherent across two sessions", coreRFC+"6.4.6", nil, pmStore),
		portCase("subscribe", "LSUB hierarchy matching and subscription removal", coreRFC+"6.3.9", nil, pmSubscribe),
		portCase("uidplus", "APPENDUID and COPYUID refer to actual destination messages", "https://www.rfc-editor.org/rfc/rfc4315.html#section-3", []string{"UIDPLUS"}, pmUIDPlus),
		portCase("uidvalidity", "Deleted and recreated mailbox names never reuse UID identity", coreRFC+"2.3.1.1", nil, pmUIDValidity),
		portCase("uidvalidity-rename", "Renamed mailboxes preserve unique identity at a reused name", coreRFC+"2.3.1.1", nil, pmUIDValidityRename),
	}
}

func pmStatus(c *Client, box, items string) (map[string]uint64, error) {
	r, err := c.OK("STATUS " + Quote(box) + " (" + items + ")")
	if err != nil {
		return nil, err
	}
	return r.StatusValues(box)
}

func pmFlags(c *Client, seq uint64) (Value, uint64, error) {
	f, err := coreSingleFetch(c, fmt.Sprintf("FETCH %d (UID FLAGS)", seq))
	if err != nil {
		return Value{}, 0, err
	}
	flags, err := coreAttribute(f, "FLAGS")
	if err != nil {
		return Value{}, 0, err
	}
	u, err := coreAttribute(f, "UID")
	if err != nil {
		return Value{}, 0, err
	}
	uid, err := u.Uint()
	return flags, uid, err
}

func pmSystemFlags(flags Value, present, absent []string) error {
	if err := Check(flags.IsList, "FLAGS is not a list"); err != nil {
		return err
	}
	for _, flag := range present {
		if err := Check(coreHasFlag(flags, flag), "FLAGS %s omitted %s", flags.String(), flag); err != nil {
			return err
		}
	}
	for _, flag := range absent {
		if err := Check(!coreHasFlag(flags, flag), "FLAGS %s unexpectedly contains %s", flags.String(), flag); err != nil {
			return err
		}
	}
	return nil
}

func pmExists(r Response, want uint64) error {
	n, found := r.Exists()
	return Check(found && n == want, "EXISTS=%d (present=%t), want %d", n, found, want)
}

func pmStatusCounts(c *Client, box string, messages, unseen uint64, recent *uint64) error {
	items := "MESSAGES UNSEEN"
	if recent != nil {
		items += " RECENT"
	}
	status, err := pmStatus(c, box, items)
	if err != nil {
		return err
	}
	if err := Check(status["MESSAGES"] == messages && status["UNSEEN"] == unseen,
		"STATUS counts %v, want MESSAGES=%d UNSEEN=%d", status, messages, unseen); err != nil {
		return err
	}
	if recent != nil {
		return Check(status["RECENT"] == *recent, "STATUS RECENT=%d, want %d", status["RECENT"], *recent)
	}
	return nil
}

func pmNoExpunge(r Response) error {
	return Check(len(r.Data("EXPUNGE")) == 0, "sequence-based command unexpectedly sent EXPUNGE")
}

// pmApplyExpunges resolves each notification against the immediately preceding
// sequence view, so both descending and ascending removal order are accepted.
func pmApplyExpunges(before []uint64, r Response) ([]uint64, []uint64, error) {
	view := slices.Clone(before)
	var removed []uint64
	for _, reply := range r.Untagged {
		if reply.Kind() != "EXPUNGE" {
			continue
		}
		seq, ok := reply.Number()
		if err := Check(ok && seq > 0 && seq <= uint64(len(view)), "EXPUNGE sequence %d outside view %v", seq, view); err != nil {
			return nil, nil, err
		}
		removed = append(removed, view[seq-1])
		view = slices.Delete(view, int(seq-1), int(seq))
	}
	return view, removed, nil
}

// A UID command may interleave FETCH data with EXPUNGE notifications. Validate
// sequence/UID pairs against the view at that exact point in the wire stream,
// rather than against either the initial or final sequence map.
func pmApplyUIDReplies(before []uint64, r Response) ([]uint64, []uint64, error) {
	return pmApplyStream(before, r, false)
}

func pmApplySequenceReplies(before []uint64, r Response) ([]uint64, []uint64, error) {
	return pmApplyStream(before, r, true)
}

func pmApplyStream(before []uint64, r Response, sequenceCommand bool) ([]uint64, []uint64, error) {
	view := slices.Clone(before)
	var seen []uint64
	dataSeen := false
	for _, reply := range r.Untagged {
		switch reply.Kind() {
		case "EXPUNGE":
			if err := Check(!sequenceCommand || !dataSeen, "sequence-based command sent EXPUNGE after its data response began"); err != nil {
				return nil, nil, err
			}
			updated, _, err := pmApplyExpunges(view, Response{Untagged: []Reply{reply}})
			if err != nil {
				return nil, nil, err
			}
			view = updated
		case "FETCH":
			dataSeen = true
			rows, err := (Response{Untagged: []Reply{reply}}).Fetches()
			if err != nil {
				return nil, nil, err
			}
			for _, row := range rows {
				if err := Check(row.Seq > 0 && row.Seq <= uint64(len(view)), "FETCH sequence %d outside current UID view %v", row.Seq, view); err != nil {
					return nil, nil, err
				}
				if value, present := row.Attrs["UID"]; present {
					uid, err := value.Uint()
					if err != nil {
						return nil, nil, err
					}
					if err := Check(uid == view[row.Seq-1], "FETCH sequence %d has UID %d, current view requires UID %d", row.Seq, uid, view[row.Seq-1]); err != nil {
						return nil, nil, err
					}
					seen = append(seen, uid)
				}
			}
		case "SEARCH":
			dataSeen = true
		}
	}
	return view, seen, nil
}

func pmExpectExpunges(before []uint64, r Response, want ...uint64) ([]uint64, error) {
	view, removed, err := pmApplyExpunges(before, r)
	if err != nil {
		return nil, err
	}
	slices.Sort(removed)
	want = slices.Clone(want)
	slices.Sort(want)
	if err := Check(slices.Equal(removed, want), "EXPUNGE removed UIDs %v, want %v", removed, want); err != nil {
		return nil, err
	}
	return view, nil
}

func pmCheckView(c *Client, want []uint64) error {
	got, err := coreUIDs(c)
	if err != nil {
		return err
	}
	return Check(slices.Equal(got, want), "selected UID/sequence view %v, want %v", got, want)
}

func pmAppend(s *Session) error {
	box, messages, err := portMailbox(s, "append", 0, false)
	if err != nil {
		return err
	}
	a := s.Client
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	c, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err = coreSelect(a, box); err != nil {
		return err
	}
	if _, err = coreSelect(b, box); err != nil {
		return err
	}
	zero := uint64(0)
	for i, writer := range []*Client{a, b, c} {
		flags := []string(nil)
		if i == 0 {
			flags = []string{"\\Seen", "\\Flagged"}
		}
		if _, err := writer.Append(box, flags, "", messages[i%len(messages)]); err != nil {
			return err
		}
		// APPEND's initial flags are SHOULD-level. Set required state through
		// STORE before checking UNSEEN so omission alone is not a hard failure.
		if _, err := a.OK("NOOP"); err != nil {
			return err
		}
		if i == 0 {
			if _, err := a.OK("STORE 1 FLAGS.SILENT (\\Seen \\Flagged)"); err != nil {
				return err
			}
		}
		for _, selected := range []*Client{a, b} {
			if _, err := selected.OK("NOOP"); err != nil {
				return err
			}
			f, uid, err := pmFlags(selected, uint64(i+1))
			if err != nil {
				return err
			}
			if err := Check(uid > 0, "FETCH returned zero UID"); err != nil {
				return err
			}
			if i == 0 {
				if err := pmSystemFlags(f, []string{"\\Seen", "\\Flagged"}, nil); err != nil {
					return err
				}
			}
		}
		// RFC 3501 leaves the allocation of Recent across selected sessions
		// undefined, including the case where first-notification is uncertain.
		// Check shared message identity without imposing imaptest's ownership
		// policy on otherwise valid server implementations.
		_, ua, err := pmFlags(a, uint64(i+1))
		if err != nil {
			return err
		}
		_, ub, err := pmFlags(b, uint64(i+1))
		if err != nil {
			return err
		}
		if err := Check(ua == ub, "new message UID differs across selected sessions"); err != nil {
			return err
		}
		var recent *uint64
		if i < 2 {
			recent = &zero
		}
		if err := pmStatusCounts(c, box, uint64(i+1), uint64(i), recent); err != nil {
			return err
		}
	}
	missing := s.Name("missing")
	r, err := a.Append(missing, nil, "", messages[0])
	if err == nil {
		return Check(false, "APPEND unexpectedly created nonexistent mailbox")
	}
	if r.Status != "NO" {
		return err
	}
	return Check(r.Code("TRYCREATE") != nil, "APPEND to an available nonexistent name omitted TRYCREATE")
}

func pmAtoms(s *Session) error {
	for _, atom := range []string{"~" + s.Name("literal-name"), "!#$&-'+,-.0123456789:;<=>?@^_`|[}" + s.Name("atom")} {
		if _, err := s.Client.OK("LIST \"\" " + atom); err != nil {
			return err
		}
		r, err := s.Client.Command("SELECT " + atom)
		if err != nil {
			return err
		}
		if err := Check(r.Status == "NO", "SELECT nonexistent valid atom returned %s", r.Status); err != nil {
			return err
		}
	}
	_, err := s.Client.OK("LIST \"\" !#$&-'+,-.0123456789:;<=>?@^_`|[}" + s.Name("atom") + "%*")
	return err
}

func pmClose(s *Session) error {
	box, _, err := portMailbox(s, "close", 3, true)
	if err != nil {
		return err
	}
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err = coreSelect(b, box); err != nil {
		return err
	}
	view, err := coreUIDs(b)
	if err != nil {
		return err
	}
	if err := Check(len(view) == 3, "CLOSE fixture has %d messages, want 3", len(view)); err != nil {
		return err
	}
	if _, err = s.Client.OK("STORE 1,3 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err := s.Client.OK("CLOSE")
	if err != nil {
		return err
	}
	if err := pmNoExpunge(r); err != nil {
		return err
	}
	r, err = b.OK("NOOP")
	if err != nil {
		return err
	}
	remaining, err := pmExpectExpunges(view, r, view[0], view[2])
	if err != nil {
		return err
	}
	return pmCheckView(b, remaining)
}

func pmCopy(s *Session) error {
	src, messages, err := portMailbox(s, "copy", 0, true)
	if err != nil {
		return err
	}
	for i := 0; i < 5; i++ {
		if _, err := s.Client.Append(src, nil, "", messages[i%len(messages)]); err != nil {
			return err
		}
	}
	if _, err = s.Client.OK("CHECK"); err != nil {
		return err
	}
	dst, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	selected, err := coreSelect(b, dst)
	if err != nil {
		return err
	}
	for _, command := range []string{"STORE 1 FLAGS (\\Seen)", "STORE 2 FLAGS (\\Answered \\Flagged)"} {
		if _, err = s.Client.OK(command); err != nil {
			return err
		}
	}
	if _, err = s.Client.OK("COPY 1:2,4 " + Quote(dst)); err != nil {
		return err
	}
	if _, err = b.OK("NOOP"); err != nil {
		return err
	}
	if err := pmCopyBodies(b, messages, []int{0, 1, 3}); err != nil {
		return err
	}
	// COPY flags and INTERNALDATE are SHOULD recommendations. The mandatory
	// contract here is complete immutable content, count and source retention.
	if code := selected.Code("PERMANENTFLAGS"); len(code) == 1 && coreHasFlag(code[0], "\\*") {
		if _, err = s.Client.OK("STORE 5 FLAGS (\\Flagged $keyword1 $keyword2)"); err != nil {
			return err
		}
		if _, err = b.OK("STORE 3 +FLAGS ($keyword1 $keyword2)"); err != nil {
			return err
		}
	}
	if _, err = s.Client.OK("COPY 5 " + Quote(dst)); err != nil {
		return err
	}
	if _, err = b.OK("NOOP"); err != nil {
		return err
	}
	if err := pmCopyBodies(b, messages, []int{0, 1, 3, 4}); err != nil {
		return err
	}
	return pmCheckCount(s.Client, src, 5)
}

func pmCopyBodies(c *Client, messages [][]byte, indexes []int) error {
	fetched, err := coreFetch(c, "FETCH 1:* (BODY.PEEK[] FLAGS INTERNALDATE)")
	if err != nil {
		return err
	}
	var got, want []string
	for _, f := range fetched {
		if v, ok := f.Attrs["BODY[]"]; ok {
			got = append(got, v.Text)
		}
	}
	for _, i := range indexes {
		want = append(want, string(messages[i%len(messages)]))
	}
	slices.Sort(got)
	slices.Sort(want)
	return Check(slices.Equal(got, want), "COPY message multiset/count differs from the source range")
}

func pmCheckCount(c *Client, box string, want uint64) error {
	status, err := pmStatus(c, box, "MESSAGES")
	if err != nil {
		return err
	}
	return Check(status["MESSAGES"] == want, "STATUS MESSAGES=%d, want %d", status["MESSAGES"], want)
}

func pmExpunge(s *Session) error {
	box, _, err := portMailbox(s, "expunge", 8, true)
	if err != nil {
		return err
	}
	a := s.Client
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err = coreSelect(b, box); err != nil {
		return err
	}
	initial, err := coreUIDs(a)
	if err != nil {
		return err
	}
	if err := Check(len(initial) == 8, "EXPUNGE fixture has %d messages, want 8", len(initial)); err != nil {
		return err
	}
	viewA := slices.Clone(initial)
	viewB := slices.Clone(initial)
	for _, cmd := range []string{"STORE 1,3 FLAGS (\\Deleted)", "STORE 2,4 FLAGS (\\Seen)"} {
		if _, err = a.OK(cmd); err != nil {
			return err
		}
	}
	r, err := a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	viewA, err = pmExpectExpunges(viewA, r, initial[0], initial[2])
	if err != nil {
		return err
	}
	for i := 0; i < 2; i++ {
		r, err = b.OK("FETCH 2,4 UID")
		if err != nil {
			return err
		}
		viewB, _, err = pmApplySequenceReplies(viewB, r)
		if err != nil {
			return err
		}
		if err := Check(len(viewB) >= 4, "selected session lost too many messages"); err != nil {
			return err
		}
		if err = pmFetchUIDs(r, map[uint64]uint64{2: viewB[1], 4: viewB[3]}); err != nil {
			return err
		}
	}
	r, err = b.OK("CHECK")
	if err != nil {
		return err
	}
	viewB, _, err = pmApplyUIDReplies(viewB, r)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(viewA, viewB), "CHECK did not synchronize the selected UID view"); err != nil {
		return err
	}
	for _, seq := range []uint64{1, 2} {
		flags, _, err := pmFlags(b, seq)
		if err != nil {
			return err
		}
		if err := pmSystemFlags(flags, []string{"\\Seen"}, nil); err != nil {
			return err
		}
	}
	if _, err = a.OK("STORE 2 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	removed := viewA[1]
	viewA, err = pmExpectExpunges(viewA, r, removed)
	if err != nil {
		return err
	}
	r, err = b.OK("STORE 1 FLAGS (\\Answered)")
	if err != nil {
		return err
	}
	viewB, _, err = pmApplySequenceReplies(viewB, r)
	if err != nil {
		return err
	}
	if _, err = a.OK("CHECK"); err != nil {
		return err
	}
	flags, _, err := pmFlags(a, 1)
	if err != nil {
		return err
	}
	if err = pmSystemFlags(flags, []string{"\\Answered"}, []string{"\\Seen"}); err != nil {
		return err
	}
	r, err = b.OK("NOOP")
	if err != nil {
		return err
	}
	viewB, _, err = pmApplyUIDReplies(viewB, r)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(viewA, viewB), "NOOP did not synchronize the selected UID view"); err != nil {
		return err
	}
	// Interleave deletions with flag updates; notifications may be ordered
	// differently but must describe the same final UID/sequence state.
	for _, cmd := range []string{"STORE 1,3 +FLAGS (\\Deleted)", "STORE 2,4 FLAGS (\\Flagged)"} {
		if _, err = a.OK(cmd); err != nil {
			return err
		}
	}
	remove1, remove3 := viewA[0], viewA[2]
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	viewA, err = pmExpectExpunges(viewA, r, remove1, remove3)
	if err != nil {
		return err
	}
	r, err = b.OK("CHECK")
	if err != nil {
		return err
	}
	viewB, err = pmExpectExpunges(viewB, r, remove1, remove3)
	if err != nil {
		return err
	}
	if err := pmCheckView(b, viewB); err != nil {
		return err
	}
	for _, seq := range []uint64{1, 2} {
		flags, _, err := pmFlags(b, seq)
		if err != nil {
			return err
		}
		if err := pmSystemFlags(flags, []string{"\\Flagged"}, nil); err != nil {
			return err
		}
	}
	for _, c := range []*Client{a, b} {
		if _, err = c.OK("STORE 1 +FLAGS (\\Deleted)"); err != nil {
			return err
		}
	}
	last := viewA[0]
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	viewA, err = pmExpectExpunges(viewA, r, last)
	if err != nil {
		return err
	}
	r, err = b.OK("EXPUNGE")
	if err != nil {
		return err
	}
	viewB, err = pmExpectExpunges(viewB, r, last)
	if err != nil {
		return err
	}
	if err := pmCheckView(a, viewA); err != nil {
		return err
	}
	return pmCheckView(b, viewB)
}

func pmFetchUIDs(r Response, want map[uint64]uint64) error {
	fs, err := r.Fetches()
	if err != nil {
		return err
	}
	got := map[uint64]uint64{}
	for _, f := range fs {
		if v, ok := f.Attrs["UID"]; ok {
			n, err := v.Uint()
			if err != nil {
				return err
			}
			got[f.Seq] = n
		}
	}
	if err := Check(len(got) == len(want), "FETCH UID result %v, want %v", got, want); err != nil {
		return err
	}
	for seq, uid := range want {
		if err := Check(got[seq] == uid, "FETCH seq=%d UID=%d, want %d", seq, got[seq], uid); err != nil {
			return err
		}
	}
	return nil
}

func pmExpunge2(s *Session) error {
	box, _, err := portMailbox(s, "expunge2", 6, true)
	if err != nil {
		return err
	}
	a := s.Client
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err = coreSelect(b, box); err != nil {
		return err
	}
	initial, err := coreUIDs(a)
	if err != nil {
		return err
	}
	if err := Check(len(initial) == 6, "EXPUNGE fixture has %d messages, want 6", len(initial)); err != nil {
		return err
	}
	va := slices.Clone(initial)
	vb := slices.Clone(initial)
	if _, err = a.OK("STORE 1,3 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err := a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	va, err = pmExpectExpunges(va, r, initial[0], initial[2])
	if err != nil {
		return err
	}
	r, err = b.OK(fmt.Sprintf("UID FETCH %d,%d UID", initial[1], initial[3]))
	if err != nil {
		return err
	}
	var got []uint64
	vb, got, err = pmApplyUIDReplies(vb, r)
	if err != nil {
		return err
	}
	for _, uid := range []uint64{initial[1], initial[3]} {
		if err := Check(slices.Contains(got, uid), "UID FETCH omitted requested UID %d; returned %v", uid, got); err != nil {
			return err
		}
	}
	r, err = b.OK("NOOP")
	if err != nil {
		return err
	}
	vb, _, err = pmApplyUIDReplies(vb, r)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(va, vb), "NOOP did not synchronize pending expunges"); err != nil {
		return err
	}
	remove := va[0]
	if _, err = a.OK("STORE 1 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	va, err = pmExpectExpunges(va, r, remove)
	if err != nil {
		return err
	}
	r, err = b.OK(fmt.Sprintf("UID STORE %d FLAGS (\\Seen)", initial[3]))
	if err != nil {
		return err
	}
	vb, _, err = pmApplyUIDReplies(vb, r)
	if err != nil {
		return err
	}
	r, err = b.OK("NOOP")
	if err != nil {
		return err
	}
	vb, _, err = pmApplyUIDReplies(vb, r)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(va, vb), "UID STORE/NOOP sequence view did not converge"); err != nil {
		return err
	}
	flags, uid, err := pmFlags(b, 1)
	if err != nil {
		return err
	}
	if err := Check(uid == initial[3], "UID STORE targeted wrong live message"); err != nil {
		return err
	}
	if err := pmSystemFlags(flags, []string{"\\Seen"}, nil); err != nil {
		return err
	}
	remove = va[0]
	if _, err = a.OK("STORE 1 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	va, err = pmExpectExpunges(va, r, remove)
	if err != nil {
		return err
	}
	r, err = b.OK("CHECK")
	if err != nil {
		return err
	}
	vb, err = pmExpectExpunges(vb, r, remove)
	if err != nil {
		return err
	}
	remove = va[0]
	if _, err = a.OK("STORE 1 +FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err = a.OK("EXPUNGE")
	if err != nil {
		return err
	}
	va, err = pmExpectExpunges(va, r, remove)
	if err != nil {
		return err
	}
	for _, cmd := range []string{"FETCH * FLAGS", "STORE * FLAGS (\\Seen)", "SEARCH ALL"} {
		r, err = b.OK(cmd)
		if err != nil {
			return err
		}
		vb, _, err = pmApplySequenceReplies(vb, r)
		if err != nil {
			return err
		}
	}
	r, err = b.OK("NOOP")
	if err != nil {
		return err
	}
	vb, _, err = pmApplyUIDReplies(vb, r)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(va, vb), "NOOP did not synchronize deferred EXPUNGE state"); err != nil {
		return err
	}
	return pmCheckView(b, va)
}

func pmFetch(s *Session) error {
	box, messages, err := portMailbox(s, "fetch", 3, true)
	if err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 3, "FETCH fixture has %d messages, want 3", len(uids)); err != nil {
		return err
	}
	status, err := pmStatus(s.Client, box, "UIDNEXT")
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		set string
		seq []int
	}{{"1:3", []int{1, 2, 3}}, {"3:1", []int{1, 2, 3}}, {"1,*", []int{1, 3}}, {"*", []int{3}}, {"*:1", []int{1, 2, 3}}} {
		r, err := s.Client.OK("FETCH " + tc.set + " UID")
		if err != nil {
			return err
		}
		want := map[uint64]uint64{}
		for _, n := range tc.seq {
			want[uint64(n)] = uids[n-1]
		}
		if err := pmFetchUIDs(r, want); err != nil {
			return err
		}
	}
	checkLast := func(seq uint64) error {
		r, err := s.Client.OK(fmt.Sprintf("UID FETCH %d:* UID", status["UIDNEXT"]))
		if err != nil {
			return err
		}
		return pmFetchUIDs(r, map[uint64]uint64{seq: uids[2]})
	}
	if err := checkLast(3); err != nil {
		return err
	}
	if _, err = s.Client.OK("STORE 2 FLAGS (\\Deleted)"); err != nil {
		return err
	}
	r, err := s.Client.OK("EXPUNGE")
	if err != nil {
		return err
	}
	if _, err = pmExpectExpunges(uids, r, uids[1]); err != nil {
		return err
	}
	if err := checkLast(2); err != nil {
		return err
	}
	for _, tc := range []struct {
		set  string
		want map[uint64]uint64
	}{
		{"1:*", map[uint64]uint64{1: uids[0], 2: uids[2]}}, {strconv.FormatUint(uids[1], 10), map[uint64]uint64{}}, {fmt.Sprintf("%d,*", uids[0]), map[uint64]uint64{1: uids[0], 2: uids[2]}},
	} {
		r, err := s.Client.OK("UID FETCH " + tc.set + " UID")
		if err != nil {
			return err
		}
		if err := pmFetchUIDs(r, tc.want); err != nil {
			return err
		}
	}
	var date time.Time
	var size uint64
	for _, tc := range []struct {
		macro string
		attrs []string
	}{{"FULL", []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"}}, {"ALL", []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}}, {"FAST", []string{"FLAGS", "INTERNALDATE", "RFC822.SIZE"}}} {
		f, err := coreSingleFetch(s.Client, "FETCH 1 "+tc.macro)
		if err != nil {
			return err
		}
		for _, attr := range tc.attrs {
			if _, err := coreAttribute(f, attr); err != nil {
				return err
			}
		}
		currentDate, currentSize, err := pmMacroMetadata(f, tc.macro)
		if err != nil {
			return err
		}
		if err := Check(currentSize == uint64(len(messages[0])), "FETCH macro RFC822.SIZE=%d, want %d", currentSize, len(messages[0])); err != nil {
			return err
		}
		if date.IsZero() {
			date = currentDate
			size = currentSize
		} else if err := Check(currentDate.Equal(date) && currentSize == size, "FETCH macros disagree about immutable metadata"); err != nil {
			return err
		}
	}
	return nil
}

func pmMacroMetadata(f Fetch, macro string) (time.Time, uint64, error) {
	if err := Check(f.Attrs["FLAGS"].IsList, "FETCH %s FLAGS is not a list", macro); err != nil {
		return time.Time{}, 0, err
	}
	size, err := f.Attrs["RFC822.SIZE"].Uint()
	if err != nil {
		return time.Time{}, 0, Check(false, "FETCH %s RFC822.SIZE is not numeric", macro)
	}
	value := f.Attrs["INTERNALDATE"]
	date, parseErr := time.Parse("_2-Jan-2006 15:04:05 -0700", value.Text)
	if err := Check(!value.IsList && !value.IsNil && parseErr == nil, "FETCH %s INTERNALDATE is not a valid IMAP date-time", macro); err != nil {
		return time.Time{}, 0, err
	}
	if macro == "FULL" || macro == "ALL" {
		envelope := f.Attrs["ENVELOPE"]
		if err := Check(envelope.IsList && len(envelope.List) == 10, "FETCH %s ENVELOPE does not have ten fields", macro); err != nil {
			return time.Time{}, 0, err
		}
	}
	if macro == "FULL" {
		body := f.Attrs["BODY"]
		if err := Check(body.IsList && len(body.List) > 0, "FETCH FULL BODY is not a nonempty structure"); err != nil {
			return time.Time{}, 0, err
		}
	}
	return date, size, nil
}

type pmListed struct {
	Flags     Value
	Delimiter Value
	Extra     []Value
}

func pmListData(r Response, kind string) (map[string]pmListed, error) {
	items := map[string]pmListed{}
	for _, reply := range r.Data(kind) {
		if err := Check(len(reply.Values) >= 4 && reply.Values[1].IsList, "malformed %s response", kind); err != nil {
			return nil, err
		}
		items[reply.Values[3].Text] = pmListed{reply.Values[1], reply.Values[2], reply.Values[4:]}
	}
	return items, nil
}

func pmExpectList(c *Client, kind, command string, present, absent []string) (map[string]pmListed, error) {
	r, err := c.OK(command)
	if err != nil {
		return nil, err
	}
	items, err := pmListData(r, kind)
	if err != nil {
		return nil, err
	}
	for _, name := range present {
		_, ok := items[name]
		if err := Check(ok, "%s omitted %q", command, name); err != nil {
			return nil, err
		}
	}
	for _, name := range absent {
		_, ok := items[name]
		if err := Check(!ok, "%s unexpectedly returned %q", command, name); err != nil {
			return nil, err
		}
	}
	return items, nil
}

func pmDelimiter(c *Client) (string, error) {
	r, err := c.OK("LIST \"\" \"\"")
	if err != nil {
		return "", err
	}
	items, err := pmListData(r, "LIST")
	if err != nil {
		return "", err
	}
	if err := Check(len(items) == 1, "LIST empty pattern returned %d roots, want one", len(items)); err != nil {
		return "", err
	}
	for _, item := range items {
		if item.Delimiter.IsNil {
			return "", Skip("server has a flat personal namespace")
		}
		if err := Check(len(item.Delimiter.Text) == 1, "hierarchy delimiter %q must be a single character", item.Delimiter.Text); err != nil {
			return "", err
		}
		return item.Delimiter.Text, nil
	}
	return "", Check(false, "LIST omitted delimiter")
}

func pmList(s *Session) error {
	sep, err := pmDelimiter(s.Client)
	if err != nil {
		return err
	}
	base := s.Name("tree")
	name := func(suffix string) string { return base + sep + strings.ReplaceAll(suffix, "/", sep) }
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	c, err := s.NewClient()
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		client          *Client
		wire, canonical string
	}{{s.Client, base + sep, base}, {s.Client, name("test"), name("test")}, {b, name("test2"), name("test2")}, {c, name("test3") + sep, name("test3")}, {b, name("test3/test4") + sep, name("test3/test4")}, {b, name("test3/test4/test5"), name("test3/test4/test5")}} {
		if err := s.CreateMailboxAs(tc.client, tc.wire, tc.canonical); err != nil {
			return err
		}
		if tc.canonical == name("test") {
			if _, err := pmExpectList(b, "LIST", "LIST \"\" "+Quote(base+sep+"%"), []string{name("test")}, nil); err != nil {
				return err
			}
		}
		if tc.canonical == name("test2") {
			if _, err := pmExpectList(s.Client, "LIST", "LIST \"\" "+Quote(base+sep+"%"), []string{name("test"), name("test2")}, nil); err != nil {
				return err
			}
		}
	}
	for _, client := range []*Client{b, c} {
		if _, err := pmExpectList(client, "LIST", "LIST \"\" "+Quote(base+sep+"%"), []string{name("test"), name("test2"), name("test3")}, []string{name("test3/test4"), name("test3/test4/test5")}); err != nil {
			return err
		}
	}
	tests := []struct {
		client       *Client
		ref, pattern string
		yes, no      []string
	}{
		{b, "", base + sep + "%" + sep + "%", []string{name("test3/test4")}, []string{name("test"), name("test2"), name("test3"), name("test3/test4/test5")}},
		{c, "", base + sep + "*", []string{name("test"), name("test2"), name("test3"), name("test3/test4/test5")}, nil},
		{c, base + sep, "*", []string{name("test"), name("test2"), name("test3"), name("test3/test4/test5")}, nil},
		{b, "", base + sep + "*test4", []string{name("test3/test4")}, []string{name("test"), name("test2"), name("test3"), name("test3/test4/test5")}},
		{b, "", base + sep + "*test*", []string{name("test"), name("test2"), name("test3"), name("test3/test4/test5")}, nil},
		{b, "", base + sep + "%3" + sep + "%", []string{name("test3/test4")}, nil},
		{b, "", base + sep + "%3" + sep + "%4", []string{name("test3/test4")}, nil},
		{b, "", base + sep + "%t*4", []string{name("test3/test4")}, nil},
	}
	for _, tc := range tests {
		if _, err := pmExpectList(tc.client, "LIST", "LIST "+Quote(tc.ref)+" "+Quote(tc.pattern), tc.yes, tc.no); err != nil {
			return err
		}
	}
	if err := s.DeleteMailbox(b, name("test2")); err != nil {
		return err
	}
	if _, err := pmExpectList(s.Client, "LIST", "LIST \"\" "+Quote(base+sep+"*"), nil, []string{name("test2")}); err != nil {
		return err
	}
	_, err = pmExpectList(s.Client, "LIST", "LIST \"\" INBOX", []string{"INBOX"}, nil)
	return err
}

func pmListExtended(s *Session) error {
	sep, err := pmDelimiter(s.Client)
	if err != nil {
		return err
	}
	base := s.Name("extended")
	name := func(suffix string) string { return base + sep + strings.ReplaceAll(suffix, "/", sep) }
	if err := s.CreateMailboxAs(s.Client, base+sep, base); err != nil {
		return err
	}
	for _, suffix := range []string{"test1", "test2", "test2/test1", "test3", "test4", "test4/test5", "test4/test52", "test6", "test7", "test7/test7", "test8", "test8/test8", "test8/test9"} {
		wire := name(suffix)
		if suffix == "test2" {
			wire += sep
		}
		if err := s.CreateMailboxAs(s.Client, wire, name(suffix)); err != nil {
			return err
		}
	}
	for _, suffix := range []string{"test1", "test2/test1", "test6", "test7/test7", "test8/test8", "test8/test9"} {
		if _, err := s.Client.OK("SUBSCRIBE " + Quote(name(suffix))); err != nil {
			return err
		}
		if err := s.TrackSubscription(name(suffix)); err != nil {
			return err
		}
	}
	if err := s.DeleteMailbox(s.Client, name("test6")); err != nil {
		return err
	}
	if _, err := pmExpectList(s.Client, "LIST", "LIST \"\" ("+Quote(base+sep+"*2")+" "+Quote(name("test3"))+")", []string{name("test2"), name("test3"), name("test4/test52")}, []string{name("test1"), name("test2/test1"), name("test4"), name("test4/test5"), name("test6")}); err != nil {
		return err
	}
	for _, cmd := range []string{"LIST (IMAPTEST) \"\" \"\"", "LIST (RECURSIVEMATCH) \"\" \"\"", "LIST (RECURSIVEMATCH REMOTE) \"\" \"\"", "LIST \"\" \"\" RETURN (IMAPTEST)"} {
		r, err := s.Client.Command(cmd)
		if err != nil {
			return err
		}
		if err := Check(r.Status == "BAD", "invalid LIST options returned %s", r.Status); err != nil {
			return err
		}
	}
	if _, err := s.Client.OK("LIST (REMOTE) \"\" " + Quote(base+sep+"%")); err != nil {
		return err
	}
	items, err := pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED) \"\" "+Quote(base+sep+"*"), []string{name("test1"), name("test2/test1"), name("test6"), name("test7/test7"), name("test8/test9")}, nil)
	if err != nil {
		return err
	}
	for _, suffix := range []string{"test1", "test2/test1", "test6", "test7/test7", "test8/test9"} {
		if err := pmSystemFlags(items[name(suffix)].Flags, []string{"\\Subscribed"}, nil); err != nil {
			return err
		}
	}
	if err := pmSystemFlags(items[name("test6")].Flags, []string{"\\NonExistent"}, []string{"\\Noselect"}); err != nil {
		return err
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" "+Quote(base+sep+"test2%")+" RETURN (CHILDREN)", []string{name("test2")}, []string{name("test2/test1")})
	if err != nil {
		return err
	}
	if err := pmSystemFlags(items[name("test2")].Flags, []string{"\\HasChildren"}, []string{"\\Subscribed"}); err != nil {
		return err
	}
	if err := pmChildInfo(items[name("test2")]); err != nil {
		return err
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST \"\" "+Quote(base+sep+"%")+" RETURN (CHILDREN SUBSCRIBED)", []string{name("test1"), name("test2"), name("test3"), name("test4"), name("test7"), name("test8")}, nil)
	if err != nil {
		return err
	}
	for _, tc := range []struct {
		suffix  string
		yes, no []string
	}{{"test1", []string{"\\Subscribed"}, []string{"\\HasChildren"}}, {"test2", []string{"\\HasChildren"}, []string{"\\Subscribed"}}, {"test3", nil, []string{"\\Subscribed", "\\HasChildren"}}, {"test4", []string{"\\HasChildren"}, []string{"\\Subscribed"}}, {"test7", []string{"\\HasChildren"}, []string{"\\Subscribed"}}, {"test8", []string{"\\HasChildren"}, []string{"\\Subscribed"}}} {
		if err := pmSystemFlags(items[name(tc.suffix)].Flags, tc.yes, tc.no); err != nil {
			return err
		}
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" "+Quote(base+"*test7"), []string{name("test7/test7")}, nil)
	if err != nil {
		return err
	}
	if err := pmOptionalRecursiveParent(items, name("test7")); err != nil {
		return err
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" "+Quote(base+"*test8"), []string{name("test8/test8")}, nil)
	if err != nil {
		return err
	}
	if parent, ok := items[name("test8")]; ok {
		if err := pmSystemFlags(parent.Flags, nil, []string{"\\Subscribed"}); err != nil {
			return err
		}
		if err := pmChildInfo(parent); err != nil {
			return err
		}
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" ("+Quote(name("test2"))+")", []string{name("test2")}, []string{name("test2/test1")})
	if err != nil {
		return err
	}
	if err := pmChildInfo(items[name("test2")]); err != nil {
		return err
	}
	items, err = pmExpectList(s.Client, "LIST", "LIST (SUBSCRIBED RECURSIVEMATCH) \"\" ("+Quote(name("test2"))+" "+Quote(name("test2/test1"))+")", []string{name("test2/test1")}, nil)
	if err != nil {
		return err
	}
	if err := pmOptionalRecursiveParent(items, name("test2")); err != nil {
		return err
	}
	_, err = pmExpectList(s.Client, "LIST", "LIST \"\" ("+Quote(name("test7"))+" "+Quote(name("test7/test7"))+")", []string{name("test7/test7")}, nil)
	return err
}

func pmOptionalRecursiveParent(items map[string]pmListed, name string) error {
	if parent, present := items[name]; present {
		if err := pmSystemFlags(parent.Flags, nil, []string{"\\Subscribed"}); err != nil {
			return err
		}
		return pmChildInfo(parent)
	}
	return nil
}

func pmChildInfo(item pmListed) error {
	for i := 0; i+1 < len(item.Extra); i++ {
		if strings.EqualFold(item.Extra[i].Text, "CHILDINFO") && item.Extra[i+1].IsList && coreHasFlag(item.Extra[i+1], "SUBSCRIBED") {
			return nil
		}
	}
	// Extended LIST data are commonly wrapped in an outer parenthesized list.
	for _, extra := range item.Extra {
		if extra.IsList {
			for i := 0; i+1 < len(extra.List); i++ {
				if strings.EqualFold(extra.List[i].Text, "CHILDINFO") && extra.List[i+1].IsList && coreHasFlag(extra.List[i+1], "SUBSCRIBED") {
					return nil
				}
			}
		}
	}
	return Check(false, "recursive LIST parent omitted CHILDINFO SUBSCRIBED")
}

func pmLogout(s *Session) error {
	a, err := s.NewUnauthenticatedClient()
	if err != nil {
		return err
	}
	b, err := s.NewUnauthenticatedClient()
	if err != nil {
		return err
	}
	for _, c := range []*Client{a, b} {
		r, err := c.OK("NOOP")
		if err != nil {
			return err
		}
		if err := Check(len(r.Data("BYE")) == 0, "NOOP sent BYE"); err != nil {
			return err
		}
	}
	for _, c := range []*Client{a, b} {
		r, err := c.OK("LOGOUT")
		if err != nil {
			return err
		}
		if err := Check(len(r.Data("BYE")) == 1, "LOGOUT omitted a single BYE response"); err != nil {
			return err
		}
		if c == a {
			if _, err := b.OK("NOOP"); err != nil {
				return err
			}
		}
	}
	return nil
}

func pmModifiedUTF7(s *Session) error {
	sep, err := pmDelimiter(s.Client)
	if err != nil {
		return err
	}
	root := s.Name("utf7")
	if err := s.CreateMailbox(s.Client, root); err != nil {
		return err
	}
	name := root + sep + "p&AOQA5A-"
	if err := s.CreateMailbox(s.Client, name); err != nil {
		return err
	}
	if _, err := pmExpectList(s.Client, "LIST", "LIST \"\" "+Quote(name), []string{name}, nil); err != nil {
		return err
	}
	return pmCheckCount(s.Client, name, 0)
}

func pmPipeline(s *Session) error            { return pmPipelineN(s, false, 4) }
func pmPipelineConnections(s *Session) error { return pmPipelineN(s, true, 2) }
func pmPipelineN(s *Session, other bool, count int) error {
	names := make([]string, count)
	for i := range names {
		names[i] = s.Name(fmt.Sprintf("pipeline-%d", i))
	}
	responses, err := s.PipelineCreates(s.Client, names...)
	if err != nil {
		return err
	}
	for _, r := range responses {
		if err := Check(r.Status == "OK", "pipelined CREATE returned %s", r.Status); err != nil {
			return err
		}
	}
	c := s.Client
	if other {
		c, err = s.NewClient()
		if err != nil {
			return err
		}
	}
	commands := make([]string, len(names))
	for i, name := range names {
		commands[i] = "STATUS " + Quote(name) + " (MESSAGES)"
	}
	responses, err = c.Pipeline(commands...)
	if err != nil {
		return err
	}
	for i, r := range responses {
		if err := Check(r.Status == "OK", "pipelined STATUS returned %s", r.Status); err != nil {
			return err
		}
		values, err := r.StatusValues(names[i])
		if err != nil {
			return err
		}
		if err := Check(values["MESSAGES"] == 0, "new pipelined mailbox contains messages"); err != nil {
			return err
		}
	}
	return nil
}

func pmCodeNumber(r Response, name string) (uint64, error) {
	code := r.Code(name)
	if err := Check(len(code) == 1, "response omitted %s", name); err != nil {
		return 0, err
	}
	return code[0].Uint()
}
func pmSelect(s *Session) error {
	box, _, err := portMailbox(s, "select", 2, false)
	if err != nil {
		return err
	}
	examined, err := s.Client.OK("EXAMINE " + Quote(box))
	if err != nil {
		return err
	}
	if err := pmExists(examined, 2); err != nil {
		return err
	}
	if err := Check(examined.Code("READ-ONLY") != nil, "EXAMINE omitted READ-ONLY"); err != nil {
		return err
	}
	validity, err := pmCodeNumber(examined, "UIDVALIDITY")
	if err != nil {
		return err
	}
	next, err := pmCodeNumber(examined, "UIDNEXT")
	if err != nil {
		return err
	}
	if err := Check(validity > 0 && next > 0, "EXAMINE returned zero UIDVALIDITY or UIDNEXT"); err != nil {
		return err
	}
	if examined.Code("UIDNOTSTICKY") != nil {
		return Skip("cross-selection UID metadata checks require persistent UIDs; server reports UIDNOTSTICKY")
	}
	if err := pmRecentCount(examined, 2); err != nil {
		return err
	}
	if err := pmSelectionMetadata(examined); err != nil {
		return err
	}
	if _, err = s.Client.OK("CLOSE"); err != nil {
		return err
	}
	status, err := pmStatus(s.Client, box, "MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN")
	if err != nil {
		return err
	}
	if err := pmPersistentSelection(validity, status["UIDVALIDITY"]); err != nil {
		return err
	}
	if err := Check(status["MESSAGES"] == 2 && status["UNSEEN"] == 2 && status["RECENT"] == 2 && status["UIDNEXT"] == next, "STATUS after EXAMINE differs: %v", status); err != nil {
		return err
	}
	selected, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	selectedValidity, err := pmCodeNumber(selected, "UIDVALIDITY")
	if err != nil {
		return err
	}
	if selected.Code("UIDNOTSTICKY") != nil {
		return Skip("cross-selection UID metadata checks require persistent UIDs; server reports UIDNOTSTICKY")
	}
	if err := pmPersistentSelection(validity, selectedValidity); err != nil {
		return err
	}
	if err := pmExists(selected, 2); err != nil {
		return err
	}
	if err := pmRecentCount(selected, 2); err != nil {
		return err
	}
	// A READ-WRITE response code is a SHOULD. READ-ONLY is mandatory if the
	// server selected a read-only mailbox; its CLOSE need not consume Recent.
	if selected.Code("READ-ONLY") != nil {
		return Skip("read-write Recent consumption requires a writable SELECT")
	}
	if err := pmSelectionMetadata(selected); err != nil {
		return err
	}
	for name, want := range map[string]uint64{"UIDVALIDITY": validity, "UIDNEXT": next} {
		n, err := pmCodeNumber(selected, name)
		if err != nil {
			return err
		}
		if err := Check(n == want, "SELECT %s changed without a mailbox mutation", name); err != nil {
			return err
		}
	}
	if _, err = s.Client.OK("CLOSE"); err != nil {
		return err
	}
	status, err = pmStatus(s.Client, box, "RECENT")
	if err != nil {
		return err
	}
	return Check(status["RECENT"] == 0, "STATUS RECENT=%d after read-write selection and CLOSE", status["RECENT"])
}

func pmPersistentSelection(before, after uint64) error {
	if err := Check(before > 0 && after > 0 && after >= before, "UIDVALIDITY regressed from %d to %d", before, after); err != nil {
		return err
	}
	if before != after {
		return Skip("UIDVALIDITY changed between selections; persistent UID metadata comparison is unavailable")
	}
	return nil
}

func pmSelectionMetadata(r Response) error {
	unseen, err := pmCodeNumber(r, "UNSEEN")
	if err != nil {
		return err
	}
	if err := Check(unseen == 1, "first unseen sequence=%d, want 1", unseen); err != nil {
		return err
	}
	flags := r.Data("FLAGS")
	if err := Check(len(flags) == 1 && len(flags[0].Values) == 2 && flags[0].Values[1].IsList, "selection omitted FLAGS list"); err != nil {
		return err
	}
	permanent := r.Code("PERMANENTFLAGS")
	return Check(len(permanent) == 1 && permanent[0].IsList, "selection omitted PERMANENTFLAGS list")
}

func pmRecentCount(r Response, want uint64) error {
	var found bool
	var n uint64
	for _, reply := range r.Data("RECENT") {
		n, found = reply.Number()
	}
	return Check(found && n == want, "RECENT=%d (present=%t), want %d", n, found, want)
}

func pmStore(s *Session) error {
	box, _, err := portMailbox(s, "store", 4, true)
	if err != nil {
		return err
	}
	a := s.Client
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	selected, err := coreSelect(b, box)
	if err != nil {
		return err
	}
	if _, err = a.OK("STORE 1:3 FLAGS (\\Seen)"); err != nil {
		return err
	}
	if _, err = b.OK("CHECK"); err != nil {
		return err
	}
	for _, c := range []*Client{a, b} {
		for _, seq := range []uint64{1, 2, 3} {
			flags, _, err := pmFlags(c, seq)
			if err != nil {
				return err
			}
			if err := pmSystemFlags(flags, []string{"\\Seen"}, nil); err != nil {
				return err
			}
		}
	}
	if _, err = a.OK("STORE 4 -FLAGS (\\Seen)"); err != nil {
		return err
	}
	if _, err = a.OK("STORE 3 FLAGS (\\Draft)"); err != nil {
		return err
	}
	flags, _, err := pmFlags(a, 3)
	if err != nil {
		return err
	}
	if err := pmSystemFlags(flags, []string{"\\Draft"}, []string{"\\Seen"}); err != nil {
		return err
	}
	if code := selected.Code("PERMANENTFLAGS"); len(code) == 1 && coreHasFlag(code[0], "\\*") {
		if _, err = a.OK("STORE 2,4 +FLAGS ($hello $world)"); err != nil {
			return err
		}
		for _, seq := range []uint64{2, 4} {
			flags, _, err := pmFlags(a, seq)
			if err != nil {
				return err
			}
			if err := pmSystemFlags(flags, []string{"$hello", "$world"}, nil); err != nil {
				return err
			}
		}
	}
	if _, err = a.OK("STORE 1 +FLAGS (\\Answered)"); err != nil {
		return err
	}
	if _, err = b.OK("STORE 1 -FLAGS (\\Seen)"); err != nil {
		return err
	}
	for _, c := range []*Client{a, b} {
		if _, err = c.OK("CHECK"); err != nil {
			return err
		}
		flags, _, err := pmFlags(c, 1)
		if err != nil {
			return err
		}
		if err := pmSystemFlags(flags, []string{"\\Answered"}, []string{"\\Seen"}); err != nil {
			return err
		}
	}
	return nil
}

func pmSubscribe(s *Session) error {
	sep, err := pmDelimiter(s.Client)
	if err != nil {
		return err
	}
	base := s.Name("subscriptions")
	name := func(suffix string) string { return base + sep + strings.ReplaceAll(suffix, "/", sep) }
	if err := s.CreateMailboxAs(s.Client, base+sep, base); err != nil {
		return err
	}
	for _, suffix := range []string{"test", "test2", "test3", "test2/test", "test3/test3"} {
		wire := name(suffix)
		if suffix == "test2" || suffix == "test3" {
			wire += sep
		}
		if err := s.CreateMailboxAs(s.Client, wire, name(suffix)); err != nil {
			return err
		}
	}
	for _, suffix := range []string{"test", "test2/test", "test3/test3"} {
		if _, err := s.Client.OK("SUBSCRIBE " + Quote(name(suffix))); err != nil {
			return err
		}
		if err := s.TrackSubscription(name(suffix)); err != nil {
			return err
		}
	}
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	items, err := pmExpectList(b, "LSUB", "LSUB \"\" "+Quote(base+sep+"%"), []string{name("test"), name("test2"), name("test3")}, []string{name("test2/test"), name("test3/test3")})
	if err != nil {
		return err
	}
	for _, suffix := range []string{"test2", "test3"} {
		if err := pmSystemFlags(items[name(suffix)].Flags, []string{"\\Noselect"}, nil); err != nil {
			return err
		}
	}
	if _, err := pmExpectList(b, "LSUB", "LSUB \"\" "+Quote(base+sep+"*test"), []string{name("test"), name("test2/test")}, []string{name("test3/test3")}); err != nil {
		return err
	}
	if _, err = s.Client.OK("UNSUBSCRIBE " + Quote(name("test"))); err != nil {
		return err
	}
	if _, err := pmExpectList(b, "LSUB", "LSUB \"\" "+Quote(base+sep+"%"), nil, []string{name("test")}); err != nil {
		return err
	}
	if _, err = s.Client.OK("UNSUBSCRIBE " + Quote(name("test2/test"))); err != nil {
		return err
	}
	if _, err := pmExpectList(b, "LSUB", "LSUB \"\" "+Quote(base+sep+"*"), []string{name("test3/test3")}, []string{name("test")}); err != nil {
		return err
	}
	if _, err = s.Client.OK("UNSUBSCRIBE " + Quote(name("test3/test3"))); err != nil {
		return err
	}
	_, err = pmExpectList(b, "LSUB", "LSUB \"\" "+Quote(base+sep+"%"), nil, []string{name("test3")})
	return err
}

func pmUIDPlus(s *Session) error {
	src, messages, err := portMailbox(s, "uidplus", 1, true)
	if err != nil {
		return err
	}
	dst, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	appendReply, err := s.Client.Append(dst, nil, "", messages[0])
	if err != nil {
		return err
	}
	sourceUIDs, _, err := extSelectedUIDs(s.Client, src)
	if err != nil {
		return err
	}
	if err := Check(len(sourceUIDs) == 1, "UIDPLUS source count differs"); err != nil {
		return err
	}
	copyReply, err := s.Client.OK("COPY 1 " + Quote(dst))
	if err != nil {
		return err
	}
	destUIDs, selected, err := extSelectedUIDs(s.Client, dst)
	if err != nil {
		return err
	}
	if err := Check(len(destUIDs) == 2, "UIDPLUS destination count differs"); err != nil {
		return err
	}
	if code := appendReply.Code("APPENDUID"); code != nil {
		if err := extCheckAppendUID(code, selected, destUIDs[0]); err != nil {
			return err
		}
	}
	if code := copyReply.Code("COPYUID"); code != nil {
		if err := extCheckCopyUID(code, selected, sourceUIDs[0], destUIDs[1]); err != nil {
			return err
		}
	}
	return nil
}

func pmUIDValidity(s *Session) error {
	box, messages, err := portMailbox(s, "uidvalidity", 1, false)
	if err != nil {
		return err
	}
	before, err := pmIdentity(s.Client, box)
	if err != nil {
		return err
	}
	if err := s.DeleteMailbox(s.Client, box); err != nil {
		return err
	}
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	if err := s.CreateMailbox(b, box); err != nil {
		return err
	}
	if _, err = b.Append(box, nil, "", messages[0]); err != nil {
		return err
	}
	after, err := pmIdentity(s.Client, box)
	if err != nil {
		return err
	}
	return Check(before.validity != after.validity || before.uid != after.uid, "recreated mailbox reused (name, UIDVALIDITY, UID) identity")
}

type pmMailboxIdentity struct{ validity, uid, next uint64 }

func pmIdentity(c *Client, box string) (pmMailboxIdentity, error) {
	status, err := pmStatus(c, box, "UIDVALIDITY UIDNEXT")
	if err != nil {
		return pmMailboxIdentity{}, err
	}
	selected, err := coreSelect(c, box)
	if err != nil {
		return pmMailboxIdentity{}, err
	}
	uids, err := coreUIDs(c)
	if err != nil {
		return pmMailboxIdentity{}, err
	}
	if err := Check(len(uids) == 1 && status["UIDVALIDITY"] > 0 && status["UIDNEXT"] > uids[0], "mailbox identity metadata invalid: %v UIDs=%v", status, uids); err != nil {
		return pmMailboxIdentity{}, err
	}
	validity, err := pmCodeNumber(selected, "UIDVALIDITY")
	if err != nil {
		return pmMailboxIdentity{}, err
	}
	if err := Check(validity == status["UIDVALIDITY"], "SELECT/STATUS UIDVALIDITY disagree"); err != nil {
		return pmMailboxIdentity{}, err
	}
	if _, err = c.OK("CLOSE"); err != nil {
		return pmMailboxIdentity{}, err
	}
	return pmMailboxIdentity{validity, uids[0], status["UIDNEXT"]}, nil
}

func pmUIDValidityRename(s *Session) error {
	box, messages, err := portMailbox(s, "uidvalidity-rename", 1, false)
	if err != nil {
		return err
	}
	other, err := s.NewMailbox("other")
	if err != nil {
		return err
	}
	b, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err = b.Append(other, nil, "", messages[0]); err != nil {
		return err
	}
	before, err := pmIdentity(s.Client, box)
	if err != nil {
		return err
	}
	renamed := s.Name("renamed")
	if err := s.RenameMailbox(s.Client, box, renamed); err != nil {
		return err
	}
	if err := s.RenameMailbox(b, other, box); err != nil {
		return err
	}
	after, err := pmIdentity(s.Client, box)
	if err != nil {
		return err
	}
	return Check(before.validity != after.validity || before.uid != after.uid, "renamed replacement reused (name, UIDVALIDITY, UID) identity")
}
