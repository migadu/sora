package imaptest

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// These scenarios follow the extension RFCs rather than a particular server's
// response text, UID allocator, or ordering of unrelated untagged responses.
func extensionCases() []Case {
	return []Case{
		{Name: "uidplus/mappings", Description: "Validate APPENDUID and COPYUID when returned", RFC: "https://www.rfc-editor.org/rfc/rfc4315.html#section-3", Requires: []string{"UIDPLUS"}, Run: extUIDMappings},
		{Name: "uidplus/targeted-expunge", Description: "UID EXPUNGE removes only named messages marked deleted", RFC: "https://www.rfc-editor.org/rfc/rfc4315.html#section-2.1", Requires: []string{"UIDPLUS"}, Run: extUIDExpunge},
		{Name: "move/uid-move", Description: "UID MOVE transfers a message and preserves its contents", RFC: "https://www.rfc-editor.org/rfc/rfc6851.html#section-3", Requires: []string{"MOVE"}, Run: extMove},
		{Name: "literal-plus/append", Description: "Non-synchronizing APPEND supports literals larger than 4096 octets", RFC: "https://www.rfc-editor.org/rfc/rfc7888.html#section-3", Requires: []string{"LITERAL+"}, Run: extLiteralPlus},
		{Name: "esearch/bounds-count", Description: "UID ESEARCH reports MIN, MAX and COUNT including empty results", RFC: "https://www.rfc-editor.org/rfc/rfc4731.html#section-3.1", Requires: []string{"ESEARCH"}, Run: extESearch},
		{Name: "condstore/conditional-store", Description: "UNCHANGEDSINCE protects system flags and successful writes advance MODSEQ", RFC: "https://www.rfc-editor.org/rfc/rfc7162.html#section-3.1.3", Requires: []string{"CONDSTORE"}, Run: extCondstore},
		{Name: "enable/condstore", Description: "ENABLE reports CONDSTORE and ignores an unknown extension", RFC: "https://www.rfc-editor.org/rfc/rfc5161.html#section-3", Requires: []string{"ENABLE", "CONDSTORE"}, Run: extEnable},
		{Name: "unselect/preserves-deleted", Description: "UNSELECT releases a mailbox without expunging deleted messages", RFC: "https://www.rfc-editor.org/rfc/rfc3691.html#section-2", Requires: []string{"UNSELECT"}, Run: extUnselect},
		{Name: "binary/decoded-content", Description: "BINARY.PEEK and BINARY.SIZE decode a MIME part containing NUL", RFC: "https://www.rfc-editor.org/rfc/rfc3516.html#section-4.2", Requires: []string{"BINARY"}, Run: extBinary},
		{Name: "sessions/append-visibility", Description: "Another selected session observes APPEND after NOOP", RFC: "https://www.rfc-editor.org/rfc/rfc3501.html#section-6.1.2", Run: extSessions},
		{Name: "pipeline/independent-status", Description: "Independent pipelined STATUS commands retain their tagged results", RFC: "https://www.rfc-editor.org/rfc/rfc3501.html#section-5.5", Run: extPipeline},
	}
}

func extMessage(label string) []byte {
	return []byte("From: sender@example.test\r\nTo: reader@example.test\r\n" +
		"Date: Wed, 18 Nov 2026 08:00:00 +0000\r\nSubject: " + label + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n" +
		"An original sora-imaptest fixture: " + label + ".\r\n")
}

func extSelectedUIDs(c *Client, box string) ([]uint64, Response, error) {
	r, err := c.OK("SELECT " + Quote(box))
	if err != nil {
		return nil, r, err
	}
	search, err := c.OK("UID SEARCH ALL")
	if err != nil {
		return nil, r, err
	}
	uids, err := search.Search()
	slices.Sort(uids)
	return uids, r, err
}

func extOneFetch(c *Client, command string, uid uint64) (Fetch, error) {
	r, err := c.OK(command)
	if err != nil {
		return Fetch{}, err
	}
	fs, err := r.Fetches()
	if err != nil {
		return Fetch{}, err
	}
	var found *Fetch
	for _, f := range fs {
		v, exists := f.Attrs["UID"]
		if !exists {
			continue // an unsolicited flag update need not include the requested data
		}
		n, err := v.Uint()
		if err != nil {
			return Fetch{}, err
		}
		if n == uid {
			if found == nil {
				found = &Fetch{Seq: f.Seq, Attrs: make(map[string]Value)}
			}
			for name, value := range f.Attrs {
				found.Attrs[name] = value
			}
		}
	}
	if found != nil {
		return *found, nil
	}
	return Fetch{}, Check(false, "FETCH did not return message UID %d", uid)
}

func extUIDMappings(s *Session) error {
	src, err := s.NewMailbox("source")
	if err != nil {
		return err
	}
	dst, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	message := extMessage("uidplus mapping")
	appendReply, err := s.Client.Append(src, nil, "", message)
	if err != nil {
		return err
	}
	uids, selected, err := extSelectedUIDs(s.Client, src)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "APPEND left %d messages, want 1", len(uids)); err != nil {
		return err
	}
	// RFC 4315 recommends these response codes with SHOULD, and explicitly
	// permits omission for UIDNOTSTICKY stores. Validate supplied mappings;
	// absence alone is not a protocol violation.
	if code := appendReply.Code("APPENDUID"); code != nil {
		if err := extCheckAppendUID(code, selected, uids[0]); err != nil {
			return err
		}
	}
	copyReply, err := s.Client.OK(fmt.Sprintf("UID COPY %d %s", uids[0], Quote(dst)))
	if err != nil {
		return err
	}
	destUIDs, destSelected, err := extSelectedUIDs(s.Client, dst)
	if err != nil {
		return err
	}
	if err := Check(len(destUIDs) == 1, "COPY left %d destination messages, want 1", len(destUIDs)); err != nil {
		return err
	}
	if code := copyReply.Code("COPYUID"); code != nil {
		if err := extCheckCopyUID(code, destSelected, uids[0], destUIDs[0]); err != nil {
			return err
		}
	}
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID BODY.PEEK[])", destUIDs[0]), destUIDs[0])
	if err != nil {
		return err
	}
	body, exists := f.Attrs["BODY[]"]
	return Check(exists && body.Text == string(message), "COPY changed the message content")
}

func extCheckAppendUID(code []Value, selected Response, uid uint64) error {
	if err := Check(len(code) == 2, "APPENDUID has %d fields, want 2", len(code)); err != nil {
		return err
	}
	if err := extCheckValidity(code[0], selected); err != nil {
		return err
	}
	set, err := extUIDSet(code[1].Text)
	if err != nil {
		return err
	}
	return Check(slices.Equal(set, []uint64{uid}), "APPENDUID returned %v, actual UID is %d", set, uid)
}

func extCheckCopyUID(code []Value, selected Response, sourceUID, destinationUID uint64) error {
	if err := Check(len(code) == 3, "COPYUID has %d fields, want 3", len(code)); err != nil {
		return err
	}
	if err := extCheckValidity(code[0], selected); err != nil {
		return err
	}
	src, err := extUIDSet(code[1].Text)
	if err != nil {
		return err
	}
	dst, err := extUIDSet(code[2].Text)
	if err != nil {
		return err
	}
	return Check(slices.Equal(src, []uint64{sourceUID}) && slices.Equal(dst, []uint64{destinationUID}),
		"COPYUID mapping %v -> %v differs from actual %d -> %d", src, dst, sourceUID, destinationUID)
}

func extCheckValidity(value Value, selected Response) error {
	validity, err := value.Uint()
	if err != nil {
		return err
	}
	if err := Check(validity > 0, "UIDVALIDITY must be nonzero"); err != nil {
		return err
	}
	code := selected.Code("UIDVALIDITY")
	if err := Check(len(code) == 1, "SELECT did not return a UIDVALIDITY"); err != nil {
		return err
	}
	actual, err := code[0].Uint()
	if err != nil {
		return err
	}
	return Check(validity == actual, "response UIDVALIDITY %d differs from selected mailbox %d", validity, actual)
}

func extUIDExpunge(s *Session) error {
	box, err := s.NewMailbox("messages")
	if err != nil {
		return err
	}
	for _, label := range []string{"remove", "keep deleted", "keep undeleted"} {
		if _, err := s.Client.Append(box, nil, "", extMessage(label)); err != nil {
			return err
		}
	}
	uids, _, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 3, "want 3 messages, got %v", uids); err != nil {
		return err
	}
	if _, err := s.Client.OK(fmt.Sprintf("UID STORE %d,%d +FLAGS.SILENT (\\Deleted)", uids[0], uids[1])); err != nil {
		return err
	}
	// Including the undeleted third message proves the flag condition is also
	// honored. The second is deleted but deliberately excluded from the set.
	if _, err := s.Client.OK(fmt.Sprintf("UID EXPUNGE %d,%d", uids[0], uids[2])); err != nil {
		return err
	}
	r, err := s.Client.OK("UID SEARCH ALL")
	if err != nil {
		return err
	}
	remaining, err := r.Search()
	if err != nil {
		return err
	}
	slices.Sort(remaining)
	return Check(slices.Equal(remaining, uids[1:]), "UID EXPUNGE left %v, want %v", remaining, uids[1:])
}

func extMove(s *Session) error {
	src, err := s.NewMailbox("source")
	if err != nil {
		return err
	}
	dst, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	message := extMessage("uid move")
	if _, err := s.Client.Append(src, nil, "", message); err != nil {
		return err
	}
	uids, _, err := extSelectedUIDs(s.Client, src)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "want 1 source message, got %v", uids); err != nil {
		return err
	}
	if _, err := s.Client.OK(fmt.Sprintf("UID STORE %d +FLAGS.SILENT (\\Flagged)", uids[0])); err != nil {
		return err
	}
	moved, err := s.Client.OK(fmt.Sprintf("UID MOVE %d %s", uids[0], Quote(dst)))
	if err != nil {
		return err
	}
	r, err := s.Client.OK("UID SEARCH ALL")
	if err != nil {
		return err
	}
	remaining, err := r.Search()
	if err != nil {
		return err
	}
	if err := Check(len(remaining) == 0, "UID MOVE retained source UIDs %v", remaining); err != nil {
		return err
	}
	destUIDs, selected, err := extSelectedUIDs(s.Client, dst)
	if err != nil {
		return err
	}
	if err := Check(len(destUIDs) == 1, "UID MOVE produced %d destination messages, want 1", len(destUIDs)); err != nil {
		return err
	}
	// COPYUID may be on an untagged or the tagged OK response. Response.Code
	// searches both; no placement or EXPUNGE ordering is assumed.
	if code := moved.Code("COPYUID"); code != nil {
		if err := extCheckCopyUID(code, selected, uids[0], destUIDs[0]); err != nil {
			return err
		}
	}
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS BODY.PEEK[])", destUIDs[0]), destUIDs[0])
	if err != nil {
		return err
	}
	body, exists := f.Attrs["BODY[]"]
	return Check(exists && body.Text == string(message) && extHasFlag(f.Attrs["FLAGS"], "\\Flagged"), "MOVE did not preserve content and \\Flagged")
}

func extLiteralPlus(s *Session) error {
	box, err := s.NewMailbox("message")
	if err != nil {
		return err
	}
	message := append(extMessage("large non-synchronizing literal"), []byte(strings.Repeat("A 70-octet-safe line in a non-synchronizing APPEND literal.\r\n", 90))...)
	if _, err := s.Client.AppendNonSync(box, nil, "", message); err != nil {
		return err
	}
	uids, _, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "non-synchronizing APPEND left %d messages, want 1", len(uids)); err != nil {
		return err
	}
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID BODY.PEEK[])", uids[0]), uids[0])
	if err != nil {
		return err
	}
	body, exists := f.Attrs["BODY[]"]
	return Check(exists && body.Text == string(message), "non-synchronizing APPEND did not round-trip %d octets", len(message))
}

func extESearch(s *Session) error {
	box, err := s.NewMailbox("messages")
	if err != nil {
		return err
	}
	for i := range 3 {
		if _, err := s.Client.Append(box, nil, "", extMessage(fmt.Sprintf("esearch %d", i))); err != nil {
			return err
		}
	}
	uids, _, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 3, "want 3 messages, got %v", uids); err != nil {
		return err
	}
	r, err := s.Client.OK("UID SEARCH RETURN (MIN MAX COUNT) ALL")
	if err != nil {
		return err
	}
	values, err := extESearchValues(r)
	if err != nil {
		return err
	}
	for key, want := range map[string]uint64{"COUNT": 3, "MIN": slices.Min(uids), "MAX": slices.Max(uids)} {
		v, ok := values[key]
		if err := Check(ok, "ESEARCH omitted %s", key); err != nil {
			return err
		}
		n, err := v.Uint()
		if err != nil {
			return err
		}
		if err := Check(n == want, "ESEARCH %s=%d, want %d", key, n, want); err != nil {
			return err
		}
	}
	r, err = s.Client.OK("UID SEARCH RETURN (MIN MAX COUNT) NOT ALL")
	if err != nil {
		return err
	}
	values, err = extESearchValues(r)
	if err != nil {
		return err
	}
	count, exists := values["COUNT"]
	if err := Check(exists, "empty ESEARCH omitted COUNT"); err != nil {
		return err
	}
	n, err := count.Uint()
	if err != nil {
		return err
	}
	_, hasMin := values["MIN"]
	_, hasMax := values["MAX"]
	return Check(n == 0 && !hasMin && !hasMax, "empty ESEARCH must return COUNT 0 without MIN or MAX")
}

func extESearchValues(r Response) (map[string]Value, error) {
	replies := r.Data("ESEARCH")
	if err := Check(len(replies) == 1, "want one ESEARCH response, got %d", len(replies)); err != nil {
		return nil, err
	}
	values := make(map[string]Value)
	hasUID := false
	for i := 1; i < len(replies[0].Values); {
		v := replies[0].Values[i]
		if v.IsList { // optional (TAG "...") correlator
			if len(v.List) == 2 && strings.EqualFold(v.List[0].Text, "TAG") {
				if err := Check(v.List[1].Text == r.Tag, "ESEARCH correlator %q differs from command tag %q", v.List[1].Text, r.Tag); err != nil {
					return nil, err
				}
			}
			i++
			continue
		}
		key := strings.ToUpper(v.Text)
		if key == "UID" {
			hasUID = true
			i++
			continue
		}
		if err := Check(i+1 < len(replies[0].Values), "ESEARCH %s lacks a value", key); err != nil {
			return nil, err
		}
		if _, duplicate := values[key]; duplicate {
			return nil, Check(false, "ESEARCH repeated result %s", key)
		}
		values[key] = replies[0].Values[i+1]
		i += 2
	}
	return values, Check(hasUID, "UID SEARCH omitted the ESEARCH UID indicator")
}

func extCondstore(s *Session) error {
	box, err := s.NewMailbox("message")
	if err != nil {
		return err
	}
	if _, err := s.Client.Append(box, nil, "", extMessage("conditional store")); err != nil {
		return err
	}
	selected, err := s.Client.OK("SELECT " + Quote(box) + " (CONDSTORE)")
	if err != nil {
		return err
	}
	if err := Check(len(selected.Code("HIGHESTMODSEQ")) == 1, "CONDSTORE SELECT omitted HIGHESTMODSEQ"); err != nil {
		return err
	}
	r, err := s.Client.OK("UID SEARCH ALL")
	if err != nil {
		return err
	}
	uids, err := r.Search()
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "want one conditional-store message, got %v", uids); err != nil {
		return err
	}
	uid := uids[0]
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS MODSEQ)", uid), uid)
	if err != nil {
		return err
	}
	before, err := extModseq(f)
	if err != nil {
		return err
	}
	r, err = s.Client.OK(fmt.Sprintf("UID STORE %d (UNCHANGEDSINCE 0) +FLAGS (\\Seen)", uid))
	if err != nil {
		return err
	}
	modified := r.Code("MODIFIED")
	if err := Check(len(modified) == 1, "UNCHANGEDSINCE 0 omitted MODIFIED"); err != nil {
		return err
	}
	set, err := extUIDSet(modified[0].Text)
	if err != nil {
		return err
	}
	if err := Check(slices.Equal(set, []uint64{uid}), "MODIFIED contains %v, want UID %d", set, uid); err != nil {
		return err
	}
	f, err = extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS MODSEQ)", uid), uid)
	if err != nil {
		return err
	}
	if err := Check(!extHasFlag(f.Attrs["FLAGS"], "\\Seen"), "failed conditional STORE changed \\Seen"); err != nil {
		return err
	}
	stored, err := s.Client.OK(fmt.Sprintf("UID STORE %d (UNCHANGEDSINCE %d) +FLAGS (\\Seen)", uid, before))
	if err != nil {
		return err
	}
	if err := Check(stored.Code("MODIFIED") == nil, "successful conditional STORE unexpectedly returned MODIFIED"); err != nil {
		return err
	}
	f, err = extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS MODSEQ)", uid), uid)
	if err != nil {
		return err
	}
	after, err := extModseq(f)
	if err != nil {
		return err
	}
	return Check(extHasFlag(f.Attrs["FLAGS"], "\\Seen") && after > before, "successful conditional STORE must set \\Seen and advance MODSEQ (before=%d after=%d)", before, after)
}

func extModseq(f Fetch) (uint64, error) {
	v, exists := f.Attrs["MODSEQ"]
	if err := Check(exists && v.IsList && len(v.List) == 1, "FETCH omitted a valid MODSEQ list"); err != nil {
		return 0, err
	}
	n, err := v.List[0].Uint()
	if err != nil {
		return 0, err
	}
	return n, Check(n > 0, "MODSEQ must be nonzero")
}

func extEnable(s *Session) error {
	const unknown = "X-SORA-IMAPTEST-UNKNOWN"
	r, err := s.Client.OK("ENABLE CONDSTORE " + unknown)
	if err != nil {
		return err
	}
	found := false
	for _, reply := range r.Data("ENABLED") {
		for _, capability := range reply.Values[1:] {
			if err := Check(!strings.EqualFold(capability.Text, unknown), "server enabled an unknown capability"); err != nil {
				return err
			}
			found = found || strings.EqualFold(capability.Text, "CONDSTORE")
		}
	}
	return Check(found, "ENABLE CONDSTORE omitted CONDSTORE from ENABLED")
}

func extUnselect(s *Session) error {
	box, err := s.NewMailbox("message")
	if err != nil {
		return err
	}
	if _, err := s.Client.Append(box, nil, "", extMessage("unselect keeps me")); err != nil {
		return err
	}
	before, beforeSelected, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(before) == 1, "want one deleted message, got %v", before); err != nil {
		return err
	}
	if _, err := s.Client.OK(fmt.Sprintf("UID STORE %d +FLAGS.SILENT (\\Deleted)", before[0])); err != nil {
		return err
	}
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS BODY.PEEK[])", before[0]), before[0])
	if err != nil {
		return err
	}
	if err := Check(extHasFlag(f.Attrs["FLAGS"], "\\Deleted"), "UNSELECT fixture was not marked \\Deleted"); err != nil {
		return err
	}
	body, exists := f.Attrs["BODY[]"]
	if err := Check(exists && !body.IsNil && !body.IsList, "UNSELECT fixture FETCH omitted message content"); err != nil {
		return err
	}
	if _, err := s.Client.OK("UNSELECT"); err != nil {
		return err
	}
	// FETCH is legal only in selected state; a successful command here would
	// mean UNSELECT failed to release the selected mailbox.
	r, err := s.Client.Command("FETCH 1 UID")
	if err != nil {
		return err
	}
	if err := Check(strings.EqualFold(r.Status, "BAD"), "FETCH after UNSELECT returned %s, want BAD", r.Status); err != nil {
		return err
	}
	after, afterSelected, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(after) == 1, "UNSELECT expunged a message: before=%v after=%v", before, after); err != nil {
		return err
	}
	beforeValidity, err := extSelectedValidity(beforeSelected)
	if err != nil {
		return err
	}
	afterValidity, err := extSelectedValidity(afterSelected)
	if err != nil {
		return err
	}
	if err := extCheckReselectedUID(before[0], after[0], beforeValidity, afterValidity); err != nil {
		return err
	}
	f, err = extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS BODY.PEEK[])", after[0]), after[0])
	if err != nil {
		return err
	}
	afterBody, exists := f.Attrs["BODY[]"]
	return Check(exists && !afterBody.IsNil && !afterBody.IsList && afterBody.Text == body.Text && extHasFlag(f.Attrs["FLAGS"], "\\Deleted"), "UNSELECT did not preserve message content and \\Deleted")
}

func extSelectedValidity(selected Response) (uint64, error) {
	code := selected.Code("UIDVALIDITY")
	if err := Check(len(code) == 1, "SELECT omitted UIDVALIDITY"); err != nil {
		return 0, err
	}
	validity, err := code[0].Uint()
	if err != nil {
		return 0, err
	}
	return validity, Check(validity > 0, "UIDVALIDITY must be nonzero")
}

func extCheckReselectedUID(beforeUID, afterUID, beforeValidity, afterValidity uint64) error {
	if beforeValidity == afterValidity {
		return Check(beforeUID == afterUID, "UID changed from %d to %d without a UIDVALIDITY change (%d)", beforeUID, afterUID, beforeValidity)
	}
	// RFC 3501 section 2.3.1.1 permits regenerated UIDs when UIDVALIDITY
	// increases. RFC 4315's UIDNOTSTICKY stores can exercise this on reselect.
	return Check(beforeUID == afterUID || afterValidity > beforeValidity, "UID changed while UIDVALIDITY decreased from %d to %d", beforeValidity, afterValidity)
}

func extBinary(s *Session) error {
	box, err := s.NewMailbox("message")
	if err != nil {
		return err
	}
	decoded := []byte{'b', 'i', 'n', 'a', 'r', 'y', 0, '\r', '\n', 0xff, '!'}
	message := []byte("From: sender@example.test\r\nTo: reader@example.test\r\n" +
		"Subject: Binary fixture\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(decoded) + "\r\n")
	if _, err := s.Client.Append(box, nil, "", message); err != nil {
		return err
	}
	uids, _, err := extSelectedUIDs(s.Client, box)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "want one binary message, got %v", uids); err != nil {
		return err
	}
	f, err := extOneFetch(s.Client, fmt.Sprintf("UID FETCH %d (UID FLAGS BINARY.PEEK[1] BINARY.SIZE[1])", uids[0]), uids[0])
	if err != nil {
		return err
	}
	body, exists := f.Attrs["BINARY[1]"]
	if err := Check(exists && body.Text == string(decoded), "BINARY[1] did not return the decoded MIME octets"); err != nil {
		return err
	}
	size, exists := f.Attrs["BINARY.SIZE[1]"]
	if err := Check(exists, "BINARY.SIZE[1] was omitted"); err != nil {
		return err
	}
	n, err := size.Uint()
	if err != nil {
		return err
	}
	if err := Check(n == uint64(len(decoded)), "BINARY.SIZE[1]=%d, decoded length=%d", n, len(decoded)); err != nil {
		return err
	}
	flags, exists := f.Attrs["FLAGS"]
	if err := Check(exists && flags.IsList, "FETCH omitted requested FLAGS"); err != nil {
		return err
	}
	return Check(!extHasFlag(flags, "\\Seen"), "BINARY.PEEK unexpectedly set \\Seen")
}

func extSessions(s *Session) error {
	box, err := s.NewMailbox("messages")
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("SELECT " + Quote(box)); err != nil {
		return err
	}
	other, err := s.NewClient()
	if err != nil {
		return err
	}
	if _, err := other.OK("SELECT " + Quote(box)); err != nil {
		return err
	}
	message := extMessage("visible from another session")
	if _, err := s.Client.Append(box, nil, "", message); err != nil {
		return err
	}
	r, err := other.OK("NOOP")
	if err != nil {
		return err
	}
	count, exists := r.Exists()
	if err := Check(exists && count == 1, "NOOP in the other selected session did not report EXISTS 1"); err != nil {
		return err
	}
	search, err := other.OK("UID SEARCH ALL")
	if err != nil {
		return err
	}
	uids, err := search.Search()
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 1, "other session sees %d messages, want 1", len(uids)); err != nil {
		return err
	}
	f, err := extOneFetch(other, fmt.Sprintf("UID FETCH %d (UID BODY.PEEK[])", uids[0]), uids[0])
	if err != nil {
		return err
	}
	body, exists := f.Attrs["BODY[]"]
	return Check(exists && body.Text == string(message), "other session fetched different APPEND content")
}

func extPipeline(s *Session) error {
	empty, err := s.NewMailbox("empty")
	if err != nil {
		return err
	}
	full, err := s.NewMailbox("full")
	if err != nil {
		return err
	}
	if _, err := s.Client.Append(full, nil, "", extMessage("pipeline")); err != nil {
		return err
	}
	results, err := s.Client.Pipeline("STATUS "+Quote(empty)+" (MESSAGES)", "STATUS "+Quote(full)+" (MESSAGES)", "NOOP")
	if err != nil {
		return err
	}
	if err := Check(len(results) == 3, "pipeline returned %d completions, want 3", len(results)); err != nil {
		return err
	}
	for i, r := range results {
		if err := Check(strings.EqualFold(r.Status, "OK"), "pipeline command %d returned %s", i+1, r.Status); err != nil {
			return err
		}
	}
	if err := Check(results[0].Tag != results[1].Tag && results[0].Tag != results[2].Tag && results[1].Tag != results[2].Tag, "pipeline reused command tags"); err != nil {
		return err
	}
	// Unsolicited data has no unique association with a pipelined command.
	// Pipeline exposes the complete group's untagged replies on each result.
	for name, want := range map[string]uint64{empty: 0, full: 1} {
		values, err := results[0].StatusValues(name)
		if err != nil {
			return err
		}
		got, exists := values["MESSAGES"]
		if err := Check(exists && got == want, "pipelined STATUS %q has MESSAGES %d (present=%v), want %d", name, got, exists, want); err != nil {
			return err
		}
	}
	return nil
}

func extHasFlag(v Value, flag string) bool {
	for _, item := range v.List {
		if strings.EqualFold(item.Text, flag) {
			return true
		}
	}
	return false
}

// extUIDSet is deliberately bounded: the initial scenarios exchange tiny sets,
// and a malformed peer must not make an assertion allocate billions of UIDs.
func extUIDSet(text string) ([]uint64, error) {
	const limit = 4096
	var values []uint64
	for _, part := range strings.Split(text, ",") {
		bounds := strings.Split(part, ":")
		if len(bounds) < 1 || len(bounds) > 2 {
			return nil, Check(false, "invalid UID set %q", text)
		}
		first, err := strconv.ParseUint(bounds[0], 10, 32)
		if err != nil || first == 0 {
			return nil, Check(false, "invalid UID set %q", text)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(bounds[1], 10, 32)
			if err != nil || last == 0 {
				return nil, Check(false, "invalid UID set %q", text)
			}
		}
		low, high := min(first, last), max(first, last)
		if high-low+1 > limit || uint64(len(values))+high-low+1 > limit {
			return nil, Check(false, "UID set exceeds this scenario's %d-message bound", limit)
		}
		for n := low; n <= high; n++ {
			values = append(values, n)
		}
	}
	slices.Sort(values)
	return slices.Compact(values), nil
}
