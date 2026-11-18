package imaptest

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

const coreRFC = "https://www.rfc-editor.org/rfc/rfc3501.html#section-"

// These scenarios use imaptest's command families as a coverage reference. The
// messages and assertions are native to this runner, and compare protocol
// semantics rather than one server's response text, UID allocation, or ordering.
func coreCases() []Case {
	return []Case{
		{Name: "core/capability-noop", Description: "CAPABILITY identifies IMAP4rev1 and NOOP succeeds", RFC: coreRFC + "6.1.1", Run: coreCapability},
		{Name: "core/unknown-command", Description: "An unrecognized command receives BAD", RFC: coreRFC + "7.1.3", Run: coreUnknownCommand},
		{Name: "mailbox/lifecycle", Description: "Create, list, rename and delete a private mailbox", RFC: coreRFC + "6.3.3", Run: coreMailboxLifecycle},
		{Name: "mailbox/subscriptions", Description: "SUBSCRIBE and UNSUBSCRIBE control LSUB membership", RFC: coreRFC + "6.3.6", Run: coreSubscriptions},
		{Name: "mailbox/select-status", Description: "SELECT and STATUS agree on message counts and UID metadata", RFC: coreRFC + "6.3.1", Run: coreSelectStatus},
		{Name: "mailbox/examine-readonly", Description: "CLOSE after EXAMINE does not expunge deleted messages", RFC: coreRFC + "6.3.2", Run: coreExamineReadonly},
		{Name: "append/roundtrip", Description: "APPEND preserves valid message octets and RFC822.SIZE", RFC: coreRFC + "6.3.11", Run: coreAppendRoundtrip},
		{Name: "fetch/partial", Description: "Partial body fetches use octet offsets and handle end of message", RFC: coreRFC + "6.4.5", Run: coreFetchPartial},
		{Name: "fetch/peek-seen", Description: "BODY.PEEK preserves Seen while BODY sets it", RFC: coreRFC + "6.4.5", Run: corePeekSeen},
		{Name: "fetch/header-fields", Description: "Header field inclusion and exclusion preserve the header terminator", RFC: coreRFC + "6.4.5", Run: coreHeaderFields},
		{Name: "fetch/mime-sections", Description: "MIME part and MIME header fetches identify the requested section", RFC: coreRFC + "6.4.5", Run: coreMIMESections},
		{Name: "fetch/envelope-bodystructure", Description: "ENVELOPE and BODYSTRUCTURE describe a simple text message", RFC: coreRFC + "7.4.2", Run: coreEnvelopeBodystructure},
		{Name: "fetch/uid-ranges", Description: "UID and sequence ranges retain their specified semantics", RFC: coreRFC + "6.4.8", Run: coreUIDRanges},
		{Name: "store/system-flags", Description: "STORE adds, removes and replaces system flags", RFC: coreRFC + "6.4.6", Run: coreStoreFlags},
		{Name: "store/keywords", Description: "Permanent user keywords round-trip when advertised", RFC: coreRFC + "7.1.1", Run: coreStoreKeywords},
		{Name: "copy/messages", Description: "COPY preserves message content and leaves the source intact", RFC: coreRFC + "6.4.7", Run: coreCopy},
		{Name: "expunge/sequence-remapping", Description: "EXPUNGE removes only deleted messages and remaps sequence numbers", RFC: coreRFC + "7.4.1", Run: coreExpunge},
		{Name: "close/expunge", Description: "CLOSE expunges deleted messages without EXPUNGE responses", RFC: coreRFC + "6.4.2", Run: coreClose},
		{Name: "search/flags", Description: "SEARCH applies flags, NOT, OR and sequence criteria", RFC: coreRFC + "6.4.4", Run: coreSearchFlags},
		{Name: "search/header-substring", Description: "Subject and address searches match substrings without case sensitivity", RFC: coreRFC + "6.4.4", Run: coreSearchHeaders},
		{Name: "search/arbitrary-header", Description: "Sora returns no matches for non-indexed HEADER fields", RFC: coreRFC + "6.4.4", Run: coreSearchArbitraryHeader},
		{Name: "search/body-substring", Description: "Sora whole-word body indexing does not match interior substrings", RFC: coreRFC + "6.4.4", Run: coreSearchBody},
		{Name: "search/sent-date", Description: "Sent-date searches use the Date header's calendar date", RFC: coreRFC + "6.4.4", Run: coreSearchDate},
		{Name: "search/size", Description: "LARGER and SMALLER use strict RFC822.SIZE comparisons", RFC: coreRFC + "6.4.4", Run: coreSearchSize},
		{Name: "core/logout", Description: "LOGOUT sends BYE and a tagged OK completion", RFC: coreRFC + "6.1.3", Run: coreLogout},
	}
}

func coreMessage(subject, body string) []byte {
	return []byte("Date: Tue, 12 May 2026 09:30:00 +0000\r\n" +
		"From: Sender Person <sender@example.test>\r\n" +
		"To: Receiver Person <receiver@example.test>\r\n" +
		"Message-ID: <sora-imaptest@example.test>\r\n" +
		"Subject: " + subject + "\r\n" +
		"X-Sora-Conformance: headerneedle-middle-end\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=us-ascii\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n\r\n" + body + "\r\n")
}

func coreAppend(c *Client, box string, messages ...[]byte) error {
	for _, msg := range messages {
		if _, err := c.Append(box, nil, "", msg); err != nil {
			return err
		}
	}
	return nil
}

func coreSelect(c *Client, box string) (Response, error) {
	return c.OK("SELECT " + Quote(box))
}

func coreFetch(c *Client, command string) ([]Fetch, error) {
	r, err := c.OK(command)
	if err != nil {
		return nil, err
	}
	replies, err := r.Fetches()
	if err != nil {
		return nil, err
	}
	// A server may split requested items across replies or send an unsolicited
	// FLAGS update next to them. Merge by sequence number before asserting data.
	var merged []Fetch
	indexes := make(map[uint64]int)
	for _, f := range replies {
		index, ok := indexes[f.Seq]
		if !ok {
			index = len(merged)
			indexes[f.Seq] = index
			merged = append(merged, Fetch{Seq: f.Seq, Attrs: make(map[string]Value)})
		}
		for name, value := range f.Attrs {
			merged[index].Attrs[name] = value
		}
	}
	return merged, nil
}

func coreSingleFetch(c *Client, command string) (Fetch, error) {
	f, err := coreFetch(c, command)
	if err != nil {
		return Fetch{}, err
	}
	fields := strings.Fields(command)
	if len(fields) >= 2 && strings.EqualFold(fields[0], "FETCH") {
		seq, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			for _, item := range f {
				if item.Seq == seq {
					return item, nil
				}
			}
			return Fetch{}, Check(false, "%s: FETCH omitted sequence %d", command, seq)
		}
	}
	return Fetch{}, fmt.Errorf("coreSingleFetch requires a single numeric sequence: %s", command)
}

func coreAttribute(f Fetch, name string) (Value, error) {
	v, ok := f.Attrs[canonicalFetchAttribute(name)]
	if err := Check(ok, "FETCH for sequence %d omitted %s", f.Seq, name); err != nil {
		return Value{}, err
	}
	return v, nil
}

func coreHasFlag(flags Value, name string) bool {
	for _, flag := range flags.List {
		if strings.EqualFold(flag.Text, name) {
			return true
		}
	}
	return false
}

func coreSearch(c *Client, criteria string, want ...uint64) error {
	r, err := c.OK("SEARCH " + criteria)
	if err != nil {
		return err
	}
	got, err := r.Search()
	if err != nil {
		return err
	}
	slices.Sort(got)
	want = slices.Clone(want)
	slices.Sort(want)
	return Check(slices.Equal(got, want), "SEARCH %s: got %v, want %v", criteria, got, want)
}

func coreUIDs(c *Client) ([]uint64, error) {
	f, err := coreFetch(c, "FETCH 1:* UID")
	if err != nil {
		return nil, err
	}
	f = slices.DeleteFunc(f, func(item Fetch) bool {
		_, hasUID := item.Attrs["UID"]
		return !hasUID // an unrelated FLAGS update is not a requested UID reply
	})
	slices.SortFunc(f, func(a, b Fetch) int {
		if a.Seq < b.Seq {
			return -1
		}
		if a.Seq > b.Seq {
			return 1
		}
		return 0
	})
	uids := make([]uint64, 0, len(f))
	var previous uint64
	for i, item := range f {
		v, err := coreAttribute(item, "UID")
		if err != nil {
			return nil, err
		}
		uid, err := v.Uint()
		if err != nil {
			return nil, err
		}
		if err := Check(item.Seq == uint64(i+1) && uid > previous, "UID ordering: sequence=%d UID=%d after UID=%d", item.Seq, uid, previous); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
		previous = uid
	}
	return uids, nil
}

func coreFresh(s *Session, messages ...[]byte) (string, error) {
	box, err := s.NewMailbox("messages")
	if err != nil {
		return "", err
	}
	if err := coreAppend(s.Client, box, messages...); err != nil {
		return "", err
	}
	_, err = coreSelect(s.Client, box)
	return box, err
}

func coreCapability(s *Session) error {
	r, err := s.Client.OK("CAPABILITY")
	if err != nil {
		return err
	}
	found := false
	for _, reply := range r.Data("CAPABILITY") {
		for _, v := range reply.Values[1:] {
			found = found || strings.EqualFold(v.Text, "IMAP4rev1")
		}
	}
	if err := Check(found, "CAPABILITY omitted IMAP4rev1 in the rev1 test profile"); err != nil {
		return err
	}
	_, err = s.Client.OK("NOOP")
	return err
}

func coreUnknownCommand(s *Session) error {
	r, err := s.Client.Command("SORAIMAPTESTUNKNOWN")
	if err != nil {
		return err
	}
	return Check(strings.EqualFold(r.Status, "BAD"), "unrecognized command returned %s, want BAD", r.Status)
}

func coreMailboxLifecycle(s *Session) error {
	box, err := s.NewMailbox("before")
	if err != nil {
		return err
	}
	r, err := s.Client.OK("LIST \"\" " + Quote(box))
	if err != nil {
		return err
	}
	if err := Check(coreListed(r, "LIST", box), "LIST omitted newly created mailbox %q", box); err != nil {
		return err
	}
	renamed := s.Name("after")
	if err := s.RenameMailbox(s.Client, box, renamed); err != nil {
		return err
	}
	if _, err := coreSelect(s.Client, renamed); err != nil {
		return err
	}
	if _, err := s.Client.OK("CLOSE"); err != nil {
		return err
	}
	if err := s.DeleteMailbox(s.Client, renamed); err != nil {
		return err
	}
	r, err = s.Client.OK("LIST \"\" " + Quote(renamed))
	if err != nil {
		return err
	}
	if err := Check(!coreListed(r, "LIST", renamed), "LIST still returned deleted mailbox %q", renamed); err != nil {
		return err
	}
	r, err = s.Client.Command("SELECT " + Quote(renamed))
	if err != nil {
		return err
	}
	return Check(strings.EqualFold(r.Status, "NO"), "SELECT deleted mailbox returned %s, want NO", r.Status)
}

func coreListed(r Response, kind, box string) bool {
	for _, reply := range r.Data(kind) {
		if len(reply.Values) >= 4 && reply.Values[3].Text == box {
			return true
		}
	}
	return false
}

func coreSubscriptions(s *Session) error {
	box, err := s.NewMailbox("subscription")
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("SUBSCRIBE " + Quote(box)); err != nil {
		return err
	}
	r, err := s.Client.OK("LSUB \"\" " + Quote(box))
	if err != nil {
		return err
	}
	if err := Check(coreListed(r, "LSUB", box), "LSUB omitted subscribed mailbox %q", box); err != nil {
		return err
	}
	if _, err := s.Client.OK("UNSUBSCRIBE " + Quote(box)); err != nil {
		return err
	}
	r, err = s.Client.OK("LSUB \"\" " + Quote(box))
	if err != nil {
		return err
	}
	return Check(!coreListed(r, "LSUB", box), "LSUB returned unsubscribed mailbox %q", box)
}

func coreSelectStatus(s *Session) error {
	box, err := coreFresh(s, coreMessage("first", "first body"), coreMessage("second", "second body"))
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1 +FLAGS.SILENT (\\Seen)"); err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 2, "FETCH returned %d UIDs, want 2", len(uids)); err != nil {
		return err
	}
	selected, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	count, ok := selected.Exists()
	if err := Check(ok && count == 2, "SELECT EXISTS=%d (present=%t), want 2", count, ok); err != nil {
		return err
	}
	r, err := s.Client.OK("STATUS " + Quote(box) + " (MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
	if err != nil {
		return err
	}
	status, err := r.StatusValues(box)
	if err != nil {
		return err
	}
	if err := Check(status["MESSAGES"] == 2 && status["UNSEEN"] == 1, "STATUS counts=%v, want MESSAGES=2 UNSEEN=1", status); err != nil {
		return err
	}
	for _, name := range []string{"UIDVALIDITY", "UIDNEXT"} {
		code := selected.Code(name)
		if err := Check(len(code) == 1, "SELECT omitted a single %s response code", name); err != nil {
			return err
		}
		value, err := code[0].Uint()
		if err != nil {
			return err
		}
		if err := Check(value > 0 && value == status[name], "SELECT %s=%d differs from STATUS %d", name, value, status[name]); err != nil {
			return err
		}
	}
	return Check(status["UIDNEXT"] > uids[1], "UIDNEXT=%d must exceed last assigned UID=%d", status["UIDNEXT"], uids[1])
}

func coreExamineReadonly(s *Session) error {
	box, err := coreFresh(s, coreMessage("readonly", "keep this message"))
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1 +FLAGS.SILENT (\\Deleted)"); err != nil {
		return err
	}
	r, err := s.Client.OK("EXAMINE " + Quote(box))
	if err != nil {
		return err
	}
	if err := Check(r.Code("READ-ONLY") != nil, "EXAMINE omitted READ-ONLY response code"); err != nil {
		return err
	}
	if _, err := s.Client.OK("CLOSE"); err != nil {
		return err
	}
	r, err = coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	n, ok := r.Exists()
	return Check(ok && n == 1, "CLOSE after EXAMINE removed a deleted message: EXISTS=%d", n)
}

func coreAppendRoundtrip(s *Session) error {
	msg := coreMessage("literal roundtrip", "First line.\r\nSecond line with parentheses () and a quoted \"word\".")
	if _, err := coreFresh(s, msg); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 (UID RFC822.SIZE BODY.PEEK[])")
	if err != nil {
		return err
	}
	body, err := coreAttribute(f, "BODY[]")
	if err != nil {
		return err
	}
	if err := Check(bytes.Equal([]byte(body.Text), msg), "APPEND/FETCH body changed message octets: got %d bytes, want %d", len(body.Text), len(msg)); err != nil {
		return err
	}
	v, err := coreAttribute(f, "RFC822.SIZE")
	if err != nil {
		return err
	}
	size, err := v.Uint()
	if err != nil {
		return err
	}
	return Check(size == uint64(len(msg)), "RFC822.SIZE=%d, want %d", size, len(msg))
}

func coreFetchPartial(s *Session) error {
	msg := coreMessage("partial", "0123456789abcdef")
	if _, err := coreFresh(s, msg); err != nil {
		return err
	}
	for _, test := range []struct{ offset, count int }{{0, 12}, {13, 17}, {len(msg) - 3, 20}, {len(msg) + 10, 5}} {
		command := fmt.Sprintf("FETCH 1 BODY.PEEK[]<%d.%d>", test.offset, test.count)
		f, err := coreSingleFetch(s.Client, command)
		if err != nil {
			return err
		}
		v, err := coreAttribute(f, fmt.Sprintf("BODY[]<%d>", test.offset))
		if err != nil {
			return err
		}
		start := min(test.offset, len(msg))
		end := min(start+test.count, len(msg))
		if err := Check(v.Text == string(msg[start:end]), "partial FETCH offset=%d count=%d returned %q, want %q", test.offset, test.count, v.Text, msg[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func corePeekSeen(s *Session) error {
	message := coreMessage("peek", "reading has side effects")
	if _, err := coreFresh(s, message); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1 -FLAGS.SILENT (\\Seen)"); err != nil {
		return err
	}
	peek, err := coreSingleFetch(s.Client, "FETCH 1 BODY.PEEK[]")
	if err != nil {
		return err
	}
	if err := coreCheckBody(peek, message); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 FLAGS")
	if err != nil {
		return err
	}
	if err := Check(!coreHasFlag(f.Attrs["FLAGS"], "\\Seen"), "BODY.PEEK[] set \\Seen"); err != nil {
		return err
	}
	fetched, err := coreSingleFetch(s.Client, "FETCH 1 BODY[]")
	if err != nil {
		return err
	}
	if err := coreCheckBody(fetched, message); err != nil {
		return err
	}
	f, err = coreSingleFetch(s.Client, "FETCH 1 FLAGS")
	if err != nil {
		return err
	}
	return Check(coreHasFlag(f.Attrs["FLAGS"], "\\Seen"), "BODY[] did not set \\Seen")
}

func coreCheckBody(f Fetch, message []byte) error {
	body, err := coreAttribute(f, "BODY[]")
	if err != nil {
		return err
	}
	return Check(body.Text == string(message), "FETCH BODY[] changed message octets: got %d bytes, want %d", len(body.Text), len(message))
}

func coreHeaderFields(s *Session) error {
	if _, err := coreFresh(s, coreMessage("selected header", "unrelated body")); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 BODY.PEEK[HEADER.FIELDS (SUBJECT)]")
	if err != nil {
		return err
	}
	v, err := coreAttribute(f, "BODY[HEADER.FIELDS (SUBJECT)]")
	if err != nil {
		return err
	}
	if err := Check(strings.EqualFold(v.Text, "Subject: selected header\r\n\r\n"), "HEADER.FIELDS returned %q", v.Text); err != nil {
		return err
	}
	f, err = coreSingleFetch(s.Client, "FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (SUBJECT)]")
	if err != nil {
		return err
	}
	v, err = coreAttribute(f, "BODY[HEADER.FIELDS.NOT (SUBJECT)]")
	if err != nil {
		return err
	}
	header := strings.ToLower(v.Text)
	return Check(!strings.Contains("\r\n"+header, "\r\nsubject:") && strings.Contains(header, "from:") && strings.HasSuffix(header, "\r\n\r\n"), "HEADER.FIELDS.NOT did not exclude Subject and retain the header terminator")
}

func coreMIMESections(s *Session) error {
	msg := []byte("Date: Tue, 12 May 2026 09:30:00 +0000\r\nFrom: sender@example.test\r\nTo: receiver@example.test\r\nSubject: MIME sections\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=imaptest-boundary\r\n\r\n" +
		"--imaptest-boundary\r\nContent-Type: text/plain\r\n\r\nfirst body line\r\n" +
		"--imaptest-boundary\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAw==\r\n" +
		"--imaptest-boundary--\r\n")
	if _, err := coreFresh(s, msg); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 (BODY.PEEK[1] BODY.PEEK[2] BODY.PEEK[2.MIME])")
	if err != nil {
		return err
	}
	first, err := coreAttribute(f, "BODY[1]")
	if err != nil {
		return err
	}
	second, err := coreAttribute(f, "BODY[2]")
	if err != nil {
		return err
	}
	mime, err := coreAttribute(f, "BODY[2.MIME]")
	if err != nil {
		return err
	}
	if err := Check(strings.TrimRight(first.Text, "\r\n") == "first body line" && strings.TrimSpace(second.Text) == "AAECAw==", "BODY part fetch returned the wrong text or decoded the transfer encoding"); err != nil {
		return err
	}
	header := strings.ToLower(mime.Text)
	return Check(strings.Contains(header, "content-type: application/octet-stream") && strings.Contains(header, "content-transfer-encoding: base64") && strings.HasSuffix(header, "\r\n\r\n"), "BODY[2.MIME] omitted the second part's MIME headers")
}

func coreEnvelopeBodystructure(s *Session) error {
	if _, err := coreFresh(s, coreMessage("envelope subject", "short plain text")); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 (ENVELOPE BODYSTRUCTURE)")
	if err != nil {
		return err
	}
	env, err := coreAttribute(f, "ENVELOPE")
	if err != nil {
		return err
	}
	if err := Check(env.IsList && len(env.List) == 10, "ENVELOPE contains %d values, want 10", len(env.List)); err != nil {
		return err
	}
	if err := Check(env.List[1].Text == "envelope subject", "ENVELOPE subject=%q", env.List[1].Text); err != nil {
		return err
	}
	for _, field := range []struct {
		index   int
		mailbox string
	}{{2, "sender"}, {5, "receiver"}} {
		addresses := env.List[field.index].List
		if err := Check(len(addresses) == 1 && len(addresses[0].List) == 4, "ENVELOPE address field %d has invalid shape", field.index); err != nil {
			return err
		}
		address := addresses[0].List
		if err := Check(address[2].Text == field.mailbox && address[3].Text == "example.test", "ENVELOPE address field %d has wrong mailbox or domain", field.index); err != nil {
			return err
		}
	}
	body, err := coreAttribute(f, "BODYSTRUCTURE")
	if err != nil {
		return err
	}
	return Check(body.IsList && len(body.List) >= 8 && strings.EqualFold(body.List[0].Text, "TEXT") && strings.EqualFold(body.List[1].Text, "PLAIN"), "BODYSTRUCTURE does not describe text/plain")
}

func coreUIDRanges(s *Session) error {
	box, err := coreFresh(s, coreMessage("one", "one"), coreMessage("two", "two"), coreMessage("three", "three"))
	if err != nil {
		return err
	}
	initial, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	initialValidity, err := coreUIDValidity(initial)
	if err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 3, "got %d UIDs, want 3", len(uids)); err != nil {
		return err
	}
	for _, seqset := range []string{"1:3", "3:1", "*:1"} {
		f, err := coreFetch(s.Client, "FETCH "+seqset+" UID")
		if err != nil {
			return err
		}
		if err := Check(len(f) == 3, "FETCH %s returned %d messages, want 3", seqset, len(f)); err != nil {
			return err
		}
		for _, item := range f {
			v, err := coreAttribute(item, "UID")
			if err != nil {
				return err
			}
			uid, err := v.Uint()
			if err != nil {
				return err
			}
			if err := Check(item.Seq > 0 && item.Seq <= 3 && uid == uids[item.Seq-1], "FETCH %s returned wrong UID/sequence mapping: seq=%d UID=%d", seqset, item.Seq, uid); err != nil {
				return err
			}
		}
	}
	r, err := s.Client.OK("STATUS " + Quote(box) + " (UIDNEXT)")
	if err != nil {
		return err
	}
	status, err := r.StatusValues(box)
	if err != nil {
		return err
	}
	if err := Check(status["UIDNEXT"] > uids[2], "UIDNEXT=%d must exceed assigned UID=%d", status["UIDNEXT"], uids[2]); err != nil {
		return err
	}
	// UIDNEXT is a lower bound, not a promised next assignment. A range with
	// '*' includes the last existing message even when UIDNEXT is greater.
	f, err := coreFetch(s.Client, fmt.Sprintf("UID FETCH %d:* UID", status["UIDNEXT"]))
	if err != nil {
		return err
	}
	f = slices.DeleteFunc(f, func(item Fetch) bool {
		_, hasUID := item.Attrs["UID"]
		return !hasUID
	})
	if err := Check(len(f) == 1 && f[0].Seq == 3, "UID FETCH UIDNEXT:* did not include exactly the last message"); err != nil {
		return err
	}
	lastUID, err := f[0].Attrs["UID"].Uint()
	if err != nil {
		return err
	}
	if err := Check(lastUID == uids[2], "UID FETCH UIDNEXT:* returned UID=%d, want last UID=%d", lastUID, uids[2]); err != nil {
		return err
	}
	reselected, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	reselectedValidity, err := coreUIDValidity(reselected)
	if err != nil {
		return err
	}
	again, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	return coreCheckUIDPersistence(initialValidity, reselectedValidity, uids, again)
}

func coreUIDValidity(r Response) (uint64, error) {
	code := r.Code("UIDVALIDITY")
	if err := Check(len(code) == 1, "SELECT omitted a single UIDVALIDITY response code"); err != nil {
		return 0, err
	}
	validity, err := code[0].Uint()
	if err != nil {
		return 0, err
	}
	return validity, Check(validity > 0, "UIDVALIDITY must be nonzero")
}

func coreCheckUIDPersistence(beforeValidity, afterValidity uint64, before, after []uint64) error {
	// RFC 3501 permits nonpersistent UIDs, but their UIDVALIDITY must increase
	// when prior identifiers cease to persist. UIDNOTSTICKY is one example.
	return Check(slices.Equal(before, after) || afterValidity > beforeValidity,
		"UIDs changed across reselect without an increased UIDVALIDITY: before=%v (UIDVALIDITY=%d) after=%v (UIDVALIDITY=%d)",
		before, beforeValidity, after, afterValidity)
}

func coreStoreFlags(s *Session) error {
	if _, err := coreFresh(s, coreMessage("flags", "flag target")); err != nil {
		return err
	}
	for _, step := range []struct {
		command         string
		present, absent []string
	}{
		{"STORE 1 +FLAGS.SILENT (\\Seen \\Flagged)", []string{"\\Seen", "\\Flagged"}, nil},
		{"STORE 1 -FLAGS.SILENT (\\Seen)", []string{"\\Flagged"}, []string{"\\Seen"}},
		{"STORE 1 FLAGS.SILENT (\\Answered \\Draft)", []string{"\\Answered", "\\Draft"}, []string{"\\Seen", "\\Flagged"}},
	} {
		if _, err := s.Client.OK(step.command); err != nil {
			return err
		}
		f, err := coreSingleFetch(s.Client, "FETCH 1 FLAGS")
		if err != nil {
			return err
		}
		flags, err := coreAttribute(f, "FLAGS")
		if err != nil {
			return err
		}
		for _, name := range step.present {
			if err := Check(coreHasFlag(flags, name), "%s: FLAGS omitted %s", step.command, name); err != nil {
				return err
			}
		}
		for _, name := range step.absent {
			if err := Check(!coreHasFlag(flags, name), "%s: FLAGS retained %s", step.command, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func coreStoreKeywords(s *Session) error {
	box, err := coreFresh(s, coreMessage("keywords", "keyword target"))
	if err != nil {
		return err
	}
	selected, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	flags := selected.Code("PERMANENTFLAGS")
	if len(flags) != 1 || !coreHasFlag(flags[0], "\\*") {
		return Skip("PERMANENTFLAGS does not permit creating permanent keywords")
	}
	if _, err := s.Client.OK("STORE 1 +FLAGS.SILENT (SoraConformance)"); err != nil {
		return err
	}
	if _, err := coreSelect(s.Client, box); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 FLAGS")
	if err != nil {
		return err
	}
	if err := Check(coreHasFlag(f.Attrs["FLAGS"], "SoraConformance"), "permanent keyword was not retained across reselect"); err != nil {
		return err
	}
	if err := coreSearch(s.Client, "KEYWORD soraconformance", 1); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1 -FLAGS.SILENT (soraconformance)"); err != nil {
		return err
	}
	return coreSearch(s.Client, "UNKEYWORD SoraConformance", 1)
}

func coreCopy(s *Session) error {
	messages := [][]byte{coreMessage("copy first", "first copy"), coreMessage("copy second", "second copy")}
	source, err := coreFresh(s, messages...)
	if err != nil {
		return err
	}
	dest, err := s.NewMailbox("destination")
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("COPY 1:2 " + Quote(dest)); err != nil {
		return err
	}
	if _, err := coreSelect(s.Client, dest); err != nil {
		return err
	}
	fetched, err := coreFetch(s.Client, "FETCH 1:* BODY.PEEK[]")
	if err != nil {
		return err
	}
	var bodies []string
	for _, f := range fetched {
		if body, ok := f.Attrs["BODY[]"]; ok {
			bodies = append(bodies, body.Text)
		}
	}
	want := []string{string(messages[0]), string(messages[1])}
	slices.Sort(bodies)
	slices.Sort(want)
	if err := Check(slices.Equal(bodies, want), "COPY did not preserve both message contents"); err != nil {
		return err
	}
	r, err := coreSelect(s.Client, source)
	if err != nil {
		return err
	}
	count, ok := r.Exists()
	return Check(ok && count == 2, "COPY changed source message count to %d", count)
}

func coreExpunge(s *Session) error {
	if _, err := coreFresh(s, coreMessage("one", "one"), coreMessage("two", "two"), coreMessage("three", "three"), coreMessage("four", "four")); err != nil {
		return err
	}
	uids, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	if err := Check(len(uids) == 4, "got %d messages, want 4", len(uids)); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 2,4 +FLAGS.SILENT (\\Deleted)"); err != nil {
		return err
	}
	r, err := s.Client.OK("EXPUNGE")
	if err != nil {
		return err
	}
	remaining := slices.Clone(uids)
	removed := make([]uint64, 0, 2)
	for _, reply := range r.Data("EXPUNGE") {
		seq, ok := reply.Number()
		if err := Check(ok && seq > 0 && seq <= uint64(len(remaining)), "EXPUNGE sequence %d is outside the current view", seq); err != nil {
			return err
		}
		removed = append(removed, remaining[seq-1])
		remaining = slices.Delete(remaining, int(seq-1), int(seq))
	}
	slices.Sort(removed)
	if err := Check(slices.Equal(removed, []uint64{uids[1], uids[3]}), "EXPUNGE removed UIDs %v, want %v", removed, []uint64{uids[1], uids[3]}); err != nil {
		return err
	}
	got, err := coreUIDs(s.Client)
	if err != nil {
		return err
	}
	return Check(slices.Equal(got, []uint64{uids[0], uids[2]}), "remaining UID/sequence map=%v, want %v", got, []uint64{uids[0], uids[2]})
}

func coreClose(s *Session) error {
	box, err := coreFresh(s, coreMessage("keep", "keep"), coreMessage("remove", "remove"))
	if err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 2 +FLAGS.SILENT (\\Deleted)"); err != nil {
		return err
	}
	r, err := s.Client.OK("CLOSE")
	if err != nil {
		return err
	}
	if err := Check(len(r.Data("EXPUNGE")) == 0, "CLOSE sent EXPUNGE responses"); err != nil {
		return err
	}
	r, err = coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	n, ok := r.Exists()
	return Check(ok && n == 1, "CLOSE did not expunge exactly the deleted message: EXISTS=%d", n)
}

func coreSearchFlags(s *Session) error {
	if _, err := coreFresh(s, coreMessage("one", "one"), coreMessage("two", "two"), coreMessage("three", "three")); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1:3 FLAGS.SILENT ()"); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 1 +FLAGS.SILENT (\\Seen)"); err != nil {
		return err
	}
	if _, err := s.Client.OK("STORE 2 +FLAGS.SILENT (\\Flagged)"); err != nil {
		return err
	}
	for _, test := range []struct {
		criteria string
		want     []uint64
	}{
		{"ALL", []uint64{1, 2, 3}}, {"SEEN", []uint64{1}}, {"UNSEEN", []uint64{2, 3}},
		{"OR SEEN FLAGGED", []uint64{1, 2}}, {"NOT SEEN", []uint64{2, 3}}, {"1:2 UNSEEN", []uint64{2}},
	} {
		if err := coreSearch(s.Client, test.criteria, test.want...); err != nil {
			return err
		}
	}
	return nil
}

func coreSearchHeaders(s *Session) error {
	if _, err := coreFresh(s, coreMessage("prefix-NeedleSuffix-end", "body without the subject word")); err != nil {
		return err
	}
	for _, criteria := range []string{"SUBJECT \"needlesuff\"", "FROM \"NDER@EXAMP\"", "TO \"ceiver@exam\"", "HEADER SUBJECT \"NEEDLESUFF\""} {
		if err := coreSearch(s.Client, criteria, 1); err != nil {
			return err
		}
	}
	return nil
}

func coreSearchArbitraryHeader(s *Session) error {
	if _, err := coreFresh(s, coreMessage("header search", "ordinary body")); err != nil {
		return err
	}
	for _, criteria := range []string{"HEADER X-Sora-Conformance \"\"", "HEADER X-Sora-Conformance \"NEEDLE-MIDD\""} {
		if err := coreSearch(s.Client, criteria); err != nil {
			return err
		}
	}
	if err := coreSearch(s.Client, "NOT HEADER X-Sora-Conformance \"\"", 1); err != nil {
		return err
	}
	return coreSearch(s.Client, "HEADER X-Sora-Absent \"\"")
}

func coreSearchBody(s *Session) error {
	if _, err := coreFresh(s, coreMessage("body search", "prefixbodyneedlesuffix")); err != nil {
		return err
	}
	// Sora deliberately indexes complete body words. Its TEXT header branch
	// still supports substrings, but this term occurs only inside a body word.
	if err := coreSearch(s.Client, "BODY \"BODYNEEDLE\""); err != nil {
		return err
	}
	return coreSearch(s.Client, "TEXT \"bodyneedle\"")
}

func coreSearchDate(s *Session) error {
	msg := coreMessage("date search", "date body")
	other := bytes.Replace(coreMessage("other date", "other body"), []byte("Tue, 12 May 2026"), []byte("Wed, 13 May 2026"), 1)
	if _, err := coreFresh(s, msg, other); err != nil {
		return err
	}
	for _, test := range []struct {
		criteria string
		want     []uint64
	}{
		{"SENTON 12-May-2026", []uint64{1}}, {"SENTBEFORE 13-May-2026", []uint64{1}},
		{"SENTSINCE 13-May-2026", []uint64{2}}, {"SENTON 14-May-2026", nil},
	} {
		if err := coreSearch(s.Client, test.criteria, test.want...); err != nil {
			return err
		}
	}
	return nil
}

func coreSearchSize(s *Session) error {
	msg := coreMessage("size search", "0123456789")
	if _, err := coreFresh(s, msg); err != nil {
		return err
	}
	for _, test := range []struct {
		criterion string
		size      int
		matches   bool
	}{
		{"LARGER", len(msg) - 1, true}, {"LARGER", len(msg), false},
		{"SMALLER", len(msg) + 1, true}, {"SMALLER", len(msg), false},
	} {
		var want []uint64
		if test.matches {
			want = []uint64{1}
		}
		if err := coreSearch(s.Client, test.criterion+" "+strconv.Itoa(test.size), want...); err != nil {
			return err
		}
	}
	return nil
}

func coreLogout(s *Session) error {
	r, err := s.Client.OK("LOGOUT")
	if err != nil {
		return err
	}
	for _, reply := range r.Untagged {
		if strings.EqualFold(reply.Status, "BYE") || reply.Kind() == "BYE" {
			return nil
		}
	}
	return Check(false, "LOGOUT omitted BYE response")
}
