package imap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/metrics"
)

var _ imapserver.SessionThread = (*IMAPSession)(nil)

func (s *IMAPSession) Thread(ctx context.Context, numKind imapserver.NumKind, algorithm imap.ThreadAlgorithm, charset string, criteria *imap.SearchCriteria) ([]imap.ThreadData, error) {
	// RFC 5256 §1: a server offers each threading algorithm as a capability
	// "consisting of "THREAD=" followed by a supported threading algorithm name".
	if err := s.requireCapability(imap.Cap("THREAD="+string(algorithm)), "THREAD "+string(algorithm)); err != nil {
		return nil, err
	}

	// Reject pathologically complex/deep criteria before building a query.
	if err := s.validateSearchCriteria("THREAD", criteria); err != nil {
		return nil, err
	}

	// THREAD shares the SEARCH rate limit; threading a few UIDs by UID is free,
	// threading the mailbox or numbering the result against it is not (see
	// search_rate_limit.go).
	if threadCharged(numKind, criteria) {
		if err := s.chargeSearch(ctx); err != nil {
			return nil, err
		}
	}

	// The client's numbering holds still until the results are numbered (seqViewMu).
	s.seqViewMu.RLock()
	defer s.seqViewMu.RUnlock()

	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(ctx)
	if !acquired {
		return nil, s.internalError("failed to acquire lock for thread")
	}
	if s.selectedMailbox == nil {
		release()
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "No mailbox selected",
		}
	}
	selectedMailboxID := s.selectedMailbox.ID
	selectedMailboxOwnerID := s.selectedMailbox.AccountID
	selectedMailboxName := s.selectedMailbox.Name
	mailboxMessageCount := s.currentNumMessages.Load()
	view := s.seqViewLocked()
	criteria = s.decodeSearchCriteriaLocked(view, criteria)
	release()

	if s.useMasterDB.Load() {
		ctx = context.WithValue(ctx, consts.UseMasterDBKey, true)
	}

	criteria, err := s.withSessionRecent(criteria, selectedMailboxID)
	if err != nil {
		return nil, err
	}

	includeSubject := algorithm == imap.ThreadReferences || algorithm == imap.ThreadOrderedSubject
	// The FTS scope is the mailbox OWNER, which for a shared mailbox is not the session
	// account: messages.account_id always carries the owner (server/imap/copy.go passes
	// destMailbox.AccountID, LMTP and delivery resolve the owner likewise). Passing the
	// session account here would make every shared-mailbox body search return nothing.
	withSeqNums := numKind == imapserver.NumKindSeq
	messages, err := s.server.rdb.GetMessagesForThreadingWithRetry(view.context(ctx), selectedMailboxID, selectedMailboxOwnerID, criteria, includeSubject, withSeqNums, s.server.threadMaxMessages)
	if errors.Is(err, db.ErrThreadTooManyMessages) {
		// RFC 5530 section 3, LIMIT: "The operation ran up against an
		// implementation limit of some kind".
		metrics.IMAPSearchRefused.WithLabelValues("result_cap").Inc()
		s.InfoLog("search refused at the result cap", "command", "THREAD", "cap", s.server.threadMaxMessages, "mailbox", selectedMailboxName, "mailbox_messages", mailboxMessageCount)
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeLimit,
			Text: fmt.Sprintf("THREAD matches more than %d messages, narrow the search", s.server.threadMaxMessages),
		}
	}
	if err != nil {
		s.ErrorLog("failed to fetch messages for threading", "err", err)
		return nil, fmt.Errorf("failed to fetch messages for threading: %w", err)
	}
	if withSeqNums {
		// Thread only the messages the client knows, by its numbers for them.
		messages = encodeResults(view, messages, func(m *db.ThreadMessageResult) *uint32 { return &m.Seq })
	}

	// No messages match the search criteria.
	if len(messages) == 0 {
		return []imap.ThreadData{}, nil
	}

	switch algorithm {
	case imap.ThreadOrderedSubject:
		return s.threadOrderedSubject(numKind, messages), nil
	case imap.ThreadReferences:
		return s.threadReferences(numKind, messages, false), nil
	case imap.ThreadRefs:
		return s.threadReferences(numKind, messages, true), nil
	default:
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeBad,
			Text: "Unsupported threading algorithm",
		}
	}
}

// threadOrderedSubject implements the ORDEREDSUBJECT threading algorithm (RFC 5256 section 2.1)
func (s *IMAPSession) threadOrderedSubject(numKind imapserver.NumKind, messages []db.ThreadMessageResult) []imap.ThreadData {
	// 1. Sort messages by subject, then by sent date, then by mailbox order. UID
	// order is sequence order, and UID is always set; Seq is 0 for UID THREAD.
	// SubjectSort arrives in i;unicode-casemap form, so comparing its octets is
	// that collation (RFC 5256 §7, RFC 5051 §2).
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].SubjectSort != messages[j].SubjectSort {
			return messages[i].SubjectSort < messages[j].SubjectSort
		}
		if !messages[i].SentDate.Equal(messages[j].SentDate) {
			return messages[i].SentDate.Before(messages[j].SentDate)
		}
		return messages[i].UID < messages[j].UID
	})

	// Split the sorted messages into threads of the same base subject.
	var threads [][]uint32
	var currentSubject string
	for _, msg := range messages {
		id := s.getMessageID(numKind, msg)
		if len(threads) == 0 || msg.SubjectSort != currentSubject || msg.SubjectSort == "" {
			threads = append(threads, []uint32{id})
			currentSubject = msg.SubjectSort
		} else {
			threads[len(threads)-1] = append(threads[len(threads)-1], id)
		}
	}

	// RFC 5256 section 3: "The second message of a thread is the child of the
	// first message, and subsequent messages of the thread are siblings of the
	// second message and hence children of the message at the root. Hence,
	// there are no grandchildren in ORDEREDSUBJECT threading." Two messages
	// are a chain, (194 195) in the RFC's example; three or more are the first
	// with the rest as its children, (174 (175)(176)(178)(181)(180)), since a
	// nested group needs at least two members.
	result := make([]imap.ThreadData, 0, len(threads))
	for _, ids := range threads {
		td := imap.ThreadData{Chain: ids}
		if len(ids) > 2 {
			td.Chain = ids[:1]
			for _, id := range ids[1:] {
				td.SubThreads = append(td.SubThreads, imap.ThreadData{Chain: []uint32{id}})
			}
		}
		result = append(result, td)
	}

	// 2. Sort the final threads by the sent date of the first message in the thread
	// We need to map the first ID of each thread back to its sent date
	dateMap := make(map[uint32]db.ThreadMessageResult)
	for _, msg := range messages {
		dateMap[s.getMessageID(numKind, msg)] = msg
	}

	sort.Slice(result, func(i, j int) bool {
		idI := result[i].Chain[0]
		idJ := result[j].Chain[0]
		dateI := dateMap[idI].SentDate
		dateJ := dateMap[idJ].SentDate

		if !dateI.Equal(dateJ) {
			return dateI.Before(dateJ)
		}
		return idI < idJ
	})

	return result
}

type jwzNode struct {
	msg      *db.ThreadMessageResult
	id       uint32 // NumKind (UID or SeqNum)
	children []*jwzNode
	parent   *jwzNode
}

// threadReferences implements the REFERENCES threading algorithm (RFC 5256 section 2.2 / JWZ algorithm)
// or, with refs set, THREAD=REFS (draft-ietf-morg-inthread section 4): the same
// linking, no grouping by subject, and threads ordered by their latest arrival.
func (s *IMAPSession) threadReferences(numKind imapserver.NumKind, messages []db.ThreadMessageResult, refs bool) []imap.ThreadData {
	// 1. Link messages by their references (RFC 5256 section 2.2, step 1).
	idTable := make(map[string]*jwzNode)
	byID := func(id string) *jwzNode {
		node, ok := idTable[id]
		if !ok {
			node = &jwzNode{} // a dummy until a message with this id turns up
			idTable[id] = node
		}
		return node
	}

	// Every message gets a node of its own. A Message-ID names the node of the first
	// message carrying it (messages is in UID order, so sequence order); a message
	// without one, or repeating one an earlier message holds, keeps a node no
	// reference reaches, which is what the RFC's "unique Message ID" amounts to.
	nodes := make([]*jwzNode, len(messages))
	for i := range messages {
		node := &jwzNode{}
		if ids := extractIDs(messages[i].MessageID); len(ids) == 1 {
			if named := byID(ids[0]); named.msg == nil {
				node = named
			}
		}
		node.msg = &messages[i]
		node.id = s.getMessageID(numKind, messages[i])
		nodes[i] = node
	}

	for i, node := range nodes {
		// 1.A: chain the references, each the parent of the next. A link already
		// made stays (a References line may have been cut short), and no link may
		// close a loop.
		var parent *jwzNode
		for _, ref := range messageReferences(&messages[i]) {
			next := byID(ref)
			if parent != nil && next.parent == nil && !isAncestor(next, parent) {
				linkChild(parent, next)
			}
			parent = next
		}

		// 1.B: the last reference is this message's parent, whatever another
		// message's references implied.
		if node.parent != nil {
			unlinkChild(node)
		}
		if parent != nil && !isAncestor(node, parent) {
			linkChild(parent, node)
		}
	}

	// 2. The threads start at the nodes without a parent.
	var rootNodes []*jwzNode
	for _, node := range nodes {
		if node.parent == nil {
			rootNodes = append(rootNodes, node)
		}
	}
	for _, node := range idTable {
		if node.parent == nil && node.msg == nil {
			rootNodes = append(rootNodes, node)
		}
	}

	// 3. Prune dummy nodes: one without children goes, one with children gives way
	// to them, except that a dummy at the top keeps several children together.
	pruned := rootNodes[:0]
	for _, root := range rootNodes {
		pruneDummies(root)
		switch {
		case root.msg != nil || len(root.children) > 1:
			pruned = append(pruned, root)
		case len(root.children) == 1:
			child := root.children[0]
			child.parent = nil
			pruned = append(pruned, child)
		}
	}
	rootNodes = pruned

	// 4. Order the threads: REFERENCES by the sent date of each thread's first
	// message, REFS by the latest INTERNALDATE in each thread, so that the thread
	// that received mail last comes last. A dummy's children are put in sent-date
	// order first, so that step 5 finds its first child.
	if refs {
		sortByLatestArrival(rootNodes)
	} else {
		for _, root := range rootNodes {
			if root.msg == nil {
				sortBySentDate(root.children)
			}
		}
		sortByEarliest(rootNodes)
	}

	// 5. Merge the threads that share a base subject; REFS ignores Subject.
	if !refs {
		rootNodes = mergeBySubject(rootNodes)

		// 6. Merging made new roots: order them again.
		sortByEarliest(rootNodes)
	}

	// 7. Build the ThreadData structure
	var result []imap.ThreadData
	for _, root := range rootNodes {
		if td := buildThreadData(root); td != nil {
			result = append(result, *td)
		}
	}

	return result
}

// mergeBySubject is step 5 of REFERENCES (RFC 5256 section 3): of the threads
// in roots, in their step 4 order, it merges those with the same thread subject
// and returns the threads left.
func mergeBySubject(roots []*jwzNode) []*jwzNode {
	// 5.B: the subject table holds one thread per subject: a dummy if there is
	// one, else a message that is not a reply or forward, else the first reply.
	table := make(map[string]*jwzNode)
	for _, root := range roots {
		subj := getSubject(root)
		if subj == "" {
			continue
		}
		held, ok := table[subj]
		if !ok || held.msg != nil && (root.msg == nil || held.msg.ReplyOrForward && !root.msg.ReplyOrForward) {
			table[subj] = root
		}
	}

	// 5.C: merge every other thread into the one in the table. A dummy thread is
	// in the table whenever there is one, so the current thread is a dummy only
	// when the one in the table is too.
	merged := make([]*jwzNode, 0, len(roots))
	for _, root := range roots {
		subj := getSubject(root)
		held := table[subj]
		if subj == "" || held == root {
			merged = append(merged, root)
			continue
		}
		switch {
		case held.msg == nil && root.msg == nil:
			// "append the current message's children to the children of the
			// message in the subject table ... and then delete the current message"
			for _, child := range root.children {
				linkChild(held, child)
			}
			root.children = nil
		case held.msg == nil, root.msg.ReplyOrForward && !held.msg.ReplyOrForward:
			// "make the current message a child of the message in the subject table"
			linkChild(held, root)
		default:
			// "create a new dummy message and make both the current message and the
			// message in the subject table children of the dummy. Then replace the
			// message in the subject table with the dummy message." The thread in
			// the table comes earlier in roots, so it is already in merged.
			dummy := &jwzNode{}
			merged[slices.Index(merged, held)] = dummy
			linkChild(dummy, held)
			linkChild(dummy, root)
			table[subj] = dummy
		}
	}
	return merged
}

func (s *IMAPSession) getMessageID(numKind imapserver.NumKind, msg db.ThreadMessageResult) uint32 {
	if numKind == imapserver.NumKindUID {
		return uint32(msg.UID)
	}
	return msg.Seq
}

// getSubject returns the thread subject of RFC 5256 REFERENCES step 5.B.i: "the
// base subject from either the current message or its first child if the current
// message is a dummy". Step 4 put a dummy's children in sent-date order, and an
// empty subject is the thread's, not a reason to look further (5.B.ii).
func getSubject(node *jwzNode) string {
	if node.msg == nil && len(node.children) > 0 {
		node = node.children[0]
	}
	if node.msg == nil {
		return ""
	}
	return node.msg.SubjectSort
}

func isAncestor(child, parent *jwzNode) bool {
	curr := parent
	for curr != nil {
		if curr == child {
			return true
		}
		curr = curr.parent
	}
	return false
}

func linkChild(parent, child *jwzNode) {
	child.parent = parent
	parent.children = append(parent.children, child)
}

func unlinkChild(child *jwzNode) {
	child.parent.children = slices.DeleteFunc(child.parent.children, func(n *jwzNode) bool { return n == child })
	child.parent = nil
}

// pruneDummies replaces every dummy below node with that dummy's children (RFC 5256
// section 2.2, step 3), so that afterwards every node below node is a message.
func pruneDummies(node *jwzNode) {
	children := make([]*jwzNode, 0, len(node.children))
	for _, child := range node.children {
		pruneDummies(child)
		if child.msg != nil {
			children = append(children, child)
			continue
		}
		for _, grandchild := range child.children {
			grandchild.parent = node
		}
		children = append(children, child.children...)
	}
	node.children = children
}

// messageReferences returns the ids RFC 5256 threads a message by: those in its
// References, or failing that the first one in its In-Reply-To.
func messageReferences(msg *db.ThreadMessageResult) []string {
	if refs := extractIDs(msg.References); len(refs) > 0 {
		return refs
	}
	if refs := extractIDs(msg.InReplyTo); len(refs) > 0 {
		return refs[:1]
	}
	return nil
}

// extractIDs splits a stored Message-ID, In-Reply-To or References value into
// message ids. The messages table holds them without angle brackets, several joined
// by a space (db.InsertMessage); a synthetic message_id never gets here
// (headerMessageID). A quoted local part stays one id (helpers.SplitMessageIDs), so
// ids from the three columns compare equal.
func extractIDs(s string) []string {
	return helpers.SplitMessageIDs(s)
}

// sortByEarliest orders nodes by the earliest sent date in each subtree, then by
// the lowest message number in it.
func sortByEarliest(nodes []*jwzNode) {
	sort.Slice(nodes, func(i, j int) bool {
		dateI := getEarliestDate(nodes[i])
		dateJ := getEarliestDate(nodes[j])
		if !dateI.Equal(dateJ) {
			return dateI.Before(dateJ)
		}
		return getEarliestID(nodes[i]) < getEarliestID(nodes[j])
	})
}

// sortBySentDate orders message nodes by their own sent date, then by mailbox
// order (RFC 5256 section 2.2).
func sortBySentDate(nodes []*jwzNode) {
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].msg == nil || nodes[j].msg == nil {
			return nodes[i].msg != nil
		}
		if dateI, dateJ := nodes[i].msg.SentDate, nodes[j].msg.SentDate; !dateI.Equal(dateJ) {
			return dateI.Before(dateJ)
		}
		return nodes[i].id < nodes[j].id
	})
}

func getEarliestDate(node *jwzNode) time.Time {
	var earliest time.Time
	if node.msg != nil {
		earliest = node.msg.SentDate
	}

	for _, child := range node.children {
		d := getEarliestDate(child)
		if !d.IsZero() {
			if earliest.IsZero() || d.Before(earliest) {
				earliest = d
			}
		}
	}
	return earliest
}

// sortByLatestArrival orders nodes by the latest INTERNALDATE in each subtree,
// then by the highest message number in it.
func sortByLatestArrival(nodes []*jwzNode) {
	sort.Slice(nodes, func(i, j int) bool {
		dateI, idI := getLatestArrival(nodes[i])
		dateJ, idJ := getLatestArrival(nodes[j])
		if !dateI.Equal(dateJ) {
			return dateI.Before(dateJ)
		}
		return idI < idJ
	})
}

// getLatestArrival returns the latest INTERNALDATE in node's subtree and the
// highest message number in it.
func getLatestArrival(node *jwzNode) (latest time.Time, id uint32) {
	if node.msg != nil {
		latest, id = node.msg.InternalDate, node.id
	}
	for _, child := range node.children {
		childLatest, childID := getLatestArrival(child)
		if childLatest.After(latest) {
			latest = childLatest
		}
		id = max(id, childID)
	}
	return latest, id
}

func getEarliestID(node *jwzNode) uint32 {
	var earliest uint32
	if node.msg != nil {
		earliest = node.id
	}
	for _, child := range node.children {
		id := getEarliestID(child)
		if id != 0 {
			if earliest == 0 || id < earliest {
				earliest = id
			}
		}
	}
	return earliest
}

func buildThreadData(node *jwzNode) *imap.ThreadData {
	td := &imap.ThreadData{}

	// Collect the chain of messages with exactly one child
	curr := node
	for curr != nil {
		if curr.msg != nil {
			td.Chain = append(td.Chain, curr.id)
		}

		if len(curr.children) == 1 {
			curr = curr.children[0]
		} else {
			break
		}
	}

	// Add subthreads if there are multiple branches
	if curr != nil && len(curr.children) > 1 {
		sortByEarliest(curr.children)

		for _, child := range curr.children {
			if sub := buildThreadData(child); sub != nil {
				td.SubThreads = append(td.SubThreads, *sub)
			}
		}
	}

	if len(td.Chain) == 0 && len(td.SubThreads) == 0 {
		return nil
	}

	return td
}
