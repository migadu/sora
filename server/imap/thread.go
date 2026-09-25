package imap

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
)

var _ imapserver.SessionThread = (*IMAPSession)(nil)

func (s *IMAPSession) Thread(ctx context.Context, numKind imapserver.NumKind, algorithm imap.ThreadAlgorithm, charset string, criteria *imap.SearchCriteria) ([]imap.ThreadData, error) {
	// THREAD is a full search; share the per-account SEARCH rate limiter.
	if s.server.searchRateLimiter != nil && s.IMAPUser != nil {
		if err := s.server.searchRateLimiter.CanSearch(ctx, s.IMAPUser.AccountID()); err != nil {
			return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: err.Error()}
		}
	}

	// Reject pathologically complex/deep criteria before building a query.
	if err := s.validateSearchCriteria("THREAD", criteria); err != nil {
		return nil, err
	}

	if s.selectedMailbox == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "No mailbox selected",
		}
	}

	includeSubject := algorithm == imap.ThreadReferences || algorithm == imap.ThreadOrderedSubject
	// The FTS scope is the mailbox OWNER, which for a shared mailbox is not the session
	// account: messages.account_id always carries the owner (server/imap/copy.go passes
	// destMailbox.AccountID, LMTP and delivery resolve the owner likewise). Passing the
	// session account here would make every shared-mailbox body search return nothing.
	messages, err := s.server.rdb.GetMessagesForThreadingWithRetry(ctx, s.selectedMailbox.ID, s.selectedMailbox.AccountID, criteria, includeSubject)
	if err != nil {
		s.ErrorLog("failed to fetch messages for threading", "err", err)
		return nil, fmt.Errorf("failed to fetch messages for threading: %w", err)
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
	// 1. Sort messages by subject, then by sent date, then by sequence number
	sort.Slice(messages, func(i, j int) bool {
		if messages[i].SubjectSort != messages[j].SubjectSort {
			return messages[i].SubjectSort < messages[j].SubjectSort
		}
		if !messages[i].SentDate.Equal(messages[j].SentDate) {
			return messages[i].SentDate.Before(messages[j].SentDate)
		}
		return messages[i].Seq < messages[j].Seq
	})

	var result []imap.ThreadData
	var currentThread *imap.ThreadData
	var currentSubject string

	for _, msg := range messages {
		id := s.getMessageID(numKind, msg)

		if currentThread == nil || msg.SubjectSort != currentSubject || msg.SubjectSort == "" {
			// Start a new thread
			if currentThread != nil {
				result = append(result, *currentThread)
			}
			currentThread = &imap.ThreadData{
				Chain: []uint32{id},
			}
			currentSubject = msg.SubjectSort
		} else {
			// Add to current thread
			currentThread.Chain = append(currentThread.Chain, id)
		}
	}

	if currentThread != nil {
		result = append(result, *currentThread)
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
	// that received mail last comes last.
	if refs {
		sortByLatestArrival(rootNodes)
	} else {
		sortByEarliest(rootNodes)
	}

	// 5. Subject Grouping (RFC 5256 JWZ algorithm phase 5); REFS ignores Subject.
	if !refs {
		subjectTable := make(map[string]*jwzNode)

		for _, root := range rootNodes {
			// Only consider nodes that are still roots (might have been merged in this loop)
			if root.parent != nil {
				continue
			}

			subj := getSubject(root)
			if subj == "" {
				continue
			}

			existing, ok := subjectTable[subj]
			if !ok || existing == root {
				subjectTable[subj] = root
				continue
			}

			// Merge root and existing
			if existing.msg == nil && root.msg == nil {
				// Both are dummies: merge root's children into existing
				for _, child := range root.children {
					child.parent = existing
					existing.children = append(existing.children, child)
				}
				root.children = nil // effectively discarded
			} else if existing.msg == nil || root.msg == nil {
				// One is dummy: make it the parent of the real one
				var dummy, real *jwzNode
				if existing.msg == nil {
					dummy, real = existing, root
				} else {
					dummy, real = root, existing
					subjectTable[subj] = dummy
				}
				real.parent = dummy
				dummy.children = append(dummy.children, real)
			} else {
				// Neither is dummy: create new dummy to parent both
				newDummy := &jwzNode{}
				existing.parent = newDummy
				root.parent = newDummy
				newDummy.children = append(newDummy.children, existing, root)
				subjectTable[subj] = newDummy
			}
		}

		// Rebuild rootNodes to include any newly created dummies and exclude merged nodes
		var newRoots []*jwzNode
		seen := make(map[*jwzNode]bool)

		for _, root := range rootNodes {
			if root.parent == nil {
				if root.msg == nil && len(root.children) == 0 {
					continue // Discarded dummy
				}
				if !seen[root] {
					newRoots = append(newRoots, root)
					seen[root] = true
				}
			}
		}
		for _, node := range subjectTable {
			if node.parent == nil {
				if !seen[node] {
					newRoots = append(newRoots, node)
					seen[node] = true
				}
			}
		}
		rootNodes = newRoots

		// 6. Grouping made new roots: order them again.
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

func (s *IMAPSession) getMessageID(numKind imapserver.NumKind, msg db.ThreadMessageResult) uint32 {
	if numKind == imapserver.NumKindUID {
		return uint32(msg.UID)
	}
	return msg.Seq
}

func getSubject(node *jwzNode) string {
	if node.msg != nil {
		return node.msg.SubjectSort
	}
	for _, child := range node.children {
		if s := getSubject(child); s != "" {
			return s
		}
	}
	return ""
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
// message ids. The messages table holds them without angle brackets, several
// joined by a space (db.InsertMessage); a bracketed value splits the same way, and
// every id comes back bare, so ids from the three columns compare equal.
func extractIDs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '<' || r == '>' || unicode.IsSpace(r)
	})
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
