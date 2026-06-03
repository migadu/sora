package imap

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
)

var _ imapserver.SessionThread = (*IMAPSession)(nil)

func (s *IMAPSession) Thread(numKind imapserver.NumKind, algorithm imap.ThreadAlgorithm, charset string, criteria *imap.SearchCriteria) ([]imap.ThreadData, error) {
	if s.selectedMailbox == nil {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Text: "No mailbox selected",
		}
	}

	messages, err := s.server.rdb.GetMessagesForThreadingWithRetry(s.ctx, s.selectedMailbox.ID, criteria)
	if err != nil {
		logger.Error("Failed to fetch messages for threading", "err", err)
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
	next     *jwzNode // For siblings
}

// threadReferences implements the REFERENCES threading algorithm (RFC 5256 section 2.2 / JWZ algorithm)
func (s *IMAPSession) threadReferences(numKind imapserver.NumKind, messages []db.ThreadMessageResult, skipSubjectGrouping bool) []imap.ThreadData {
	// The JWZ algorithm:
	// 1. Group by Message-ID
	idTable := make(map[string]*jwzNode)

	// Pre-populate nodes for all matching messages
	for i := range messages {
		msg := &messages[i]
		node := &jwzNode{
			msg: msg,
			id:  s.getMessageID(numKind, *msg),
		}

		msgID := msg.MessageID
		if msgID != "" {
			if existing, ok := idTable[msgID]; ok {
				// If a node already exists, we prefer the one with the actual message over a dummy node.
				if existing.msg == nil {
					existing.msg = msg
					existing.id = node.id
				}
				node = existing
			} else {
				idTable[msgID] = node
			}
		}
	}

	// 2. Link messages via In-Reply-To and References
	for i := range messages {
		msg := &messages[i]
		if msg.InReplyTo == "" && msg.References == "" {
			continue
		}

		// For true JWZ, we process the full References header first, followed by In-Reply-To.
		chain := strings.TrimSpace(msg.References + " " + msg.InReplyTo)
		refs := extractIDs(chain)

		if len(refs) == 0 {
			continue
		}

		var parentNode *jwzNode
		for _, ref := range refs {
			if existing, ok := idTable[ref]; ok {
				parentNode = existing
			} else {
				// Create dummy node
				dummy := &jwzNode{}
				idTable[ref] = dummy
				parentNode = dummy
			}
		}

		childMsgID := msg.MessageID
		var childNode *jwzNode
		if childMsgID != "" {
			childNode = idTable[childMsgID]
		} else {
			// Find it by linear search since it lacks a message ID
			for _, n := range idTable {
				if n.msg != nil && n.id == s.getMessageID(numKind, *msg) {
					childNode = n
					break
				}
			}
		}

		if childNode != nil && parentNode != nil && childNode.parent == nil {
			// Detect loops
			if !isAncestor(childNode, parentNode) {
				childNode.parent = parentNode
				parentNode.children = append(parentNode.children, childNode)
			}
		}
	}

	// 3. Find root nodes (those without parents)
	var rootNodes []*jwzNode
	for _, node := range idTable {
		if node.parent == nil {
			rootNodes = append(rootNodes, node)
		}
	}

	// 4. Prune dummy nodes
	for i := 0; i < len(rootNodes); i++ {
		root := rootNodes[i]
		if root.msg == nil {
			if len(root.children) == 0 {
				continue
			} else if len(root.children) == 1 {
				// Promote child
				child := root.children[0]
				child.parent = nil
				rootNodes[i] = child
			} else {
				// Keep dummy node as root with multiple children
			}
		}
	}

	// 5. Subject Grouping (RFC 5256 JWZ algorithm phase 5)
	if !skipSubjectGrouping {
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
	}

	// 6. Sort root nodes
	sort.Slice(rootNodes, func(i, j int) bool {
		dateI := getEarliestDate(rootNodes[i])
		dateJ := getEarliestDate(rootNodes[j])
		if !dateI.Equal(dateJ) {
			return dateI.Before(dateJ)
		}
		// Fallback to sort by ID
		return getEarliestID(rootNodes[i]) < getEarliestID(rootNodes[j])
	})

	// 6. Build the ThreadData structure
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

func extractIDs(s string) []string {
	var ids []string
	start := -1
	for i, c := range s {
		if c == '<' {
			start = i
		} else if c == '>' && start != -1 {
			ids = append(ids, s[start:i+1])
			start = -1
		}
	}
	if len(ids) == 0 && strings.TrimSpace(s) != "" {
		// Just take the string if it doesn't have brackets
		return []string{strings.TrimSpace(s)}
	}
	return ids
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
		// Sort children by date
		sort.Slice(curr.children, func(i, j int) bool {
			dateI := getEarliestDate(curr.children[i])
			dateJ := getEarliestDate(curr.children[j])
			if !dateI.Equal(dateJ) {
				return dateI.Before(dateJ)
			}
			return getEarliestID(curr.children[i]) < getEarliestID(curr.children[j])
		})

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
