package imap

import (
	"math"
	"slices"
	"strings"

	"github.com/migadu/go-imap"
)

// RFC 3501 §2.3.2: \Recent is a session flag, so Sora does not store it (see
// db.FlagToBitwise). A message is \Recent in this session when its UID is above
// the one SELECT counted the RECENT response from (recentAboveUID). go-imap
// hands SEARCH RECENT, NEW and OLD to the session as \Recent flag criteria;
// SEARCH, SORT, THREAD and multimailbox SEARCH turn those into that UID range
// before the query is built, so they agree with the RECENT count. The FLAGS of
// every FETCH response add \Recent from the same threshold (withRecentFlag).

const flagRecent imap.Flag = "\\Recent"

// recentFlagAboveLocked returns the UID above which a message of the selected
// mailbox has \Recent in this session's FETCH FLAGS: the threshold SEARCH
// RECENT answers from, as "The only reliable way to identify recent messages
// is to look at message flags to see which have the \Recent flag set, or to do
// a SEARCH RECENT" (RFC 3501 §7.3.2). An IMAP4rev2 session, where the flag is
// deprecated (RFC 9051 Appendix E item 12), gets math.MaxUint32, above which
// there is no UID. The caller holds s.mutex.
func (s *IMAPSession) recentFlagAboveLocked() imap.UID {
	if s.conn != nil && s.conn.IsIMAP4rev2() {
		return math.MaxUint32
	}
	return s.recentAboveUID
}

// withRecentFlag returns the stored flags of message uid with \Recent added
// when uid is above recentAbove (recentFlagAboveLocked). flags itself is left
// as it was.
func withRecentFlag(flags []imap.Flag, uid, recentAbove imap.UID) []imap.Flag {
	if uid <= recentAbove {
		return flags
	}
	return append(slices.Clip(flags), flagRecent)
}

// withSessionRecent returns criteria with its \Recent keys answered for mailbox
// mailboxID: from the session's threshold in the selected mailbox, and as no
// message in any other, since this session has seen nothing arrive there.
func (s *IMAPSession) withSessionRecent(criteria *imap.SearchCriteria, mailboxID int64) (*imap.SearchCriteria, error) {
	if criteria == nil || !mentionsRecent(criteria) {
		return criteria, nil
	}
	acquired, release := s.mutexHelper.AcquireReadLockWithTimeout(s.ctx)
	if !acquired {
		return nil, &imap.Error{
			Type: imap.StatusResponseTypeNo,
			Code: imap.ResponseCodeServerBug,
			Text: "Server busy, please try again",
		}
	}
	recent := imap.UIDSet{}
	if s.selectedMailbox != nil && s.selectedMailbox.ID == mailboxID && s.recentAboveUID < math.MaxUint32 {
		recent = imap.UIDSet{{Start: s.recentAboveUID + 1, Stop: math.MaxUint32}}
	}
	release()
	return recentAsUIDs(criteria, recent), nil
}

// recentAsUIDs returns a copy of c with every \Recent key, nested ones
// included, replaced by the UID set recent: \Recent becomes UID recent, and
// NOT \Recent (OLD) becomes NOT UID recent. An empty recent matches nothing.
// c itself is left as it was.
func recentAsUIDs(c *imap.SearchCriteria, recent imap.UIDSet) *imap.SearchCriteria {
	out := *c
	out.Flag = slices.DeleteFunc(slices.Clone(c.Flag), isRecentFlag)
	out.NotFlag = slices.DeleteFunc(slices.Clone(c.NotFlag), isRecentFlag)

	out.UID = slices.Clone(c.UID)
	if len(out.Flag) < len(c.Flag) {
		out.UID = append(out.UID, recent)
	}
	out.Not = make([]imap.SearchCriteria, 0, len(c.Not)+1)
	for i := range c.Not {
		out.Not = append(out.Not, *recentAsUIDs(&c.Not[i], recent))
	}
	if len(out.NotFlag) < len(c.NotFlag) {
		out.Not = append(out.Not, imap.SearchCriteria{UID: []imap.UIDSet{recent}})
	}
	out.Or = make([][2]imap.SearchCriteria, len(c.Or))
	for i := range c.Or {
		out.Or[i] = [2]imap.SearchCriteria{*recentAsUIDs(&c.Or[i][0], recent), *recentAsUIDs(&c.Or[i][1], recent)}
	}
	return &out
}

// mentionsRecent reports whether c has a \Recent key anywhere.
func mentionsRecent(c *imap.SearchCriteria) bool {
	if slices.ContainsFunc(c.Flag, isRecentFlag) || slices.ContainsFunc(c.NotFlag, isRecentFlag) {
		return true
	}
	for i := range c.Not {
		if mentionsRecent(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if mentionsRecent(&c.Or[i][0]) || mentionsRecent(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

func isRecentFlag(f imap.Flag) bool {
	return strings.EqualFold(string(f), string(flagRecent))
}
