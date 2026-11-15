package imap

import (
	"context"
	"sort"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
	"github.com/migadu/sora/db"
)

// seqView translates message sequence numbers between the client and the database for
// one command.
//
// A client renumbers its messages when it is sent an EXPUNGE, not when another session
// expunges (RFC 9051 §7.5.1), and FETCH, STORE and SEARCH may not send one, so the
// client goes on numbering the mailbox as it was told about it. Two layers sit between
// that numbering and the database's:
//
//   - the session tracker holds what the poll queued but has not sent yet (an EXPUNGE
//     a FETCH held back, the EXISTS behind it); it maps the client's numbers to the
//     server view the poll left, and back;
//   - the database numbers the mailbox in that server view, as of the poll cursor
//     (db.WithSeqView), however much other sessions have expunged since.
//
// The caller holds seqViewMu for reading while it uses the view, so that no poll moves
// the cursor or the tracker underneath it.
type seqView struct {
	tracker *imapserver.SessionTracker
	// modSeq is the poll cursor, the modseq the server view stands at.
	modSeq uint64
	// serverCount is the number of messages in the server view.
	serverCount uint32
	// direct is set when the tracker holds nothing for the client: its numbers are
	// those of the server view.
	direct bool
}

// seqViewLocked returns the selected mailbox's view. The caller holds s.mutex and
// seqViewMu (both may be read locks).
func (s *IMAPSession) seqViewLocked() seqView {
	v := seqView{
		tracker:     s.sessionTracker,
		modSeq:      s.currentHighestModSeq.Load(),
		serverCount: s.currentNumMessages.Load(),
	}
	v.direct = v.tracker == nil || v.tracker.QueuedUpdates() == 0
	return v
}

// context returns ctx with the view's numbering bound for the database.
func (v seqView) context(ctx context.Context) context.Context {
	return db.WithSeqView(ctx, v.modSeq)
}

// clientCount is the number of messages the client knows: the largest sequence number
// it can name, its "*".
func (v seqView) clientCount() uint32 {
	if v.direct {
		return v.serverCount
	}
	return v.tracker.EncodeNumMessages()
}

// encode returns the client's sequence number for the message at seq in the server
// view, or 0 if the client has not been told about it (it arrived since, or the poll
// that found it has not been delivered).
func (v seqView) encode(seq uint32) uint32 {
	if seq == 0 || seq > v.serverCount {
		return 0
	}
	if v.direct {
		return seq
	}
	return v.tracker.EncodeSeqNum(seq)
}

// decode returns the server-view sequence set naming the messages the client's set
// names. A client number past its last message names nothing, as does one whose
// message has been expunged although the client has not been told yet. The result
// holds no "*": its ranges end at the last message the client knows, wherever the
// database's view ends. The two can differ (a restored message keeps the
// created_modseq it had, mailbox_stats.message_count can trail the live count), and
// a message the client was not told about must not be stored to, copied or moved by
// sequence number.
func (v seqView) decode(set imap.SeqSet) imap.SeqSet {
	clientCount := v.clientCount()
	out := imap.SeqSet{}
	for _, r := range set {
		start, stop := r.Start, r.Stop
		if start == 0 {
			start = clientCount
		}
		if stop == 0 {
			stop = clientCount
		}
		if start > stop {
			start, stop = stop, start
		}
		if start == 0 || start > clientCount {
			continue
		}
		stop = min(stop, clientCount)

		lo, hi := start, stop
		if !v.direct {
			// encode is increasing over the server view's messages the client knows,
			// which come first; the ones it does not (0) are the last. The messages
			// the client numbers start..stop are therefore a run of the server view,
			// found by two binary searches.
			after := func(n uint32) func(int) bool {
				return func(i int) bool {
					c := v.encode(uint32(i) + 1)
					return c == 0 || c > n
				}
			}
			lo = uint32(sort.Search(int(v.serverCount), after(start-1))) + 1
			hi = uint32(sort.Search(int(v.serverCount), after(stop)))
			if lo > hi {
				continue // every one of them has been expunged
			}
		}
		out = append(out, imap.SeqRange{Start: lo, Stop: hi})
	}
	return out
}

// decodeCriteria returns criteria with its sequence-set keys, nested ones included,
// decoded into the server view. A key naming no message becomes an empty UID set, which
// matches none.
func (v seqView) decodeCriteria(criteria *imap.SearchCriteria) *imap.SearchCriteria {
	decoded := *criteria
	decoded.SeqNum = nil
	decoded.UID = append([]imap.UIDSet(nil), criteria.UID...)
	for _, seqSet := range criteria.SeqNum {
		if d := v.decode(seqSet); len(d) > 0 {
			decoded.SeqNum = append(decoded.SeqNum, d)
		} else {
			decoded.UID = append(decoded.UID, imap.UIDSet{})
		}
	}
	decoded.Not = make([]imap.SearchCriteria, len(criteria.Not))
	for i := range criteria.Not {
		decoded.Not[i] = *v.decodeCriteria(&criteria.Not[i])
	}
	decoded.Or = make([][2]imap.SearchCriteria, len(criteria.Or))
	for i := range criteria.Or {
		for j := range criteria.Or[i] {
			decoded.Or[i][j] = *v.decodeCriteria(&criteria.Or[i][j])
		}
	}
	return &decoded
}

// encodeResults returns the results the client knows, in their order, each with its
// sequence number (seq) set to the client's number for it (encode).
func encodeResults[T any](v seqView, results []T, seq func(*T) *uint32) []T {
	known := make([]T, 0, len(results))
	for _, r := range results {
		n := seq(&r)
		if *n = v.encode(*n); *n != 0 {
			known = append(known, r)
		}
	}
	return known
}

// encodeSearchResults is encodeResults for SEARCH and SORT results.
func (v seqView) encodeSearchResults(results []db.SearchMessageResult) []db.SearchMessageResult {
	return encodeResults(v, results, func(r *db.SearchMessageResult) *uint32 { return &r.Seq })
}
