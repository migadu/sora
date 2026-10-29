package imap

import (
	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
)

// returnedModSeq is the mod-sequence a SEARCH, SORT or ESEARCH response reports
// for msgs: the highest of the messages it returns (RFC 7162 §3.1.5, §3.1.9), or
// zero if it returns none. Following RFC 4731 §3.2 (RFC 7162 §3.1.10 for SORT),
// with MIN and/or MAX but neither ALL nor COUNT those are only msgs[minIdx] and
// msgs[maxIdx]. Nil options mean ALL.
//
// go-imap sends it only when the criteria use MODSEQ, including under NOT and
// OR, so callers set it whatever the criteria.
func returnedModSeq(msgs []db.SearchMessageResult, minIdx, maxIdx int, options *imap.SearchOptions) uint64 {
	if len(msgs) == 0 {
		return 0
	}
	var modSeq uint64
	if options != nil && (options.ReturnMin || options.ReturnMax) && !options.ReturnAll && !options.ReturnCount {
		if options.ReturnMin {
			modSeq = messageModSeq(&msgs[minIdx])
		}
		if options.ReturnMax {
			modSeq = max(modSeq, messageModSeq(&msgs[maxIdx]))
		}
		return modSeq
	}
	for i := range msgs {
		modSeq = max(modSeq, messageModSeq(&msgs[i]))
	}
	return modSeq
}

// messageModSeq is msg's mod-sequence as FETCH MODSEQ reports it (fetch.go) and
// the MODSEQ search key matches it (db/search.go).
func messageModSeq(msg *db.SearchMessageResult) uint64 {
	modSeq := msg.CreatedModSeq
	if msg.UpdatedModSeq != nil {
		modSeq = max(modSeq, *msg.UpdatedModSeq)
	}
	if msg.ExpungedModSeq != nil {
		modSeq = max(modSeq, *msg.ExpungedModSeq)
	}
	return uint64(modSeq)
}
