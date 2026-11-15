package db

import "context"

// seqViewKey is the context key WithSeqView stores a view under.
type seqViewKey struct{}

// WithSeqView returns a context in which message sequence numbers are numbered as the
// mailbox stood at modSeq, the position an IMAP session's poll has brought its client
// to, instead of as it stands now.
//
// A client renumbers its messages when it is sent an EXPUNGE, not when another session
// expunges (RFC 9051 §7.5.1), so a message expunged after modSeq keeps its sequence
// number in that view. The rows a sequence number counts are the live messages plus
// those the view still holds although they have since been expunged (heldExpungedCond).
// Nothing created after modSeq can come before a message of the view, since UIDs only
// grow, so such messages only occupy the numbers past the view's last message; the
// caller, which knows how many messages its client was told about, names no number past
// them. "*" (0) is the last row counted, which is also what a UID "*" resolves to:
// "the unique identifier of the last message in the mailbox" (RFC 9051 §9).
//
// For append and soft-expunge changes, the view of a modseq is the same in every
// snapshot: an expunge only moves a message from the live rows to the held ones.
// Each numbering statement is therefore exact while those rows and their recorded
// UID/creation/expunge history remain available. Restore rewrites that history
// (including the UID) and is outside this guarantee.
//
// Without a view (or with modSeq 0, before anything exists) sequence numbers count the
// live messages, as for any caller that is not an IMAP session.
func WithSeqView(ctx context.Context, modSeq uint64) context.Context {
	return context.WithValue(ctx, seqViewKey{}, modSeq)
}

// seqViewOf returns the modseq of ctx's view, or 0 for none.
func seqViewOf(ctx context.Context) uint64 {
	v, _ := ctx.Value(seqViewKey{}).(uint64)
	return v
}

// heldExpungedCond selects (on table alias m) the expunged messages that the view at
// the modseq bound to param still holds: created at or before it, expunged after it.
func heldExpungedCond(m, param string) string {
	return m + ".expunged_at IS NOT NULL AND " + m + ".expunged_modseq > " + param + " AND " + m + ".created_modseq <= " + param
}

// seqCountedRows returns a FROM item listing (as column uid) the messages of mailbox
// mailboxParam that a sequence number counts and that satisfy cond, a condition on the
// unqualified uid column (empty for none): the live messages, plus, when viewParam is
// not empty, the ones the view bound to it still holds (heldExpungedCond).
//
// order is the UID order ("ASC" or "DESC") the caller numbers the rows in, or empty
// when it only counts them. In a view each branch of the UNION ALL is ordered by it,
// which lets the planner merge the live branch, read in order from the live-uid index,
// with the few held rows (a Merge Append) instead of sorting every live UID of the
// mailbox: the numbering keeps streaming, and a LIMIT still stops it early. The held
// branch reads only the messages expunged after the view, which are few.
func seqCountedRows(mailboxParam, viewParam, cond, order string) string {
	if cond != "" {
		cond = " AND " + cond
	}
	live := "SELECT uid FROM messages WHERE mailbox_id = " + mailboxParam + " AND expunged_at IS NULL" + cond
	if viewParam == "" {
		return "(" + live + ")"
	}
	held := "SELECT m.uid FROM messages m WHERE m.mailbox_id = " + mailboxParam +
		" AND " + heldExpungedCond("m", viewParam) + cond
	if order != "" {
		live += " ORDER BY uid " + order
		held += " ORDER BY m.uid " + order
	}
	return "((" + live + ") UNION ALL (" + held + "))"
}
