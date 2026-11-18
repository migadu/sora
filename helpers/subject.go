package helpers

import (
	"strings"
)

// NormalizeSubjectForSort computes the "base subject" of a message per RFC 5256
// Section 2.1. The base subject is used as the comparison key for SORT (SUBJECT)
// and for THREAD subject grouping (ORDEREDSUBJECT and the subject-merge step of
// REFERENCES).
//
// RFC 5256 §2.1 defines the extraction as a small grammar:
//
//	subject       = *subj-leader [subj-middle] *subj-trailer
//	subj-leader   = (*subj-blob subj-refwd) / WSP
//	subj-blob     = "[" *BLOBCHAR "]" *WSP
//	subj-refwd    = ("re" / ("fw" ["d"])) *WSP [subj-blob] ":"
//	subj-fwd      = subj-fwd-hdr subject subj-fwd-trl
//	subj-fwd-hdr  = "[fwd:"
//	subj-fwd-trl  = "]"
//	subj-trailer  = "(fwd)" / WSP
//	BLOBCHAR      = any CHAR except "[" and "]"
//
// and the algorithm that drives it:
//
//	(1) Normalize whitespace: collapse runs of whitespace to a single space.
//	(2) Strip trailing subj-trailer repeatedly.
//	(3) Strip a leading subj-leader.
//	(4) If a leading subj-blob can be removed while leaving a non-empty base,
//	    remove it.
//	(5) Repeat (3) and (4) until nothing more is removed.
//	(6) If the remainder is wrapped in "[fwd:" ... "]", unwrap it and repeat
//	    from (2).
//
// Token matching ("re", "fw"/"fwd", "[fwd:", "(fwd)") is case-insensitive. We
// fold the working string to upper case up front: this both makes the matching
// case-insensitive and yields a case-folded key. RFC 5256 §7 requires the
// i;unicode-casemap collation, which also titlecases and decomposes (RFC 5051
// §2); SORT and THREAD finish that preparation when they read the stored key
// (db.subjectCasemapKey).
func NormalizeSubjectForSort(subject string) string {
	base, _ := baseSubject(subject)
	return base
}

// SubjectIsReplyOrForward reports whether a subject marks its message as a reply
// or forward, which the subject merge of THREAD REFERENCES goes by. RFC 5256
// section 3: "A message is considered to be a reply or forward if the base
// subject extraction rules, applied to the original subject, remove any of the
// following: a subj-refwd, a "(fwd)" subj-trailer, or a subj-fwd-hdr and
// subj-fwd-trl."
func SubjectIsReplyOrForward(subject string) bool {
	_, replyOrForward := baseSubject(subject)
	return replyOrForward
}

// baseSubject returns the base subject (see NormalizeSubjectForSort) and whether
// extracting it removed a reply or forward marker (see SubjectIsReplyOrForward).
func baseSubject(subject string) (base string, replyOrForward bool) {
	if subject == "" {
		return "", false
	}

	// Step 1: collapse all whitespace runs to a single space and trim, then fold
	// case for case-insensitive token matching / comparison.
	s := strings.ToUpper(strings.Join(strings.Fields(subject), " "))

	for {
		// Step 2: strip trailing subj-trailer ("(fwd)" / WSP) until stable.
		for {
			if next, ok, fwd := stripSubjTrailer(s); ok {
				s = next
				replyOrForward = replyOrForward || fwd
				continue
			}
			break
		}

		// Steps 3-5: strip leaders and leading blobs until nothing changes.
		for {
			changed := false
			if next, ok, refwd := stripSubjLeader(s); ok {
				s = next
				changed = true
				replyOrForward = replyOrForward || refwd
			}
			if next, ok := stripLeadingBlob(s); ok {
				s = next
				changed = true
			}
			if !changed {
				break
			}
		}

		// Step 6: if wrapped as "[fwd: ... ]", unwrap and reprocess from step 2.
		if next, ok := unwrapSubjFwd(s); ok {
			s = next
			replyOrForward = true
			continue
		}
		break
	}

	return strings.TrimSpace(s), replyOrForward
}

// stripSubjTrailer removes one trailing subj-trailer: "(fwd)" or a single space.
// fwd reports that it was "(fwd)".
func stripSubjTrailer(s string) (next string, ok, fwd bool) {
	if strings.HasSuffix(s, "(FWD)") {
		return s[:len(s)-len("(FWD)")], true, true
	}
	if strings.HasSuffix(s, " ") {
		return s[:len(s)-1], true, false
	}
	return s, false, false
}

// stripSubjLeader removes one leading subj-leader. A leader is either a run of
// zero-or-more subj-blobs followed by a subj-refwd, or a single WSP. Blobs are
// only consumed here when a refwd follows them; a bare leading blob is left for
// stripLeadingBlob (step 4), which guards against emptying the subject. refwd
// reports that the leader held a subj-refwd.
func stripSubjLeader(s string) (next string, ok, refwd bool) {
	// Try (*subj-blob subj-refwd).
	rest := s
	for {
		if next, ok := matchSubjBlob(rest); ok {
			rest = next
			continue
		}
		break
	}
	if next, ok := matchSubjRefwd(rest); ok {
		return next, true, true
	}

	// Try WSP.
	if len(s) > 0 && s[0] == ' ' {
		return s[1:], true, false
	}
	return s, false, false
}

// stripLeadingBlob removes a single leading subj-blob, but only if doing so
// leaves a non-empty base (RFC 5256 step 4).
func stripLeadingBlob(s string) (string, bool) {
	if next, ok := matchSubjBlob(s); ok && strings.TrimSpace(next) != "" {
		return next, true
	}
	return s, false
}

// matchSubjBlob matches a leading subj-blob: "[" *BLOBCHAR "]" *WSP, where
// BLOBCHAR is any character except "[" and "]" (blobs do not nest). On success
// it returns the remainder with the blob and trailing whitespace consumed.
func matchSubjBlob(s string) (string, bool) {
	if len(s) == 0 || s[0] != '[' {
		return s, false
	}
	// Scan for the closing ']'. A '[' before ']' means this is not a valid blob
	// (BLOBCHAR excludes '[').
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '[':
			return s, false
		case ']':
			rest := strings.TrimLeft(s[i+1:], " ")
			return rest, true
		}
	}
	return s, false
}

// matchSubjRefwd matches a leading subj-refwd:
//
//	("re" / ("fw" ["d"])) *WSP [subj-blob] ":"
//
// On success it returns the remainder after the ":".
func matchSubjRefwd(s string) (string, bool) {
	rest := s
	switch {
	case strings.HasPrefix(rest, "RE"):
		rest = rest[2:]
	case strings.HasPrefix(rest, "FWD"):
		rest = rest[3:]
	case strings.HasPrefix(rest, "FW"):
		rest = rest[2:]
	default:
		return s, false
	}

	// *WSP
	rest = strings.TrimLeft(rest, " ")
	// [subj-blob]
	if next, ok := matchSubjBlob(rest); ok {
		rest = next
	}
	// ":"
	if strings.HasPrefix(rest, ":") {
		return rest[1:], true
	}
	return s, false
}

// unwrapSubjFwd implements step 6: if the subject is wrapped in subj-fwd-hdr
// ("[fwd:") and subj-fwd-trl ("]"), strip both.
func unwrapSubjFwd(s string) (string, bool) {
	const hdr = "[FWD:"
	if len(s) >= len(hdr)+1 && strings.HasPrefix(s, hdr) && strings.HasSuffix(s, "]") {
		return s[len(hdr) : len(s)-1], true
	}
	return s, false
}

// SanitizeSubjectForSort combines UTF-8 sanitization with RFC 5256 base-subject
// extraction. This is the function to use when computing the stored sort key.
func SanitizeSubjectForSort(subject string) string {
	// First sanitize UTF-8, then extract the base subject per RFC 5256.
	return NormalizeSubjectForSort(SanitizeUTF8(subject))
}
