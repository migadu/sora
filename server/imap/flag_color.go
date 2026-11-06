package imap

import (
	"slices"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/helpers"
)

// RFC 9979 §3.2: "Servers MAY clear these flag color keywords when a client
// clears the \Flagged system flag." Sora does. A client that does not know the
// color keywords unflags with -FLAGS (\Flagged) and leaves them behind, so the
// next time any client flags the message, a color-aware client shows the old
// color instead of red. Clearing \Flagged needs the 'w' right, which also covers
// the color keywords, so the extra removal never changes a flag the user could
// not have changed itself.
//
// A .SILENT STORE lets the server "assume that the client has determined the
// updated value itself" (RFC 9051 §6.4.6), which it cannot have for keywords it
// did not name. It still learns of them: Poll, which runs after every command,
// reports each message whose modseq moved, this session's own STOREs included.
// TestIMAP_UnflagClearsFlagColor pins that.

// withColorsOnUnflag returns the flags a -FLAGS removes, plus the flag color
// keywords when they include \Flagged.
func withColorsOnUnflag(flags []imap.Flag) []imap.Flag {
	if !helpers.HasFlag(flags, imap.FlagFlagged) {
		return flags
	}
	out := slices.Clone(flags)
	for _, k := range helpers.FlagColorKeywords {
		if !helpers.HasFlag(out, k) {
			out = append(out, k)
		}
	}
	return out
}

// storeReplaceTarget is replaceTargetFlags for STORE FLAGS: a replace that
// leaves the message without \Flagged also drops the flag color keywords, as
// long as the user may change \Flagged (and so them).
func storeReplaceTarget(current, desired []imap.Flag, rights string) []imap.Flag {
	target := replaceTargetFlags(current, desired, rights)
	if flagRightHeld(imap.FlagFlagged, rights) && !helpers.HasFlag(target, imap.FlagFlagged) {
		target = slices.DeleteFunc(target, helpers.IsFlagColorKeyword)
	}
	return target
}
