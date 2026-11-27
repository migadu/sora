package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/migadu/go-imap"
)

// IMAPAlwaysAdvertisedCaps are the capabilities go-imap lists on every IMAP4rev1
// server whatever the configured set holds (imapserver availableCaps: SASL-IR
// and LITERAL- before login, UNSELECT, ENABLE and UTF8=ACCEPT after it), so
// neither disabled_caps nor client_filters can withdraw them. All but
// UTF8=ACCEPT are implied by IMAP4rev2, and LITERAL- also by LITERAL+:
// removing those for them would downgrade the server and leave them advertised
// all the same.
var IMAPAlwaysAdvertisedCaps = imap.CapSet{
	imap.CapSASLIR:       {},
	imap.CapLiteralMinus: {},
	imap.CapUnselect:     {},
	imap.CapEnable:       {},
	imap.CapUTF8Accept:   {},
}

// IMAPServerCaps returns the capabilities an IMAP server ([[server]] type "imap")
// starts with, before disabled_caps and client_filters withdraw any: the set
// disabled_caps and a filter's disable_caps can withdraw from, besides the
// IMAPAlwaysAdvertisedCaps go-imap adds by itself. PREVIEW (RFC 8970) is opt-in
// (enable_preview): answering it for mail that is not on this node costs an S3
// download per message.
//
// It holds no AUTH= entry: go-imap advertises AUTH= from the session's
// AuthenticateMechanisms and never reads it from this set, so one here would let
// disabled_caps and client_filters report it removed while it stays advertised
// and usable.
func IMAPServerCaps(preview bool) imap.CapSet {
	caps := imap.CapSet{
		imap.CapIMAP4rev1:                 {},
		imap.CapIMAP4rev2:                 {},
		imap.CapLiteralPlus:               {},
		imap.CapSASLIR:                    {},
		imap.CapMove:                      {},
		imap.CapIdle:                      {},
		imap.CapUIDPlus:                   {},
		imap.CapESearch:                   {},
		imap.CapSearchRes:                 {},
		imap.CapESort:                     {},
		imap.CapSort:                      {},
		imap.CapSortDisplay:               {},
		imap.CapSpecialUse:                {},
		imap.CapCreateSpecialUse:          {},
		imap.CapListStatus:                {},
		imap.CapListExtended:              {}, // listed so a session without IMAP4rev2 keeps it (DisableIMAPCapabilities)
		imap.CapStatusSize:                {},
		imap.CapBinary:                    {},
		imap.CapCondStore:                 {},
		imap.CapQResync:                   {},
		imap.CapNotify:                    {},
		imap.CapChildren:                  {},
		imap.CapID:                        {},
		imap.CapNamespace:                 {},
		imap.CapMetadata:                  {},
		imap.CapQuota:                     {}, // STORAGE only (server/imap/quota.go)
		imap.Cap("THREAD=REFERENCES"):     {},
		imap.Cap("THREAD=REFS"):           {},
		imap.Cap("THREAD=ORDEREDSUBJECT"): {},
		imap.Cap("MULTISEARCH"):           {},
	}
	if preview {
		caps[imap.CapPreview] = struct{}{}
	}
	return caps
}

// IMAPCapNotWithdrawn says why naming a capability in disabled_caps (perClient
// false) or in a client_filters disable_caps list (perClient true) does not withdraw
// it from a server whose capabilities are caps (IMAPServerCaps), or returns "" when
// it does. A filter cannot withdraw IMAP4rev1: go-imap picks the connection's
// protocol version from the server-wide set. The server logs the reason at start-up,
// and Config.Warnings reports it.
func IMAPCapNotWithdrawn(caps imap.CapSet, name string, perClient bool) string {
	c := IMAPCap(name)
	if perClient && c == imap.CapIMAP4rev1 {
		return "go-imap selects connection protocol version from server-global capabilities"
	}
	if _, ok := IMAPAlwaysAdvertisedCaps[c]; ok {
		return "go-imap always advertises it with IMAP4rev1"
	}
	if !caps.Has(c) {
		return "it is not one this server can withdraw"
	}
	return ""
}

// IMAPCap returns the capability a disabled_caps or disable_caps name stands for,
// spelled as go-imap advertises it and keys its CapSet: capability names are
// case-insensitive (RFC 9051 section 9, note 1: "Implementations MUST accept these
// strings in a case-insensitive fashion"), and go-imap spells every capability
// these settings can withdraw in upper case but the two base versions. (RIGHTS=,
// whose rights are lower case, is not one of them: go-imap advertises it with ACL.)
func IMAPCap(name string) imap.Cap {
	for _, base := range []imap.Cap{imap.CapIMAP4rev1, imap.CapIMAP4rev2} {
		if strings.EqualFold(name, string(base)) {
			return base
		}
	}
	return imap.Cap(strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, name))
}

// IMAPCapImplies reports whether capability by implies capability c: go-imap's
// own Has, so it follows the library, plus the extension dependencies Has does
// not model:
//   - SORT=DISPLAY (RFC 5957 §1) and ESORT (RFC 5267 §3.1) extend SORT;
//   - SEARCHRES (RFC 5182 §2.1), ESORT (RFC 5267 §3.1) and MULTISEARCH
//     (RFC 7377 §1, §2) require ESEARCH;
//   - CREATE-SPECIAL-USE requires SPECIAL-USE (RFC 6154 §3).
func IMAPCapImplies(by, c imap.Cap) bool {
	if (imap.CapSet{by: {}}).Has(c) {
		return true
	}
	switch c {
	case imap.CapSort:
		return by == imap.CapSortDisplay || by == imap.CapESort
	case imap.CapESearch:
		return by == imap.CapSearchRes || by == imap.CapESort || by == imap.CapMultiSearch
	case imap.CapSpecialUse:
		return by == imap.CapCreateSpecialUse
	}
	return false
}

// imapCapKeptBy returns the capabilities in keep that prevent target from being
// withdrawn (either target itself or an enabled capability that implies target,
// such as IMAP4rev2 implying ESEARCH or QRESYNC implying CONDSTORE).
func imapCapKeptBy(keep imap.CapSet, target imap.Cap) []imap.Cap {
	var keepers []imap.Cap
	for k := range keep {
		if k == target || IMAPCapImplies(k, target) {
			keepers = append(keepers, k)
		}
	}
	return keepers
}

// DisableIMAPCapabilities removes the named capabilities (IMAPCap: in any case)
// and any capabilities in caps that imply them from caps, except capabilities
// protected by keep.
// When a capability is protected by keep, it is neither deleted nor cascaded
// from, so extensions that depend on it and were not themselves disabled stay
// available. It returns the removed capability names and the sorted, unique
// capability names from keep that prevented removal.
func DisableIMAPCapabilities(caps imap.CapSet, names []string, keep imap.CapSet) (removed, kept []string) {
	keptSet := make(imap.CapSet)
	recordKept := func(keepers []imap.Cap) bool {
		if len(keepers) == 0 {
			return false
		}
		for _, k := range keepers {
			keptSet[k] = struct{}{}
		}
		return true
	}

	for _, name := range names {
		c := IMAPCap(name)
		if _, ok := IMAPAlwaysAdvertisedCaps[c]; ok {
			continue
		}
		if recordKept(imapCapKeptBy(keep, c)) {
			continue
		}
		if _, ok := caps[c]; ok {
			delete(caps, c)
			removed = append(removed, string(c))
		}
		queue := []imap.Cap{c}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for other := range caps {
				if IMAPCapImplies(other, cur) {
					if recordKept(imapCapKeptBy(keep, other)) {
						continue
					}
					delete(caps, other)
					removed = append(removed, string(other))
					queue = append(queue, other)
				}
			}
		}
	}

	if len(keptSet) > 0 {
		kept = make([]string, 0, len(keptSet))
		for k := range keptSet {
			kept = append(kept, string(k))
		}
		slices.Sort(kept)
	}
	return removed, kept
}

// ValidateIMAPDisabledCaps checks that applying disabled_caps leaves at least
// one base IMAP protocol version (IMAP4rev1 or IMAP4rev2). Disabling IMAP4rev1
// together with IMAP4rev2 (directly or via any capability IMAP4rev2 implies,
// such as MOVE, IDLE, ESEARCH, SEARCHRES, or CHILDREN) leaves neither version
// and would panic go-imap's imapserver.New.
func ValidateIMAPDisabledCaps(disabled []string) error {
	if len(disabled) == 0 {
		return nil
	}
	caps := imap.CapSet{
		imap.CapIMAP4rev1: {},
		imap.CapIMAP4rev2: {},
	}
	DisableIMAPCapabilities(caps, disabled, nil)
	if !caps.Has(imap.CapIMAP4rev1) && !caps.Has(imap.CapIMAP4rev2) {
		return fmt.Errorf("disabled_caps leaves neither IMAP4rev1 nor IMAP4rev2 enabled; at least one base IMAP version must remain supported")
	}
	return nil
}
