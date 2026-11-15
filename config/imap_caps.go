package config

import (
	"fmt"
	"slices"

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

// DisableIMAPCapabilities removes the named capabilities (and any capabilities
// in caps that imply them) from caps, except capabilities protected by keep.
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
		c := imap.Cap(name)
		if _, ok := IMAPAlwaysAdvertisedCaps[c]; ok {
			continue
		}
		if recordKept(imapCapKeptBy(keep, c)) {
			continue
		}
		if _, ok := caps[c]; ok {
			delete(caps, c)
			removed = append(removed, name)
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
