package proxy

import (
	"net"
	"testing"
)

// A dual-stack backend name contributes ONE pool entry, and which family it is comes
// from net.LookupIP's RFC 6724 ordering — which is computed against this host's own
// source addresses, not against the DNS answer. That makes the choice host state, and
// host state changes: gaining or losing an IPv6 route reorders every dual-stack name at
// once. Since the pool entry is also the consistent-hash ring member, an unpinned choice
// would replace the entire pool on such a change and rehash every user onto a different
// backend. The family is therefore decided once per name and then held.

func TestPinnedFamilySurvivesAReorderedLookup(t *testing.T) {
	v4 := []net.IP{net.IPv4(10, 0, 0, 1), net.ParseIP("2001:db8::1")}
	v6First := []net.IP{net.ParseIP("2001:db8::1"), net.IPv4(10, 0, 0, 1)}

	// First resolution, no history: RFC 6724 order decides, here IPv4.
	first := resolvePoolEntriesFrom("backend.test:143", nil, v4)
	if len(first) != 1 || first[0] != "10.0.0.1:143" {
		t.Fatalf("first resolution = %v, want one IPv4 entry", first)
	}

	// Same records, opposite ordering (this host gained IPv6 connectivity). The pin
	// must keep the pool on the family it already published.
	second := resolvePoolEntriesFrom("backend.test:143", first, v6First)
	if len(second) != 1 || second[0] != "10.0.0.1:143" {
		t.Errorf("after the lookup order flipped, pool = %v, want the pinned %v: an unpinned family "+
			"swaps every dual-stack backend at once and rehashes every user", second, first)
	}
}

// TestPinReleasesWhenTheFamilyIsGone covers the other direction: the pin is a tiebreak,
// not a cage. A backend that genuinely stops publishing its pinned family must be
// followed to the family it does publish, or it drops out of the pool entirely.
func TestPinReleasesWhenTheFamilyIsGone(t *testing.T) {
	pinnedToIPv4 := []string{"10.0.0.1:143"}
	onlyIPv6 := []net.IP{net.ParseIP("2001:db8::1")}

	got := resolvePoolEntriesFrom("backend.test:143", pinnedToIPv4, onlyIPv6)
	if len(got) != 1 || got[0] != "[2001:db8::1]:143" {
		t.Errorf("backend that dropped its IPv4 records resolved to %v, want the IPv6 address: "+
			"the pin must not outlive the records it names", got)
	}
}

// TestPinIgnoresAnUnresolvedPlaceholder guards the fallback in resolveAddresses, which
// stores the bare configured name when a lookup fails. That is not an address and must
// not be read as a family pin.
func TestPinIgnoresAnUnresolvedPlaceholder(t *testing.T) {
	if _, ok := pinnedFamilyIsIPv4([]string{"backend.test:143"}); ok {
		t.Error("a hostname placeholder was read as a family pin")
	}
	if _, ok := pinnedFamilyIsIPv4(nil); ok {
		t.Error("an empty history was read as a family pin")
	}
	if isIPv4, ok := pinnedFamilyIsIPv4([]string{"[2001:db8::1]:143"}); !ok || isIPv4 {
		t.Errorf("IPv6 host:port pin read as (isIPv4=%v, ok=%v), want (false, true)", isIPv4, ok)
	}
}
